/*
 * dnsq: a from-scratch stub resolver (phase 5, M12-M14).
 *
 *   dnsq [-s <server>] [-p <port>] [-t <type>] [--edns N | --no-edns] [--do]
 *        [--tcp] [--iter] [--trace] [--weak] [-T <sec>] <name>
 *
 *   -s       server to ask (default: the first A in lab/dns/root.hints)
 *   -t       A AAAA NS MX TXT CNAME PTR SOA (default A)
 *   --iter   iterative walk from the lab root instead of a single query
 *   --tcp    use TCP from the first query (else only after TC=1)
 *   --weak   predictable id + fixed source port for the spoof lab (M15)
 *
 * Safety: refuses any peer that is not a lab address or namespace loopback
 * (nt_guard_peer_v4); fresh connected UDP socket per query; bounded 1 s-spaced
 * retransmissions; hard deadline. No libc resolver anywhere in the tool.
 */
#include "nettk.h"
#include "dns.h"
#include "guard.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>

#define NT_DNSQ_DEFAULT_PORT      53
#define NT_DNSQ_DEFAULT_TIMEOUT_S 10
#define NT_DNSQ_REFERRAL_MAX      16
#define NT_DNSQ_QUERY_MAX         32
#define NT_DNSQ_CNAME_MAX         8
#define NT_DNSQ_WEAK_PORT         53053
#define NT_DNSQ_RECV_MAX          65535
#define NT_DNSQ_SO_RCVBUF         (1u << 20)
#define NT_DNSQ_RETRY            3

struct counters {
    unsigned queries, sent, recv, matched, answers;
    unsigned ignored, timeout, oversize, parse_error, tcp_fallback;
};

struct qcfg {
    uint32_t server;
    uint16_t port;
    const char  *qname;
    uint16_t qtype, qclass;
    int edns;
    uint16_t edns_size;
    int do_bit;
    int tcp;         /* force TCP from the first query */
    int weak;
    int weak_port;
    int per_query_ms;
};

struct qres {
    nt_dns_msg msg;
    int matched;
    int tcp;
};

/* Weak mode walks 1,2,3,...; predictable by design (spoof lab only). */
static uint16_t g_weak_id = 1;

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint16_t rand16(void)
{
    uint16_t v = 0;
    if (getrandom(&v, sizeof v, 0) != (ssize_t)sizeof v)
        v = (uint16_t)(now_ms() ^ (long long)getpid());
    return v;
}

static uint16_t parse_type(const char *s)
{
    if (strcasecmp(s, "A") == 0)     return NT_DNS_TYPE_A;
    if (strcasecmp(s, "NS") == 0)    return NT_DNS_TYPE_NS;
    if (strcasecmp(s, "CNAME") == 0) return NT_DNS_TYPE_CNAME;
    if (strcasecmp(s, "SOA") == 0)   return NT_DNS_TYPE_SOA;
    if (strcasecmp(s, "PTR") == 0)   return NT_DNS_TYPE_PTR;
    if (strcasecmp(s, "MX") == 0)    return NT_DNS_TYPE_MX;
    if (strcasecmp(s, "TXT") == 0)   return NT_DNS_TYPE_TXT;
    if (strcasecmp(s, "AAAA") == 0)  return NT_DNS_TYPE_AAAA;
    return 0;
}

/* First "<owner> [ttl] IN A <ip>" hint in a root.hints file, host order. */
static uint32_t parse_root_hint(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256];
    uint32_t addr = 0;

    if (f == NULL) return 0;
    while (fgets(line, sizeof line, f) != NULL) {
        char *tok[8];
        int n = 0;
        char *p;
        for (p = strtok(line, " \t\r\n"); p != NULL && n < 8; p = strtok(NULL, " \t\r\n"))
            tok[n++] = p;
        for (int i = 0; i + 1 < n; i++) {
            struct in_addr in;
            if (strcasecmp(tok[i], "A") == 0 &&
                inet_pton(AF_INET, tok[i + 1], &in) == 1) {
                addr = ntohl(in.s_addr);
                goto done;
            }
        }
    }
done:
    fclose(f);
    return addr;
}

static void fmt_addr(char *out, size_t cap, uint32_t a)
{
    struct in_addr in;
    in.s_addr = htonl(a);
    if (inet_ntop(AF_INET, &in, out, (socklen_t)cap) == NULL)
        snprintf(out, cap, "?");
}

/* ---- transport ------------------------------------------------------ */

static size_t emit_query(uint8_t *buf, const struct qcfg *c, uint16_t id)
{
    nt_dns_query q;
    size_t len = 0;
    memset(&q, 0, sizeof q);
    q.id = id;
    q.qname = c->qname;
    q.qtype = c->qtype;
    q.qclass = c->qclass;
    q.rd = 1;
    q.edns = c->edns;
    q.edns_size = c->edns_size;
    q.do_bit = c->do_bit;
    if (nt_dns_msg_build_query(&q, buf, NT_DNS_NAME_MAX + 64, &len) != NT_OK)
        return 0;
    return len;
}

static int udp_socket(const struct qcfg *c)
{
    struct sockaddr_in sa;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rcv = (int)NT_DNSQ_SO_RCVBUF;

    if (fd < 0) return -1;
    if (c->weak) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)c->weak_port);
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
            fprintf(stderr, "dnsq: weak bind :%d: %s\n", c->weak_port, strerror(errno));
            close(fd);
            return -1;
        }
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(c->port);
    sa.sin_addr.s_addr = htonl(c->server);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "dnsq: connect: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* Wait for a datagram until `until`; returns 0 and fills out on a match. */
static int udp_collect(int fd, const struct qcfg *c, uint16_t id,
                       struct qres *out, struct counters *ct, long long until)
{
    uint8_t rbuf[NT_DNSQ_RECV_MAX];

    while (now_ms() < until) {
        struct pollfd p = { fd, POLLIN, 0 };
        int left = (int)(until - now_ms());
        int pr;

        if (left <= 0) break;
        pr = poll(&p, 1, left);
        if (pr < 0) return -1;
        if (pr == 0) break;
        if (p.revents & POLLERR) { ct->recv++; continue; }
        if (p.revents & POLLIN) {
            struct sockaddr_in from;
            struct iovec iov = { rbuf, sizeof rbuf };
            struct msghdr mh;
            ssize_t n;

            memset(&mh, 0, sizeof mh);
            mh.msg_name = &from;
            mh.msg_namelen = sizeof from;
            mh.msg_iov = &iov;
            mh.msg_iovlen = 1;
            n = recvmsg(fd, &mh, 0);
            if (n < 0) {
                if (errno == ECONNREFUSED) ct->recv++;
                continue;
            }
            ct->recv++;
            if (mh.msg_flags & MSG_TRUNC) { ct->oversize++; continue; }
            {
                nt_dns_msg tmp;
                if (nt_dns_msg_decode(rbuf, (size_t)n, &tmp) != NT_OK) {
                    ct->parse_error++;
                    continue;
                }
                if (nt_dns_match(&tmp, id, c->qname, c->qtype, c->qclass,
                                 c->server, c->port,
                                 ntohl(from.sin_addr.s_addr),
                                 ntohs(from.sin_port)) == NT_MATCH) {
                    out->msg = tmp;
                    out->matched = 1;
                    out->tcp = 0;
                    ct->matched++;
                    return 0;
                }
                ct->ignored++;
            }
        }
    }
    return -1;
}

static int udp_query(const struct qcfg *c, uint16_t id, struct qres *out,
                     struct counters *ct, long long deadline)
{
    uint8_t qbuf[NT_DNS_NAME_MAX + 64];
    size_t qlen = emit_query(qbuf, c, id);
    long long qdeadline = now_ms() + c->per_query_ms;
    int fd;

    if (qlen == 0) return -1;
    if (qdeadline > deadline) qdeadline = deadline;
    fd = udp_socket(c);
    if (fd < 0) return -1;

    for (int attempt = 0; attempt < NT_DNSQ_RETRY; attempt++) {
        long long until;
        if (now_ms() >= qdeadline) break;
        if (send(fd, qbuf, qlen, 0) == (ssize_t)qlen) ct->sent++;
        until = now_ms() + 1000;
        if (until > qdeadline) until = qdeadline;
        if (udp_collect(fd, c, id, out, ct, until) == 0) { close(fd); return 0; }
    }
    ct->timeout++;
    close(fd);
    return -1;
}

static int tcp_query(const struct qcfg *c, uint16_t id, struct qres *out,
                     struct counters *ct, long long deadline)
{
    uint8_t qbuf[NT_DNS_NAME_MAX + 64];
    uint8_t rbuf[NT_DNSQ_RECV_MAX];
    size_t qlen = emit_query(qbuf, c, id), got = 0;
    uint8_t frame[2 + sizeof qbuf];
    struct sockaddr_in sa;
    int fd, want;

    if (qlen == 0) return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(c->port);
    sa.sin_addr.s_addr = htonl(c->server);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        ct->timeout++;
        return -1;
    }
    frame[0] = (uint8_t)(qlen >> 8);
    frame[1] = (uint8_t)qlen;
    memcpy(frame + 2, qbuf, qlen);
    if (send(fd, frame, qlen + 2, 0) != (ssize_t)(qlen + 2)) {
        close(fd);
        ct->timeout++;
        return -1;
    }
    ct->sent++;
    want = 2;
    while (got < (size_t)want) {
        struct pollfd p = { fd, POLLIN, 0 };
        long long left = deadline - now_ms();
        ssize_t n;
        if (left <= 0 || poll(&p, 1, (int)left) <= 0) { close(fd); ct->timeout++; return -1; }
        n = recv(fd, rbuf + got, sizeof rbuf - got, 0);
        if (n <= 0) { close(fd); ct->timeout++; return -1; }
        got += (size_t)n;
        if (want == 2 && got >= 2) {
            want = 2 + ((rbuf[0] << 8) | rbuf[1]);
            if (want > (int)sizeof rbuf) { close(fd); ct->oversize++; return -1; }
        }
    }
    close(fd);
    ct->recv++;
    {
        nt_dns_msg tmp;
        if (nt_dns_msg_decode(rbuf + 2, (size_t)(want - 2), &tmp) != NT_OK) {
            ct->parse_error++;
            return -1;
        }
        if (nt_dns_match(&tmp, id, c->qname, c->qtype, c->qclass, c->server,
                         c->port, c->server, c->port) == NT_MATCH) {
            out->msg = tmp;
            out->matched = 1;
            out->tcp = 1;
            ct->matched++;
            return 0;
        }
        ct->ignored++;
    }
    return -1;
}

/* One logical query: UDP, then TCP if the reply was truncated (or --tcp). */
static int ask(const struct qcfg *c, struct qres *out, struct counters *ct,
               long long deadline)
{
    uint16_t id;
    int r;

    ct->queries++;
    if (c->weak) {
        id = g_weak_id++;
        if (g_weak_id == 0) g_weak_id = 1;
    } else {
        id = rand16();
    }

    if (c->tcp)
        return tcp_query(c, id, out, ct, deadline);
    r = udp_query(c, id, out, ct, deadline);
    if (r == 0 && out->msg.tc) {
        ct->tcp_fallback++;
        r = tcp_query(c, id, out, ct, deadline);
    }
    return r;
}

/* ---- printing ------------------------------------------------------- */

static void print_answer(const nt_dns_msg *m)
{
    for (unsigned i = 0; i < m->an; i++) {
        char own[NT_DNS_NAME_STR_MAX], rd[2048];
        size_t end;
        if (nt_dns_name_parse(m->buf, m->len, m->an_rr[i].name_off, own, sizeof own, &end) != NT_OK)
            snprintf(own, sizeof own, "?");
        if (nt_dns_rdata_str(m, &m->an_rr[i], rd, sizeof rd) != NT_OK)
            snprintf(rd, sizeof rd, "?");
        printf("answer %s %u %s %s\n", own, m->an_rr[i].ttl,
               nt_dns_type_str(m->an_rr[i].type), rd);
    }
}

static void print_counters(const struct counters *ct)
{
    printf("counters queries=%u sent=%u recv=%u matched=%u ignored=%u timeout=%u "
           "oversize=%u parse_error=%u tcp_fallback=%u answers=%u\n",
           ct->queries, ct->sent, ct->recv, ct->matched, ct->ignored, ct->timeout,
           ct->oversize, ct->parse_error, ct->tcp_fallback, ct->answers);
}

/* ---- iterative walk ------------------------------------------------- */

static int cname_first(const nt_dns_msg *m, const char *qname, char *out, size_t cap)
{
    for (unsigned i = 0; i < m->an; i++) {
        char own[NT_DNS_NAME_STR_MAX];
        size_t end;
        if (m->an_rr[i].type != NT_DNS_TYPE_CNAME) continue;
        if (nt_dns_name_parse(m->buf, m->len, m->an_rr[i].name_off, own, sizeof own, &end) != NT_OK)
            continue;
        if (nt_dns_name_cmp_ci(own, qname) != 0) continue;
        if (nt_dns_rdata_str(m, &m->an_rr[i], out, cap) != NT_OK) continue;
        return 1;
    }
    return 0;
}

/* First NS in the referral whose owner is a deeper ancestor of qname and which
 * has believable in-bailiwick glue. Returns the delegated zone, the NS name
 * and the glue address. */
static int pick_delegation(const nt_dns_msg *m, const char *qname, const char *zone,
                           char *deleg_zone, size_t dzcap, uint32_t *server,
                           char *nsname, size_t nscap)
{
    for (unsigned i = 0; i < m->ns; i++) {
        char own[NT_DNS_NAME_STR_MAX], ns[NT_DNS_NAME_STR_MAX];
        uint32_t glue = 0;
        size_t end;

        if (m->ns_rr[i].type != NT_DNS_TYPE_NS) continue;
        if (nt_dns_name_parse(m->buf, m->len, m->ns_rr[i].name_off, own, sizeof own, &end) != NT_OK)
            continue;
        if (!nt_dns_name_suffix(qname, own)) continue;
        if (nt_dns_name_labels(own) <= nt_dns_name_labels(zone)) continue;
        if (nt_dns_rdata_str(m, &m->ns_rr[i], ns, sizeof ns) != NT_OK) continue;
        if (!nt_dns_name_suffix(ns, own)) continue;        /* out-of-bailiwick */
        if (!nt_dns_glue(m, ns, &glue)) continue;
        snprintf(deleg_zone, dzcap, "%s", own);
        snprintf(nsname, nscap, "%s", ns);
        *server = glue;
        return 1;
    }
    return 0;
}

static int walk(struct qcfg cfg, uint32_t root_addr, struct counters *ct,
                long long deadline)
{
    char zone[NT_DNS_NAME_STR_MAX];
    char qname[NT_DNS_NAME_STR_MAX];
    nt_dns_state st = { 0 };
    unsigned depth = 0, total = 0;
    uint32_t server = root_addr;

    zone[0] = '\0';
    snprintf(qname, sizeof qname, "%s", cfg.qname);

    for (;;) {
        struct qres r;
        nt_dns_qd q;
        nt_dns_class cls;
        char sname[64];

        if (++total > NT_DNSQ_QUERY_MAX) {
            fprintf(stderr, "dnsq: query cap (%d) reached\n", NT_DNSQ_QUERY_MAX);
            return 1;
        }
        if (now_ms() >= deadline) {
            fprintf(stderr, "dnsq: deadline reached\n");
            return 1;
        }
        memset(&q, 0, sizeof q);
        snprintf(q.qname, sizeof q.qname, "%s", qname);
        q.qtype = cfg.qtype;
        q.qclass = cfg.qclass;

        cfg.server = server;
        cfg.qname = qname;
        memset(&r, 0, sizeof r);
        if (ask(&cfg, &r, ct, deadline) != 0) {
            fmt_addr(sname, sizeof sname, server);
            fprintf(stderr, "dnsq: %s:%u zone=%s %s %s: no usable reply\n", sname,
                    cfg.port, zone[0] ? zone : ".", qname, nt_dns_type_str(cfg.qtype));
            return 1;
        }
        cls = nt_dns_classify(&r.msg, &q, zone, &st);
        fmt_addr(sname, sizeof sname, server);

        if (cls == NT_DNS_C_ANSWER) {
            printf("iter %u %s:%u zone=%s %s %s -> ANSWER\n", total, sname, cfg.port,
                   zone[0] ? zone : ".", qname, nt_dns_type_str(cfg.qtype));
            print_answer(&r.msg);
            ct->answers += r.msg.an;
            return 0;
        }
        if (cls == NT_DNS_C_CNAME) {
            char tgt[NT_DNS_NAME_STR_MAX];
            if (!cname_first(&r.msg, qname, tgt, sizeof tgt)) {
                fprintf(stderr, "dnsq: CNAME without a target\n");
                return 1;
            }
            printf("iter %u %s:%u zone=%s %s %s -> CNAME %s\n", total, sname, cfg.port,
                   zone[0] ? zone : ".", qname, nt_dns_type_str(cfg.qtype), tgt);
            if (st.chain > NT_DNSQ_CNAME_MAX) {
                fprintf(stderr, "dnsq: CNAME chain cap (%d) reached\n", NT_DNSQ_CNAME_MAX);
                return 1;
            }
            snprintf(qname, sizeof qname, "%s", tgt);
            server = root_addr;       /* restart the walk for the new name */
            zone[0] = '\0';
            continue;
        }
        if (cls == NT_DNS_C_REFERRAL) {
            char dz[NT_DNS_NAME_STR_MAX], ns[NT_DNS_NAME_STR_MAX], g[64];
            uint32_t srv = 0;
            if (++depth > NT_DNSQ_REFERRAL_MAX) {
                fprintf(stderr, "dnsq: referral depth cap (%d) reached\n", NT_DNSQ_REFERRAL_MAX);
                return 1;
            }
            if (!pick_delegation(&r.msg, qname, zone, dz, sizeof dz, &srv, ns, sizeof ns)) {
                fprintf(stderr, "dnsq: %s:%u zone=%s: glueless or unusable referral\n",
                        sname, cfg.port, zone[0] ? zone : ".");
                return 1;
            }
            fmt_addr(g, sizeof g, srv);
            printf("iter %u %s:%u zone=%s %s %s -> REFERRAL %s (%s/%s)\n", total, sname,
                   cfg.port, zone[0] ? zone : ".", qname, nt_dns_type_str(cfg.qtype), dz, ns, g);
            snprintf(zone, sizeof zone, "%s", dz);
            server = srv;
            continue;
        }
        printf("iter %u %s:%u zone=%s %s %s -> %s\n", total, sname, cfg.port,
               zone[0] ? zone : ".", qname, nt_dns_type_str(cfg.qtype),
               nt_dns_class_str(cls));
        return (cls == NT_DNS_C_NODATA || cls == NT_DNS_C_NXDOMAIN) ? 0 : 1;
    }
}

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
            "usage: %s [-s <server>] [-p <port>] [-t <type>] [--edns N|--no-edns] [--do]\n"
            "          [--tcp] [--iter] [--weak] [-T <sec>] <name>\n"
            "  -s <ip>      server (default: first lab/dns/root.hints A record)\n"
            "  -p <port>    server port (default 53)\n"
            "  -t <type>    A AAAA NS MX TXT CNAME PTR SOA (default A)\n"
            "  --edns N     advertise an EDNS0 UDP payload size (default %u)\n"
            "  --no-edns    no OPT record\n"
            "  --do         set the DNSSEC OK bit\n"
            "  --tcp        use TCP from the first query (also after TC=1)\n"
            "  --iter       iterative walk from the lab root\n"
            "  --weak       predictable id + fixed source port (spoof lab only)\n"
            "  -T <sec>     overall deadline in seconds (default %d)\n",
            prog, NT_DNS_EDNS_DEFAULT, NT_DNSQ_DEFAULT_TIMEOUT_S);
}

/* ---- main ----------------------------------------------------------- */

int main(int argc, char **argv)
{
    struct qcfg cfg;
    struct counters ct;
    const char *name = NULL, *server_s = NULL;
    long timeout_s = NT_DNSQ_DEFAULT_TIMEOUT_S;
    int iter = 0, rc;
    long long deadline;
    uint32_t server = 0;

    memset(&cfg, 0, sizeof cfg);
    memset(&ct, 0, sizeof ct);
    cfg.port = NT_DNSQ_DEFAULT_PORT;
    cfg.qtype = NT_DNS_TYPE_A;
    cfg.qclass = NT_DNS_CLASS_IN;
    cfg.edns = 1;
    cfg.edns_size = NT_DNS_EDNS_DEFAULT;
    cfg.per_query_ms = 3000;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            server_s = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            cfg.port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            cfg.qtype = parse_type(argv[++i]);
            if (cfg.qtype == 0) { fprintf(stderr, "dnsq: unknown type\n"); return 2; }
        } else if (strcmp(argv[i], "--edns") == 0 && i + 1 < argc) {
            cfg.edns = 1;
            cfg.edns_size = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-edns") == 0) {
            cfg.edns = 0;
        } else if (strcmp(argv[i], "--do") == 0) {
            cfg.do_bit = 1;
        } else if (strcmp(argv[i], "--tcp") == 0) {
            cfg.tcp = 1;
        } else if (strcmp(argv[i], "--iter") == 0) {
            iter = 1;
        } else if (strcmp(argv[i], "--weak") == 0) {
            cfg.weak = 1;
            cfg.weak_port = NT_DNSQ_WEAK_PORT;
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            timeout_s = atol(argv[++i]);
        } else if (argv[i][0] == '-') {
            usage(stderr, argv[0]);
            return 2;
        } else if (name != NULL) {
            fprintf(stderr, "dnsq: unexpected extra argument '%s'\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        } else {
            name = argv[i];
        }
    }

    if (name == NULL) { usage(stderr, argv[0]); return 2; }
    if (server_s != NULL) {
        struct in_addr in;
        if (inet_pton(AF_INET, server_s, &in) != 1) {
            fprintf(stderr, "dnsq: server must be a numeric IPv4 address\n");
            return 2;
        }
        server = ntohl(in.s_addr);
    } else {
        server = parse_root_hint("lab/dns/root.hints");
        if (server == 0) {
            fprintf(stderr, "dnsq: no -s server and no lab/dns/root.hints\n");
            return 2;
        }
    }

    if (nt_guard_peer_v4(server) != 0) return 1;
    if (cfg.weak && nt_guard_lab() != 0) return 1;

    cfg.server = server;
    cfg.qname = name;
    deadline = now_ms() + timeout_s * 1000;

    if (cfg.weak)
        printf("dnsq: WEAK MODE: predictable id, fixed source port :%d; spoof lab only\n",
               cfg.weak_port);

    if (iter) {
        rc = walk(cfg, server, &ct, deadline);
        print_counters(&ct);
        return rc;
    }

    {
        struct qres r;
        nt_dns_qd q;
        nt_dns_class cls;
        char sname[64];

        memset(&q, 0, sizeof q);
        snprintf(q.qname, sizeof q.qname, "%s", name);
        q.qtype = cfg.qtype;
        q.qclass = cfg.qclass;
        memset(&r, 0, sizeof r);
        if (ask(&cfg, &r, &ct, deadline) != 0) {
            fmt_addr(sname, sizeof sname, server);
            fprintf(stderr, "dnsq: no usable reply from %s:%u\n", sname, cfg.port);
            print_counters(&ct);
            return 1;
        }
        cls = nt_dns_classify(&r.msg, &q, "", NULL);
        fmt_addr(sname, sizeof sname, server);
        printf("dnsq: %s %s @%s:%u -> %s\n", q.qname, nt_dns_type_str(cfg.qtype),
               sname, cfg.port, nt_dns_class_str(cls));
        if (cls == NT_DNS_C_ANSWER) {
            print_answer(&r.msg);
            ct.answers += r.msg.an;
        }
        print_counters(&ct);
        return (cls == NT_DNS_C_ANSWER || cls == NT_DNS_C_NODATA ||
                cls == NT_DNS_C_NXDOMAIN) ? 0 : 1;
    }
}
