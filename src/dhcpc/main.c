/*
 * dhcpc: a from-scratch DHCP client (DORA) over an AF_PACKET raw socket.
 *
 *   dhcpc -i <if> [--chaddr MAC] [--xid N] [--broadcast] [--trust-server IP]
 *         [--timeout S] [--lease-file F] [--apply NS] [-v]
 *
 * Why raw: a reply is often unicast to yiaddr, an address the client does not
 * own yet, so a normal UDP socket bound to 0.0.0.0:68 never delivers it to the
 * application. AF_PACKET sees the frame regardless of the destination IP.
 *
 * The client sends DISCOVER (broadcast), takes the first valid OFFER, sends a
 * broadcast REQUEST naming the chosen server (option 54), and waits for an ACK.
 * A NAK sends it back to INIT. It applies nothing to the kernel itself: with
 * --lease-file it writes a lease file that lab/apply-lease.sh validates and
 * applies (docs/phase4-6-prompt.md rule 75).
 *
 * Safety: refuses to send unless NT_LAB=1 and the interface is a veth (guard).
 * Privileges are dropped after the socket opens, keeping only CAP_NET_RAW.
 * Bounded: at most 4 DISCOVERs and 3 REQUESTs, within --timeout seconds.
 */
#include "dhcp.h"
#include "guard.h"
#include "live.h"
#include "nettk.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FRAME_MAX 1024
#define CFG_MAX   512
#define DEFAULT_TIMEOUT 15

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

struct opts {
    const char *iface;
    const char *chaddr_s;
    const char *hostname;
    unsigned    xid;
    int         xid_set;
    int         broadcast;
    const char *trust_server;
    int         timeout;
    const char *lease_file;
    const char *apply_ns;
    int         verbose;
};

struct ctx {
    int      fd;
    int      ifindex;
    uint8_t  mac[6];
    uint32_t xid;
    uint16_t flags;
    const struct opts *o;

    uint8_t  buf[FRAME_MAX];
    uint64_t deadline_ms;

    nt_dhcp  ack;            /* last accepted ACK */
    int      have_ack;

    unsigned sent_discover, sent_request, frames, replies_malformed;
    unsigned ignored_not_ours, ignored_untrusted, offers, acks, naks;
};

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void fmt4(char *out, size_t cap, uint32_t a)
{
    snprintf(out, cap, "%u.%u.%u.%u",
             (a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff);
}

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
            "usage: %s -i <if> [options]\n"
            "  -i <if>            interface (must be a lab veth)\n"
            "  --chaddr MAC       client hardware address (default: interface MAC)\n"
            "  --hostname NAME    option 12 host name\n"
            "  --xid N            fixed transaction id (hex with 0x, or decimal)\n"
            "  --broadcast        set the broadcast flag (0x8000) in DISCOVER/REQUEST\n"
            "  --trust-server IP  ignore offers from any other server identifier\n"
            "  --timeout S        whole-exchange deadline, seconds (default %d)\n"
            "  --lease-file F     write the accepted lease as key=value lines\n"
            "  --apply NS         run lab/apply-lease.sh NS on the written lease\n"
            "  -v                 print every DHCP reply considered\n",
            prog, DEFAULT_TIMEOUT);
}

static int parse_mac(const char *s, uint8_t out[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff)
            return -1;
        out[i] = (uint8_t)v[i];
    }
    return 0;
}

static int get_if_mac(const char *iface, uint8_t mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", iface);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int open_packet(const char *iface, int *ifindex)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;
    struct sockaddr_ll ll;
    memset(&ll, 0, sizeof ll);
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = (int)if_nametoindex(iface);
    if (ll.sll_ifindex == 0 || bind(fd, (struct sockaddr *)&ll, sizeof ll) != 0) {
        close(fd);
        return -1;
    }
    *ifindex = ll.sll_ifindex;
    return fd;
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Build and send one DHCP message as Ethernet/IPv4/UDP. Returns 0 or -1. */
static int send_msg(struct ctx *c, const nt_dhcp_opt *opts, size_t nopts,
                    uint16_t sport, uint16_t dport,
                    const uint8_t eth_dst[6], uint32_t sip, uint32_t dip)
{
    nt_dhcp_out o;
    memset(&o, 0, sizeof o);
    o.op = NT_DHCP_BOOTREQUEST;
    o.htype = 1;
    o.hlen = 6;
    o.xid = c->xid;
    o.flags = c->flags;
    memcpy(o.chaddr, c->mac, 6);
    o.opts = opts;
    o.nopts = nopts;

    uint8_t payload[CFG_MAX];
    size_t plen = 0;
    if (nt_dhcp_build(&o, payload, sizeof payload, &plen) != NT_OK)
        return -1;

    uint8_t frame[FRAME_MAX];
    size_t flen = 0;
    if (nt_build_eth_ipv4_udp(frame, sizeof frame, &flen, c->mac, eth_dst,
                              sip, dip, sport, dport, payload, plen) != NT_OK)
        return -1;

    struct sockaddr_ll to;
    memset(&to, 0, sizeof to);
    to.sll_family = AF_PACKET;
    to.sll_protocol = htons(ETH_P_IP);
    to.sll_ifindex = c->ifindex;
    to.sll_halen = 6;
    memcpy(to.sll_addr, eth_dst, 6);

    ssize_t n = sendto(c->fd, frame, flen, 0, (struct sockaddr *)&to, sizeof to);
    return n == (ssize_t)flen ? 0 : -1;
}

static int recv_frame(struct ctx *c, size_t *len, int slice_ms)
{
    struct pollfd p = { .fd = c->fd, .events = POLLIN };
    int r = poll(&p, 1, slice_ms);
    if (r <= 0)
        return r;
    ssize_t n = recv(c->fd, c->buf, sizeof c->buf, 0);
    if (n < 0)
        return -1;
    *len = (size_t)n;
    return 1;
}

enum reply { REPLY_NONE = 0, REPLY_OFFER, REPLY_ACK, REPLY_NAK };

/* Decode one frame and classify it against our xid/chaddr. On a reply that is
 * ours, *m is filled. A reply for someone else is counted, not an error. */
static enum reply classify(struct ctx *c, const uint8_t *frame, size_t len, nt_dhcp *m)
{
    nt_packet pkt;
    if (nt_decode_frame(frame, len, &pkt) != NT_OK || !pkt.has_udp)
        return REPLY_NONE;
    if (pkt.udp.sport != NT_DHCP_SERVER_PORT || pkt.udp.dport != NT_DHCP_CLIENT_PORT)
        return REPLY_NONE;

    c->frames++;
    if (nt_dhcp_decode(pkt.udp.payload.data, pkt.udp.payload.len, m) != NT_OK) {
        c->replies_malformed++;
        return REPLY_NONE;
    }

    if (c->o->verbose) {
        char y[16];
        fmt4(y, sizeof y, m->yiaddr);
        printf("  <- op=%s xid=0x%08x type=%s yi=%s server_id=%s\n",
               nt_dhcp_op_str(m->op), m->xid,
               m->has_msg_type ? nt_dhcp_msg_type_str(m->msg_type) : "-", y,
               m->has_server_id ? "yes" : "no");
    }

    if (nt_dhcp_match_offer(m, c->xid, c->mac) == NT_MATCH) {
        if (c->o->trust_server != NULL &&
            m->server_id != ntohl(inet_addr(c->o->trust_server))) {
            c->ignored_untrusted++;
            if (c->o->verbose)
                puts("     ignored: untrusted server id");
            return REPLY_NONE;
        }
        return REPLY_OFFER;
    }
    if (nt_dhcp_match_nak(m, c->xid, c->mac) == NT_MATCH)
        return REPLY_NAK;

    /* A well-formed ACK for us; yiaddr is checked by the caller. */
    if (m->op == NT_DHCP_BOOTREPLY && m->xid == c->xid &&
        memcmp(m->chaddr, c->mac, 6) == 0 &&
        m->has_msg_type && m->msg_type == NT_DHCP_ACK && m->has_server_id)
        return REPLY_ACK;

    c->ignored_not_ours++;
    return REPLY_NONE;
}

/* Send DISCOVER and wait for an OFFER. Returns 0 and fills offer/server. */
static int do_discover(struct ctx *c, uint32_t *offer, uint32_t *server)
{
    static const int backoff_ms[4] = { 1000, 2000, 4000, 8000 };
    nt_dhcp_opt opts[5];
    unsigned n = 0;
    memset(opts, 0, sizeof opts);

    opts[n].code = NT_DHCP_OPT_MSG_TYPE; opts[n].len = 1; opts[n].data[0] = NT_DHCP_DISCOVER; n++;
    opts[n].code = NT_DHCP_OPT_PARAM_LIST; opts[n].len = 6;
    opts[n].data[0] = 1; opts[n].data[1] = 3; opts[n].data[2] = 6;
    opts[n].data[3] = 51; opts[n].data[4] = 54; opts[n].data[5] = 58; n++;
    if (c->o->hostname != NULL) {
        size_t hl = strlen(c->o->hostname);
        if (hl > 63) hl = 63;
        opts[n].code = NT_DHCP_OPT_HOSTNAME; opts[n].len = (uint8_t)hl;
        memcpy(opts[n].data, c->o->hostname, hl); n++;
    }

    const uint8_t bcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    for (int a = 0; a < 4; a++) {
        if (g_stop)
            return -1;
        if (send_msg(c, opts, n, NT_DHCP_CLIENT_PORT, NT_DHCP_SERVER_PORT,
                     bcast_mac, 0, 0xffffffffu) != 0) {
            fprintf(stderr, "dhcpc: sendto: %s\n", strerror(errno));
            return -1;
        }
        c->sent_discover++;

        long elapsed = 0;
        while (elapsed < backoff_ms[a]) {
            if (g_stop || now_ms() >= c->deadline_ms)
                return -1;
            size_t len = 0;
            int r = recv_frame(c, &len, 100);
            if (r < 0) {
                fprintf(stderr, "dhcpc: recv: %s\n", strerror(errno));
                return -1;
            }
            if (r == 0) {
                elapsed += 100;
                continue;
            }
            nt_dhcp m;
            if (classify(c, c->buf, len, &m) == REPLY_OFFER) {
                c->offers++;
                *offer = m.yiaddr;
                *server = m.server_id;
                return 0;
            }
        }
    }
    return -1;
}

/* Send a SELECTING REQUEST and wait for ACK/NAK. 1=ACK, 0=no reply, -1=NAK. */
static int do_request(struct ctx *c, uint32_t requested, uint32_t server)
{
    static const int backoff_ms[3] = { 1000, 2000, 4000 };
    nt_dhcp_opt opts[5];
    unsigned n = 0;
    memset(opts, 0, sizeof opts);

    opts[n].code = NT_DHCP_OPT_MSG_TYPE; opts[n].len = 1; opts[n].data[0] = NT_DHCP_REQUEST; n++;
    opts[n].code = NT_DHCP_OPT_REQUESTED_IP; opts[n].len = 4;
    put16(opts[n].data, (uint16_t)(requested >> 16));
    put16(opts[n].data + 2, (uint16_t)requested); n++;
    opts[n].code = NT_DHCP_OPT_SERVER_ID; opts[n].len = 4;
    put16(opts[n].data, (uint16_t)(server >> 16));
    put16(opts[n].data + 2, (uint16_t)server); n++;
    opts[n].code = NT_DHCP_OPT_PARAM_LIST; opts[n].len = 6;
    opts[n].data[0] = 1; opts[n].data[1] = 3; opts[n].data[2] = 6;
    opts[n].data[3] = 51; opts[n].data[4] = 54; opts[n].data[5] = 58; n++;

    const uint8_t bcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    for (int a = 0; a < 3; a++) {
        if (g_stop)
            return -1;
        if (send_msg(c, opts, n, NT_DHCP_CLIENT_PORT, NT_DHCP_SERVER_PORT,
                     bcast_mac, 0, 0xffffffffu) != 0) {
            fprintf(stderr, "dhcpc: sendto: %s\n", strerror(errno));
            return -1;
        }
        c->sent_request++;

        long elapsed = 0;
        while (elapsed < backoff_ms[a]) {
            if (g_stop || now_ms() >= c->deadline_ms)
                return -1;
            size_t len = 0;
            int r = recv_frame(c, &len, 100);
            if (r < 0) {
                fprintf(stderr, "dhcpc: recv: %s\n", strerror(errno));
                return -1;
            }
            if (r == 0) {
                elapsed += 100;
                continue;
            }
            nt_dhcp m;
            enum reply rep = classify(c, c->buf, len, &m);
            if (rep == REPLY_ACK &&
                nt_dhcp_match_ack(&m, c->xid, c->mac, requested) == NT_MATCH) {
                c->acks++;
                c->ack = m;
                c->have_ack = 1;
                return 1;
            }
            if (rep == REPLY_NAK) {
                c->naks++;
                char sid[16];
                fmt4(sid, sizeof sid, m.server_id);
                fprintf(stderr, "dhcpc: NAK from %s%s%s\n", sid,
                        m.has_message ? ": " : "", m.has_message ? m.message : "");
                return -1;
            }
        }
    }
    return 0;
}

static int prefix_from_mask(uint32_t mask)
{
    int n = 0;
    for (int i = 31; i >= 0; i--) {
        if (mask & (1u << i))
            n++;
        else
            break;
    }
    return n == 0 ? 24 : n;
}

/* Validate an ACK before we believe it. Returns 1 (ok) or 0, with a reason. */
static int lease_ok(const nt_dhcp *m, uint32_t requested, char *why, size_t cap)
{
    why[0] = '\0';
    if (!m->has_msg_type || m->msg_type != NT_DHCP_ACK) { snprintf(why, cap, "not-an-ACK"); return 0; }
    if (m->yiaddr == 0) { snprintf(why, cap, "yiaddr-0"); return 0; }
    if (m->yiaddr != requested) { snprintf(why, cap, "yiaddr-ne-requested"); return 0; }
    if (!m->has_server_id) { snprintf(why, cap, "no-server-id"); return 0; }
    if ((m->yiaddr & 0xffffff00u) != 0x0a000600u) { snprintf(why, cap, "outside-pool"); return 0; }
    if (m->has_lease && m->lease_time == 0) { snprintf(why, cap, "lease-0"); return 0; }
    if (m->has_lease && m->lease_time > 30u * 24u * 3600u) { snprintf(why, cap, "lease-too-long"); return 0; }
    return 1;
}

static int write_lease(const struct opts *o, const nt_dhcp *m, uint32_t ip)
{
    FILE *f = fopen(o->lease_file, "w");
    if (f == NULL) {
        fprintf(stderr, "dhcpc: cannot write %s: %s\n", o->lease_file, strerror(errno));
        return -1;
    }
    int plen = m->has_mask ? prefix_from_mask(m->mask) : 24;
    char buf[32];

    fmt4(buf, sizeof buf, ip);
    fprintf(f, "ip=%s/%d\n", buf, plen);
    if (m->has_router) { fmt4(buf, sizeof buf, m->router[0]); fprintf(f, "router=%s\n", buf); }
    if (m->has_dns)    { fmt4(buf, sizeof buf, m->dns[0]);    fprintf(f, "dns=%s\n", buf); }
    if (m->has_server_id) { fmt4(buf, sizeof buf, m->server_id); fprintf(f, "server_id=%s\n", buf); }
    if (m->has_lease)  fprintf(f, "lease=%u\n", m->lease_time);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    struct opts o;
    memset(&o, 0, sizeof o);
    o.timeout = DEFAULT_TIMEOUT;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            o.iface = argv[++i];
        } else if (strcmp(argv[i], "--chaddr") == 0 && i + 1 < argc) {
            o.chaddr_s = argv[++i];
        } else if (strcmp(argv[i], "--hostname") == 0 && i + 1 < argc) {
            o.hostname = argv[++i];
        } else if (strcmp(argv[i], "--xid") == 0 && i + 1 < argc) {
            o.xid = (unsigned)strtoul(argv[++i], NULL, 0);
            o.xid_set = 1;
        } else if (strcmp(argv[i], "--broadcast") == 0) {
            o.broadcast = 1;
        } else if (strcmp(argv[i], "--trust-server") == 0 && i + 1 < argc) {
            o.trust_server = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            o.timeout = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--lease-file") == 0 && i + 1 < argc) {
            o.lease_file = argv[++i];
        } else if (strcmp(argv[i], "--apply") == 0 && i + 1 < argc) {
            o.apply_ns = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            o.verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        } else {
            fprintf(stderr, "dhcpc: unknown argument '%s'\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        }
    }
    if (o.iface == NULL) {
        usage(stderr, argv[0]);
        return 2;
    }

    /* Safety: only inside the lab, on a veth. */
    if (nt_guard_lab() != 0 || nt_guard_iface_veth(o.iface) != 0)
        return 1;

    struct ctx c;
    memset(&c, 0, sizeof c);
    c.o = &o;
    c.flags = o.broadcast ? NT_DHCP_FLAG_BROADCAST : 0;

    if (get_if_mac(o.iface, c.mac) != 0) {
        fprintf(stderr, "dhcpc: cannot read MAC of %s\n", o.iface);
        return 1;
    }
    if (o.chaddr_s != NULL && parse_mac(o.chaddr_s, c.mac) != 0) {
        fprintf(stderr, "dhcpc: bad --chaddr '%s'\n", o.chaddr_s);
        return 2;
    }

    if (o.xid_set) {
        c.xid = o.xid;
    } else if (getrandom(&c.xid, sizeof c.xid, 0) != (ssize_t)sizeof c.xid) {
        fprintf(stderr, "dhcpc: getrandom: %s\n", strerror(errno));
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    c.fd = open_packet(o.iface, &c.ifindex);
    if (c.fd < 0) {
        fprintf(stderr, "dhcpc: AF_PACKET on %s: %s\n", o.iface, strerror(errno));
        return 1;
    }
    /* Keep only CAP_NET_RAW from here on. */
    if (nt_drop_privs() != 0)
        fprintf(stderr, "dhcpc: warning: could not drop privileges\n");

    c.deadline_ms = now_ms() + (uint64_t)o.timeout * 1000u;

    char mb[18];
    snprintf(mb, sizeof mb, "%02x:%02x:%02x:%02x:%02x:%02x",
             c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5]);
    printf("dhcpc: iface=%s chaddr=%s xid=0x%08x broadcast=%d timeout=%ds\n",
           o.iface, mb, c.xid, o.broadcast, o.timeout);

    uint32_t offer = 0, server = 0;
    if (do_discover(&c, &offer, &server) != 0) {
        printf("dhcpc: no OFFER after %u DISCOVER(s); giving up\n", c.sent_discover);
        close(c.fd);
        return 1;
    }
    char ob[16], sb[16];
    fmt4(ob, sizeof ob, offer);
    fmt4(sb, sizeof sb, server);
    printf("dhcpc: OFFER yiaddr=%s server_id=%s (frames=%u malformed=%u not-ours=%u untrusted=%u)\n",
           ob, sb, c.frames, c.replies_malformed, c.ignored_not_ours, c.ignored_untrusted);

    int rr = do_request(&c, offer, server);
    if (rr < 0) {
        printf("dhcpc: REQUEST refused (NAK); back to INIT\n");
        close(c.fd);
        return 2;
    }
    if (rr == 0 || !c.have_ack) {
        printf("dhcpc: no ACK after %u REQUEST(s); giving up\n", c.sent_request);
        close(c.fd);
        return 1;
    }

    const nt_dhcp *m = &c.ack;
    char why[32];
    int ok = lease_ok(m, offer, why, sizeof why);
    char ib[16], rb[16], db[16];
    fmt4(ib, sizeof ib, offer);
    fmt4(rb, sizeof rb, m->has_router ? m->router[0] : 0);
    fmt4(db, sizeof db, m->has_dns ? m->dns[0] : 0);
    printf("dhcpc: ACK lease_valid=%d%s%s ip=%s mask=%d router=%s dns=%s lease=%u t1=%u t2=%u\n",
           ok, ok ? "" : " reason=", ok ? "" : why, ib,
           m->has_mask ? prefix_from_mask(m->mask) : 24,
           m->has_router ? rb : "none", m->has_dns ? db : "none",
           m->has_lease ? m->lease_time : 0,
           m->has_t1 ? m->t1 : 0, m->has_t2 ? m->t2 : 0);

    if (!ok) {
        close(c.fd);
        return 1;
    }

    if (o.lease_file != NULL) {
        if (write_lease(&o, m, offer) != 0) {
            close(c.fd);
            return 1;
        }
        printf("dhcpc: wrote lease to %s\n", o.lease_file);
    }

    if (o.apply_ns != NULL) {
        if (o.lease_file == NULL) {
            fprintf(stderr, "dhcpc: --apply needs --lease-file\n");
            close(c.fd);
            return 2;
        }
        const char *script = getenv("NT_APPLY_LEASE");
        if (script == NULL)
            script = "lab/apply-lease.sh";
        pid_t pid = fork();
        if (pid == 0) {
            execl(script, script, o.apply_ns, "--lease-file", o.lease_file, (char *)NULL);
            fprintf(stderr, "dhcpc: exec %s: %s\n", script, strerror(errno));
            _exit(127);
        }
        if (pid < 0) {
            fprintf(stderr, "dhcpc: fork: %s\n", strerror(errno));
            close(c.fd);
            return 1;
        }
        int st = 0;
        waitpid(pid, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            fprintf(stderr, "dhcpc: apply-lease.sh failed\n");
            close(c.fd);
            return 1;
        }
    }

    close(c.fd);
    return 0;
}
