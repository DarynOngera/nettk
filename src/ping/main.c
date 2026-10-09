/*
 * ping: ICMP echo for the lab (M2 raw, M3 extras).
 *
 *   sudo lab/ex h1 ping -c4 10.0.2.2
 *   sudo lab/ex h1 ping -c1 -M do -s 1473 10.0.2.2   # EMSGSIZE on the wire
 *   sudo lab/ex h1 ping -c2 --dgram 10.0.2.2         # kernel id + checksum
 *
 * Raw AF_INET/ICMP: we build the ICMP message, the kernel adds the IPv4 header,
 * and recvfrom returns the IPv4 header + reply. --dgram uses SOCK_DGRAM/ICMP,
 * where the kernel picks the id, computes the checksum and strips the IP header
 * on receive (the id is taken from the reply). Every send passes the lab guard.
 */
#include "nettk.h"
#include "clock.h"
#include "guard.h"
#include "opts.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NT_PAYLOAD_DEFAULT 56
#define NT_RECV_CAP 65536
#define NT_PAYLOAD_TIME 8

#ifndef ICMP_FILTER
#define ICMP_FILTER 1 /* Linux: sockopt(IPPROTO_IP, ICMP_FILTER, struct icmp_filter) */
#endif

static void fmt_v4(char out[16], uint32_t ip)
{
    snprintf(out, 16, "%u.%u.%u.%u",
             (ip >> 24) & 0xffu, (ip >> 16) & 0xffu, (ip >> 8) & 0xffu, ip & 0xffu);
}

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
            "usage: %s [-c count] [-i interval_ms] [-W timeout_ms] [-s size] [-t ttl]\n"
            "          [-M do|dont] [--dgram] [-6] <host>\n"
            "  -c N      stop after N replies (default 4; 0 = until stopped)\n"
            "  -i N      interval between sends in ms (default 1000)\n"
            "  -W N      reply timeout in ms (default 1000)\n"
            "  -s N      payload bytes (default %d)\n"
            "  -t N      IP TTL (default 64)\n"
            "  -M do     set DF and report MTU failures; -M dont clears it\n"
            "  --dgram   SOCK_DGRAM/ICMP (kernel id + checksum, no raw header)\n",
            prog, NT_PAYLOAD_DEFAULT);
}

static int resolve(const char *host, struct in_addr *out)
{
    if (inet_pton(AF_INET, host, out) == 1)
        return 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL)
        return -1;
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

static void build_payload(uint8_t *buf, size_t len, uint64_t send_ns)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(0x40 + (i & 0x3f));
    if (len >= NT_PAYLOAD_TIME) {
        for (int i = 0; i < 8; i++)
            buf[i] = (uint8_t)(send_ns >> (56 - 8 * i));
    }
}

static int wait_until(uint64_t deadline)
{
    return nt_poll_until(-1, 0, deadline); /* no fds: just sleeps, wakes on signal */
}

static const char *error_text(uint8_t type, uint8_t code)
{
    if (type == 3) {
        switch (code) {
        case 0: return "Destination Net Unreachable";
        case 1: return "Destination Host Unreachable";
        case 2: return "Destination Protocol Unreachable";
        case 3: return "Destination Port Unreachable";
        case 4: return "Fragmentation needed";
        case 5: return "Source Route Failed";
        default: return "Destination Unreachable";
        }
    }
    if (type == 11) {
        switch (code) {
        case 0: return "Time to live exceeded";
        default: return "Time exceeded";
        }
    }
    if (type == 12)
        return "Parameter problem";
    return "ICMP error";
}

/* Extract the original packet quoted inside an ICMPv4 error (RFC 792). The quoted
 * IP header's totlen describes the *full* packet, so only what is present is read
 * (the library helper does exactly this). */

/* ICMPv6 echo. Raw AF_INET6/ICMPv6; the kernel computes the checksum on send.
 * Receives carry hop limit and source via control messages; the reply's source
 * must equal the target and the payload must match what we sent. */
static int run_ping6(const char *host, long count, long interval_ms, long timeout_ms,
                     long size, long ttl)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_RAW;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        fprintf(stderr, "ping: cannot resolve %s\n", host);
        return 2;
    }
    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof dst);
    dst.sin6_family = AF_INET6;
    dst.sin6_addr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
    dst.sin6_scope_id = ((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id;
    freeaddrinfo(res);

    char dsttxt[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &dst.sin6_addr, dsttxt, sizeof dsttxt);
    if (nt_guard_ipv6(dst.sin6_addr.s6_addr) != 0)
        return 1;

    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) {
        fprintf(stderr, "ping: socket: %s (need root/CAP_NET_RAW)\n", strerror(errno));
        return 1;
    }
    int t = (int)ttl;
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &t, sizeof t);
    int on = 1;
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof on);
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof on);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    uint16_t id = (uint16_t)(getpid() & 0xffff);
    size_t payload_len = (size_t)size;
    uint8_t *payload = malloc(payload_len ? payload_len : 1);
    uint8_t *icmp = malloc(payload_len + 8);
    uint8_t *recvbuf = malloc(NT_RECV_CAP);
    if (payload == NULL || icmp == NULL || recvbuf == NULL) {
        fprintf(stderr, "ping: out of memory\n");
        free(payload); free(icmp); free(recvbuf); close(fd);
        return 1;
    }
    uint8_t zeros[16] = { 0 };

    printf("PING %s (%s): %zu data bytes\n", host, dsttxt, payload_len);

    long sent = 0, received = 0;
    double rtt_min = 0, rtt_max = 0, rtt_sum = 0;

    for (long seq = 1; !g_stop && (count == 0 || received < count); seq++) {
        uint64_t send_ns = nt_now_ns();
        build_payload(payload, payload_len, send_ns);

        size_t icmp_len = 0; /* kernel overwrites the checksum on raw ICMPv6 */
        nt_status bs = nt_build_icmp6_echo(icmp, payload_len + 8, &icmp_len, 128, id,
                                           (uint16_t)seq, payload, payload_len,
                                           zeros, dst.sin6_addr.s6_addr);
        if (bs != NT_OK) {
            fprintf(stderr, "ping: build failed: %s\n", nt_status_str(bs));
            break;
        }
        if (sendto(fd, icmp, icmp_len, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
            fprintf(stderr, "ping: sendto: %s\n", strerror(errno));
            break;
        }
        sent++;

        uint64_t deadline = send_ns + nt_ms_to_ns((uint64_t)timeout_ms);
        while (!g_stop) {
            if (nt_poll_until(fd, POLLIN, deadline) <= 0)
                break;

            uint8_t ctrl[256];
            struct sockaddr_in6 from;
            struct iovec iov = { .iov_base = recvbuf, .iov_len = NT_RECV_CAP };
            struct msghdr msg;
            memset(&msg, 0, sizeof msg);
            memset(&from, 0, sizeof from);
            msg.msg_name = &from;
            msg.msg_namelen = sizeof from;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl;
            msg.msg_controllen = sizeof ctrl;
            ssize_t n = recvmsg(fd, &msg, 0);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }

            int hlim = (int)ttl;
            struct in6_addr local;
            memset(&local, 0, sizeof local);
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c != NULL; c = CMSG_NXTHDR(&msg, c)) {
                if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_HOPLIMIT)
                    memcpy(&hlim, CMSG_DATA(c), sizeof hlim);
                else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
                    struct in6_pktinfo pi;
                    memcpy(&pi, CMSG_DATA(c), sizeof pi);
                    local = pi.ipi6_addr;
                }
            }

            if (memcmp(&from.sin6_addr, &dst.sin6_addr, 16) != 0)
                continue; /* not from the target */

            nt_pseudo ph;
            memset(&ph, 0, sizeof ph);
            ph.family = 6;
            memcpy(ph.src6, &from.sin6_addr, 16);
            memcpy(ph.dst6, &local, 16);
            nt_icmp ic;
            if (nt_icmp6_decode(recvbuf, (size_t)n, &ph, &ic) != NT_OK)
                continue;

            if (ic.type != 129) {
                if (ic.type == 1 || ic.type == 3 || ic.type == 4)
                    printf("From %s icmp_seq=%ld icmpv6 type %u code %u\n",
                           dsttxt, seq, ic.type, ic.code);
                continue;
            }

            nt_echo_probe probe = { .id = id, .seq = (uint16_t)seq,
                                    .data = payload, .datalen = payload_len };
            if (nt_match_icmp6_echo_reply(&ic, from.sin6_addr.s6_addr, &probe) != NT_MATCH)
                continue;

            uint64_t now = nt_now_ns();
            double rtt = (double)(now - send_ns) / 1e6;
            received++;
            rtt_sum += rtt;
            if (received == 1 || rtt < rtt_min) rtt_min = rtt;
            if (received == 1 || rtt > rtt_max) rtt_max = rtt;
            printf("%zu bytes from %s: icmp_seq=%ld hlim=%d time=%.3f ms\n",
                   (size_t)n, dsttxt, seq, hlim, rtt);
            break;
        }

        uint64_t next = send_ns + nt_ms_to_ns((uint64_t)interval_ms);
        if (!g_stop && (count == 0 || received < count) && next > nt_now_ns())
            wait_until(next);
    }

    printf("\n--- %s ping statistics ---\n", host);
    double loss = sent ? 100.0 * (double)(sent - received) / (double)sent : 0.0;
    printf("%ld packets transmitted, %ld received, %.0f%% packet loss\n", sent, received, loss);
    if (received > 0)
        printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n", rtt_min, rtt_sum / (double)received, rtt_max);

    free(payload);
    free(icmp);
    free(recvbuf);
    close(fd);
    return received > 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    long count = 4, interval_ms = 1000, timeout_ms = 1000, size = NT_PAYLOAD_DEFAULT;
    long ttl = 64;
    int dgram = 0, mtu_do = 0, mtu_dont = 0, v6 = 0;
    const char *host = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if ((v = nt_opt_value(a, 'c', &i, argc, argv)) != NULL) count = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 'i', &i, argc, argv)) != NULL) interval_ms = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 'W', &i, argc, argv)) != NULL) timeout_ms = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 's', &i, argc, argv)) != NULL) size = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 't', &i, argc, argv)) != NULL) ttl = strtol(v, NULL, 10);
        else if (strcmp(a, "--dgram") == 0) dgram = 1;
        else if (strcmp(a, "-6") == 0) v6 = 1;
        else if ((v = nt_opt_value(a, 'M', &i, argc, argv)) != NULL) {
            if (strcmp(v, "do") == 0) mtu_do = 1;
            else if (strcmp(v, "dont") == 0) mtu_dont = 1;
            else { fprintf(stderr, "ping: -M takes do or dont\n"); return 2; }
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(stdout, argv[0]); return 0; }
        else if (a[0] == '-') { fprintf(stderr, "ping: unknown option '%s'\n", a); usage(stderr, argv[0]); return 2; }
        else host = a;
    }
    if (host == NULL) { usage(stderr, argv[0]); return 2; }
    if (size < 0 || size > 65500) { fprintf(stderr, "ping: bad size\n"); return 2; }
    if (interval_ms < 0 || timeout_ms <= 0) { fprintf(stderr, "ping: bad timing\n"); return 2; }

    if (v6)
        return run_ping6(host, count, interval_ms, timeout_ms, size, ttl);

    struct in_addr dst;
    if (resolve(host, &dst) != 0) {
        fprintf(stderr, "ping: cannot resolve %s\n", host);
        return 2;
    }
    uint32_t dst_host = ntohl(dst.s_addr);
    if (nt_guard_ipv4(dst_host) != 0)
        return 1;

    int fd = socket(AF_INET, dgram ? SOCK_DGRAM : SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        fprintf(stderr, "ping: socket: %s (need root/CAP_NET_RAW)\n", strerror(errno));
        return 1;
    }
    int t = (int)ttl;
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &t, sizeof t) != 0)
        fprintf(stderr, "ping: IP_TTL: %s\n", strerror(errno));

    if (mtu_do || mtu_dont) {
        int mode = mtu_do ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
        if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof mode) != 0)
            fprintf(stderr, "ping: IP_MTU_DISCOVER: %s\n", strerror(errno));
    }
    if (dgram) {
        int on = 1;
        (void)setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof on);
    } else {
        /* Let the kernel drop everything but echo requests/replies and errors. */
        struct { uint32_t data; } filt;
        filt.data = ~((1u << 0) | (1u << 8) | (1u << 3) | (1u << 11) | (1u << 12));
        (void)setsockopt(fd, IPPROTO_IP, ICMP_FILTER, &filt, sizeof filt);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr = dst;

    uint16_t id = (uint16_t)(getpid() & 0xffff);
    size_t payload_len = (size_t)size;
    uint8_t *payload = malloc(payload_len ? payload_len : 1);
    uint8_t *icmp = malloc(payload_len + 8);
    uint8_t *recvbuf = malloc(NT_RECV_CAP);
    if (payload == NULL || icmp == NULL || recvbuf == NULL) {
        fprintf(stderr, "ping: out of memory\n");
        free(payload); free(icmp); free(recvbuf); close(fd);
        return 1;
    }

    printf("PING %s (%s): %zu data bytes%s\n", host, inet_ntoa(dst), payload_len,
           dgram ? " (dgram)" : "");

    long sent = 0, received = 0;
    double rtt_min = 0, rtt_max = 0, rtt_sum = 0;

    for (long seq = 1; !g_stop && (count == 0 || received < count); seq++) {
        uint64_t send_ns = nt_now_ns();
        build_payload(payload, payload_len, send_ns);

        size_t icmp_len = 0;
        nt_status bs = nt_build_icmp_echo(icmp, payload_len + 8, &icmp_len, 8, id,
                                          (uint16_t)seq, payload, payload_len);
        if (bs != NT_OK) {
            fprintf(stderr, "ping: build failed: %s\n", nt_status_str(bs));
            break;
        }
        if (sendto(fd, icmp, icmp_len, 0, (struct sockaddr *)&addr, sizeof addr) < 0) {
            if (errno == EMSGSIZE) {
                int mtu = 0; socklen_t ml = sizeof mtu;
                getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &ml);
                printf("ping: local error: message too long, mtu=%d\n", mtu);
            } else {
                fprintf(stderr, "ping: sendto: %s\n", strerror(errno));
                break;
            }
        }
        sent++;

        uint64_t deadline = send_ns + nt_ms_to_ns((uint64_t)timeout_ms);
        while (!g_stop) {
            int r = nt_poll_until(fd, POLLIN, deadline);
            if (r <= 0)
                break;

            uint8_t ctrl[CMSG_SPACE(sizeof(int))];
            struct msghdr msg;
            struct iovec iov = { .iov_base = recvbuf, .iov_len = NT_RECV_CAP };
            memset(&msg, 0, sizeof msg);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl;
            msg.msg_controllen = sizeof ctrl;
            ssize_t n = recvmsg(fd, &msg, 0);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }

            int reply_ttl = (int)ttl;
            if (dgram) {
                for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c != NULL; c = CMSG_NXTHDR(&msg, c))
                    if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL)
                        memcpy(&reply_ttl, CMSG_DATA(c), sizeof reply_ttl);
            }

            const uint8_t *icmp_buf;
            size_t icmp_buflen;
            uint32_t reply_src = dst_host;
            nt_ipv4 ip;
            if (dgram) {
                icmp_buf = recvbuf;
                icmp_buflen = (size_t)n;
            } else {
                if (nt_ipv4_decode(recvbuf, (size_t)n, &ip) != NT_OK)
                    continue;
                reply_src = ip.src;
                reply_ttl = ip.ttl;
                if (!ip.has_l4 || ip.proto != NT_IPPROTO_ICMP) {
                    /* ICMP error about our probe? */
                    continue;
                }
                icmp_buf = ip.payload.data;
                icmp_buflen = ip.payload.len;
            }

            nt_icmp ic;
            if (nt_icmp_decode(icmp_buf, icmp_buflen, &ic) != NT_OK)
                continue;

            if (ic.type != 0) {
                /* error from a router (raw mode only) */
                nt_quote q;
                if (!dgram && (ic.type == 3 || ic.type == 11 || ic.type == 12) &&
                    nt_icmp_quote_parse(&ic, &q) == NT_OK &&
                    q.proto == NT_IPPROTO_ICMP && q.id == id && q.seq == (uint16_t)seq) {
                    char rb[16];
                    fmt_v4(rb, ip.src);
                    printf("From %s icmp_seq=%ld %s\n", rb, seq, error_text(ic.type, ic.code));
                }
                continue;
            }

            /* echo reply: in dgram mode the kernel chose the id, so take it from the reply */
            nt_echo_probe probe = { .id = dgram ? 0 : id, .seq = (uint16_t)seq,
                                    .src = dst_host, .data = payload, .datalen = payload_len };
            if (dgram) {
                uint16_t rid = (uint16_t)((ic.rest.data[0] << 8) | ic.rest.data[1]);
                probe.id = rid;
            }
            if (nt_match_icmp_echo_reply(&ic, reply_src, &probe) != NT_MATCH)
                continue;

            uint64_t now = nt_now_ns();
            double rtt = (double)(now - send_ns) / 1e6;
            received++;
            rtt_sum += rtt;
            if (received == 1 || rtt < rtt_min) rtt_min = rtt;
            if (received == 1 || rtt > rtt_max) rtt_max = rtt;
            size_t icmp_bytes = dgram ? (size_t)n : ip.payload.len;
            printf("%zu bytes from %s: icmp_seq=%ld ttl=%d time=%.3f ms\n",
                   icmp_bytes, inet_ntoa(dst), seq, reply_ttl, rtt);
            break;
        }

        uint64_t next = send_ns + nt_ms_to_ns((uint64_t)interval_ms);
        if (!g_stop && (count == 0 || received < count) && next > nt_now_ns())
            wait_until(next);
    }

    printf("\n--- %s ping statistics ---\n", host);
    double loss = sent ? 100.0 * (double)(sent - received) / (double)sent : 0.0;
    printf("%ld packets transmitted, %ld received, %.0f%% packet loss\n", sent, received, loss);
    if (received > 0)
        printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n", rtt_min, rtt_sum / (double)received, rtt_max);

    free(payload);
    free(icmp);
    free(recvbuf);
    close(fd);
    return received > 0 ? 0 : 1;
}
