/* traceroute(8)-style hop discovery, lab-scoped.
 *
 * UDP mode (default): each probe is a UDP datagram sent with an increasing
 * IP_TTL to a distinct destination port, so the router that discards it returns
 * ICMP time-exceeded quoting our probe's headers. The destination itself returns
 * ICMP port-unreachable (type 3 code 3), which is how we know we arrived.
 *
 * ICMP mode (-I): each probe is an ICMP echo request with a distinctive
 * identifier and a sequence number equal to the TTL; the same raw socket receives
 * the time-exceeded/echo-reply, so we match on the quoted ICMP header.
 */
#include "clock.h"
#include "guard.h"
#include "nettk.h"
#include "opts.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NT_RECV_CAP 65536
#define NT_UDP_BASE_PORT 33434

static volatile sig_atomic_t g_stop;

static void on_signal(int s)
{
    (void)s;
    g_stop = 1;
}

static void fmt_v4(char out[16], uint32_t ip)
{
    snprintf(out, 16, "%u.%u.%u.%u",
             (ip >> 24) & 0xffu, (ip >> 16) & 0xffu, (ip >> 8) & 0xffu, ip & 0xffu);
}

/* traceroute's symbolic annotation for an ICMP error (RFC 792). */
static const char *annot(uint8_t type, uint8_t code)
{
    if (type == 3) {
        switch (code) {
        case 0: return " !N";
        case 1: return " !H";
        case 2:
        case 3: return " !P";
        case 4: return " !F";
        case 5: return " !S";
        case 9:
        case 10:
        case 13: return " !X";
        default: return " !?";
        }
    }
    if (type == 12)
        return " !?";
    return "";
}

int main(int argc, char **argv)
{
    const char *host = NULL;
    long max_ttl = 30, first_ttl = 1, timeout_ms = 1000, size = 0;
    long base_port = NT_UDP_BASE_PORT;
    int icmp_mode = 0, mtu_do = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if (strcmp(a, "-I") == 0) icmp_mode = 1;
        else if (strcmp(a, "-n") == 0) { /* always numeric */ }
        else if ((v = nt_opt_value(a, 'M', &i, argc, argv)) != NULL) {
            if (strcmp(v, "do") == 0) mtu_do = 1;
            else if (strcmp(v, "dont") == 0) mtu_do = 0;
            else { fprintf(stderr, "traceroute: -M takes do|dont\n"); return 2; }
        }
        else if ((v = nt_opt_value(a, 'm', &i, argc, argv)) != NULL) max_ttl = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 'f', &i, argc, argv)) != NULL) first_ttl = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 'W', &i, argc, argv)) != NULL) timeout_ms = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 's', &i, argc, argv)) != NULL) size = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 'p', &i, argc, argv)) != NULL) base_port = strtol(v, NULL, 10);
        else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "traceroute: unknown option %s\n", a);
            return 2;
        } else {
            host = a;
        }
    }
    if (host == NULL || max_ttl < 1 || first_ttl < 1 || first_ttl > max_ttl ||
        timeout_ms <= 0 || size < 0 || base_port < 1 || base_port > 65535) {
        fprintf(stderr,
                "usage: traceroute [-n] [-I] [-M do|dont] [-m max_ttl] [-f first_ttl]\n"
                "                  [-W timeout_ms] [-s size] [-p base_port] <host>\n");
        return 2;
    }

    struct in_addr dst;
    if (inet_aton(host, &dst) == 0) {
        fprintf(stderr, "traceroute: cannot resolve %s (IPv4 literal required)\n", host);
        return 2;
    }
    uint32_t target = ntohl(dst.s_addr);
    if (nt_guard_ipv4(target) != 0)
        return 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int fd_recv, fd_udp = -1;
    if (icmp_mode) {
        fd_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    } else {
        fd_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        fd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    }
    if (fd_recv < 0 || (!icmp_mode && fd_udp < 0)) {
        fprintf(stderr, "traceroute: socket: %s (need root/CAP_NET_RAW)\n", strerror(errno));
        return 1;
    }

    /* Ensure the UDP socket has a stable source port so we can match the quote. */
    uint16_t local_port = 0;
    if (!icmp_mode) {
        struct sockaddr_in any;
        memset(&any, 0, sizeof any);
        any.sin_family = AF_INET;
        any.sin_port = 0;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd_udp, (struct sockaddr *)&any, sizeof any) != 0) {
            fprintf(stderr, "traceroute: bind: %s\n", strerror(errno));
            return 1;
        }
        socklen_t alen = sizeof any;
        if (getsockname(fd_udp, (struct sockaddr *)&any, &alen) != 0) {
            fprintf(stderr, "traceroute: getsockname: %s\n", strerror(errno));
            return 1;
        }
        local_port = ntohs(any.sin_port);
    }

    uint16_t my_id = (uint16_t)(getpid() & 0xffff);

    if (mtu_do) {
        int pmtu = IP_PMTUDISC_DO;
        int sf = icmp_mode ? fd_recv : fd_udp;
        (void)setsockopt(sf, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof pmtu);
    }
    uint8_t *payload = malloc((size_t)size ? (size_t)size : 1);
    uint8_t *recvbuf = malloc(NT_RECV_CAP);
    if (payload == NULL || recvbuf == NULL) {
        fprintf(stderr, "traceroute: out of memory\n");
        return 1;
    }

    char target_txt[16];
    fmt_v4(target_txt, target);
    printf("traceroute to %s (%s), %ld hops max\n", host, target_txt, max_ttl);

    int reached = 0;
    for (long ttl = first_ttl; ttl <= max_ttl && !g_stop && !reached; ttl++) {
        int ttl_i = (int)ttl;
        if (icmp_mode) {
            setsockopt(fd_recv, IPPROTO_IP, IP_TTL, &ttl_i, sizeof ttl_i);
        } else {
            setsockopt(fd_udp, IPPROTO_IP, IP_TTL, &ttl_i, sizeof ttl_i);
        }

        uint64_t send_ns = nt_now_ns();
        uint16_t dport = (uint16_t)(base_port + (ttl - first_ttl));
        uint16_t seq16 = (uint16_t)ttl;

        if (icmp_mode) {
            uint8_t icmp[8 + 256];
            size_t icmp_len = 0;
            if (nt_build_icmp_echo(icmp, sizeof icmp, &icmp_len, 8, my_id, seq16,
                                   payload, (size_t)size) != NT_OK) {
                fprintf(stderr, "traceroute: build failed\n");
                break;
            }
            struct sockaddr_in d;
            memset(&d, 0, sizeof d);
            d.sin_family = AF_INET;
            d.sin_addr = dst;
            if (sendto(fd_recv, icmp, icmp_len, 0,
                       (struct sockaddr *)&d, sizeof d) < 0) {
                fprintf(stderr, "traceroute: sendto: %s\n", strerror(errno));
                break;
            }
        } else {
            struct sockaddr_in d;
            memset(&d, 0, sizeof d);
            d.sin_family = AF_INET;
            d.sin_port = htons(dport);
            d.sin_addr = dst;
            if (sendto(fd_udp, payload, (size_t)size, 0,
                       (struct sockaddr *)&d, sizeof d) < 0) {
                fprintf(stderr, "traceroute: sendto: %s\n", strerror(errno));
                break;
            }
        }

        uint64_t deadline = send_ns + nt_ms_to_ns((uint64_t)timeout_ms);
        int printed = 0;
        while (!g_stop && nt_poll_until(fd_recv, POLLIN, deadline) > 0) {
            struct sockaddr_in from;
            socklen_t flen = sizeof from;
            ssize_t n = recvfrom(fd_recv, recvbuf, NT_RECV_CAP, 0,
                                 (struct sockaddr *)&from, &flen);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }

            nt_ipv4 ip;
            if (nt_ipv4_decode(recvbuf, (size_t)n, &ip) != NT_OK || !ip.has_l4)
                continue;
            nt_icmp ic;
            if (nt_icmp_decode(ip.payload.data, ip.payload.len, &ic) != NT_OK)
                continue;

            int ours = 0;
            const char *note = "";
            if (ic.type == 0) { /* echo reply (ICMP mode) */
                if (icmp_mode && ic.rest.len >= 4 &&
                    rd16be(ic.rest.data, 0) == my_id &&
                    rd16be(ic.rest.data, 2) == seq16)
                    ours = 1;
            } else if (ic.type == 3 || ic.type == 11 || ic.type == 12) {
                nt_quote q;
                if (nt_icmp_quote_parse(&ic, &q) != NT_OK)
                    continue;
                if (icmp_mode) {
                    ours = (q.proto == NT_IPPROTO_ICMP && q.id == my_id && q.seq == seq16);
                } else {
                    ours = (q.proto == NT_IPPROTO_UDP && q.sport == local_port &&
                            q.dport == dport);
                }
                note = annot(ic.type, ic.code);
            }
            if (!ours)
                continue;

            uint64_t now = nt_now_ns();
            double rtt = (double)(now - send_ns) / 1e6;
            char hop[16];
            fmt_v4(hop, ip.src);
            printf("%2ld  %-15s  %.3f ms%s", ttl, hop, rtt, note);
            if (ic.type == 3 && ic.code == 4 && ic.rest.len >= 4)
                printf(" mtu=%u", rd16be(ic.rest.data, 2));
            printf("\n");
            printed = 1;

            if ((ic.type == 0 && ip.src == target) ||
                (ic.type == 3 && ip.src == target))
                reached = 1;
            break;
        }
        if (!printed && !g_stop)
            printf("%2ld  *\n", ttl);
    }

    free(payload);
    free(recvbuf);
    close(fd_recv);
    if (fd_udp >= 0)
        close(fd_udp);
    return reached ? 0 : 1;
}
