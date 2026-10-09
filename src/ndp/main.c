/* ndp: resolve an IPv6 address to a MAC with a Neighbour Solicitation on a lab
 * veth. NS goes to the solicited-node multicast address with hop limit 255; an
 * Advertisement is accepted only from the target with hop limit 255, code 0 and
 * a valid checksum (RFC 4861 section 7.1). That hop-limit check is what stops an
 * off-link attacker from poisoning the cache, because only a neighbour can send
 * a 255 hop-limit packet that survives the last hop. */
#include "clock.h"
#include "guard.h"
#include "nettk.h"
#include "opts.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NT_NDP_RECV_CAP 2048

static void fmt_mac(char out[18], const uint8_t m[6])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void solicited_node(const uint8_t target[16], uint8_t out[16])
{
    memset(out, 0, 16);
    out[0] = 0xff; out[1] = 0x02; out[11] = 0x01; out[12] = 0xff;
    out[13] = target[13];
    out[14] = target[14];
    out[15] = target[15];
}

/* walk the NA options for the Target Link-Layer Address (type 2). */
static int find_tll(const nt_icmp *ic, uint8_t mac[6])
{
    if (ic->rest.len < 20)
        return -1;
    const uint8_t *p = ic->rest.data + 20;
    size_t n = ic->rest.len - 20;
    while (n >= 8) {
        uint8_t type = p[0];
        size_t olen = (size_t)p[1] * 8;
        if (olen == 0 || olen > n)
            break;
        if (type == 2 && olen >= 8) {
            memcpy(mac, p + 2, 6);
            return 0;
        }
        p += olen;
        n -= olen;
    }
    return -1;
}

int main(int argc, char **argv)
{
    const char *iface = NULL, *host = NULL;
    long tries = 3, timeout_ms = 1000;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if ((v = nt_opt_value(a, 'i', &i, argc, argv)) != NULL) iface = v;
        else if ((v = nt_opt_value(a, 'c', &i, argc, argv)) != NULL) tries = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 'W', &i, argc, argv)) != NULL) timeout_ms = strtol(v, NULL, 10);
        else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "ndp: unknown option %s\n", a);
            return 2;
        } else host = a;
    }
    if (iface == NULL || host == NULL || tries < 1 || timeout_ms <= 0) {
        fprintf(stderr, "usage: ndp -i <iface> [-c tries] [-W timeout_ms] <ipv6>\n");
        return 2;
    }

    uint8_t target[16];
    if (inet_pton(AF_INET6, host, target) != 1) {
        fprintf(stderr, "ndp: bad IPv6 address '%s'\n", host);
        return 2;
    }
    if (nt_guard_ipv6(target) != 0)
        return 1;
    if (nt_guard_iface_veth(iface) != 0)
        return 1;

    unsigned ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "ndp: %s: no such interface\n", iface);
        return 1;
    }

    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) {
        fprintf(stderr, "ndp: socket: %s (need root/CAP_NET_RAW)\n", strerror(errno));
        return 1;
    }
    int hl = 255, ifi = (int)ifindex, on = 1;
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hl, sizeof hl);
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifi, sizeof ifi);
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof on);
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof on);

    uint8_t mcast[16], zeros[16] = { 0 };
    solicited_node(target, mcast);
    uint8_t icmp[32];
    size_t icmp_len = 0;
    if (nt_build_icmp6_ns(icmp, sizeof icmp, &icmp_len, zeros, mcast, target, NULL) != NT_OK) {
        fprintf(stderr, "ndp: build failed\n");
        close(fd);
        return 1;
    }

    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof dst);
    dst.sin6_family = AF_INET6;
    memcpy(&dst.sin6_addr, mcast, 16);
    dst.sin6_scope_id = ifindex;

    char ttxt[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, target, ttxt, sizeof ttxt);
    printf("NDP %s on %s\n", ttxt, iface);

    int found = 0;
    long rejected = 0;
    for (long try = 1; try <= tries && !found; try++) {
        uint64_t send_ns = nt_now_ns();
        if (sendto(fd, icmp, icmp_len, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
            fprintf(stderr, "ndp: sendto: %s\n", strerror(errno));
            break;
        }
        uint64_t deadline = send_ns + nt_ms_to_ns((uint64_t)timeout_ms);

        while (nt_poll_until(fd, POLLIN, deadline) > 0) {
            uint8_t buf[NT_NDP_RECV_CAP], ctrl[256];
            struct sockaddr_in6 from;
            struct iovec iov = { .iov_base = buf, .iov_len = sizeof buf };
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

            int hop = 0;
            struct in6_addr local;
            memset(&local, 0, sizeof local);
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c != NULL; c = CMSG_NXTHDR(&msg, c)) {
                if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_HOPLIMIT)
                    memcpy(&hop, CMSG_DATA(c), sizeof hop);
                else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
                    struct in6_pktinfo pi;
                    memcpy(&pi, CMSG_DATA(c), sizeof pi);
                    local = pi.ipi6_addr;
                }
            }

            nt_pseudo ph;
            memset(&ph, 0, sizeof ph);
            ph.family = 6;
            memcpy(ph.src6, &from.sin6_addr, 16);
            memcpy(ph.dst6, &local, 16);
            nt_icmp ic;
            if (nt_icmp6_decode(buf, (size_t)n, &ph, &ic) != NT_OK)
                continue;
            if (ic.type != 136)
                continue;

            /* RFC 4861 7.1.1: hop limit 255, code 0, checksum valid, target matches. */
            if (hop != 255) { rejected++; continue; }
            if (ic.code != 0 || ic.csum_state != NT_CSUM_VALID) { rejected++; continue; }
            if (!ic.has_target || memcmp(ic.target, target, 16) != 0) { rejected++; continue; }

            uint8_t mac[6];
            if (find_tll(&ic, mac) != 0) { rejected++; continue; }

            uint64_t now = nt_now_ns();
            char mac_txt[18];
            fmt_mac(mac_txt, mac);
            printf("%s is-at %s  %.3f ms\n", ttxt, mac_txt, (double)(now - send_ns) / 1e6);
            found = 1;
            break;
        }
    }

    if (!found)
        printf("no advertisement from %s\n", ttxt);
    if (rejected)
        printf("rejected %ld advertisement(s) (hop limit, checksum or target)\n", rejected);
    close(fd);
    return found ? 0 : 1;
}
