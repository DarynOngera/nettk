/* arp: resolve/probe an IPv4 address, or scan a /24 on a lab veth.
 *
 * Frames are built by hand (nt_build_arp_frame) and padded to the 60-byte
 * Ethernet minimum; an AF_PACKET/SOCK_RAW socket bypasses the kernel's own
 * neighbour logic so probe mode can send sender IP 0.0.0.0 (RFC 5227) and never
 * writes the kernel neighbour table. Replies are validated against the request:
 * opcode 2, sender protocol address equals the address asked about, target IP
 * matches ours, and the ARP sender-hardware field equals the Ethernet source.
 */
#include "clock.h"
#include "guard.h"
#include "nettk.h"
#include "opts.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netpacket/packet.h>

#define NT_ARP_RECV_CAP 2048
#define NT_ETH_MIN 60
#define NT_SCAN_MAX_HOSTS 254
#define NT_BCAST { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }

static const uint8_t bcast[6] = NT_BCAST;

static void fmt_v4(char out[16], uint32_t ip)
{
    snprintf(out, 16, "%u.%u.%u.%u",
             (ip >> 24) & 0xffu, (ip >> 16) & 0xffu, (ip >> 8) & 0xffu, ip & 0xffu);
}

static void fmt_mac(char out[18], const uint8_t m[6])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void put_v4(uint8_t out[4], uint32_t ip)
{
    out[0] = (uint8_t)(ip >> 24); out[1] = (uint8_t)(ip >> 16);
    out[2] = (uint8_t)(ip >> 8);  out[3] = (uint8_t)ip;
}

static int iface_mac_ip(const char *iface, uint8_t mac[6], uint32_t *ip)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) { close(fd); return -1; }
    *ip = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
    close(fd);
    return 0;
}

static int arp_socket(const char *iface, int *ifindex)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0)
        return -1;
    struct sockaddr_ll ll;
    memset(&ll, 0, sizeof ll);
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_ARP);
    ll.sll_ifindex = (int)if_nametoindex(iface);
    if (ll.sll_ifindex == 0 || bind(fd, (struct sockaddr *)&ll, sizeof ll) != 0) {
        close(fd);
        return -1;
    }
    *ifindex = ll.sll_ifindex;
    return fd;
}

/* returns 1 if buf is a valid reply for `target`/`our_ip`, fills sha; -1 if the
 * reply fails the Ethernet/ARP MAC consistency check, 0 otherwise. */
static int arp_reply_ok(const uint8_t *buf, size_t len, uint32_t target, uint32_t our_ip,
                        const uint8_t our_mac[6], uint8_t sha[6], uint16_t *op_out)
{
    nt_eth_hdr eth;
    nt_vlan vlan;
    if (nt_eth_decode(buf, len, &eth, &vlan) != NT_OK || eth.ethertype != 0x0806)
        return 0;
    nt_arp a;
    if (nt_arp_decode(buf + 14, len - 14, &a) != NT_OK)
        return 0;
    *op_out = a.op;
    if (a.op != 2)
        return 0;
    if (memcmp(a.spa, (uint8_t[]){ (uint8_t)(target >> 24), (uint8_t)(target >> 16),
                                   (uint8_t)(target >> 8), (uint8_t)target }, 4) != 0)
        return 0; /* sender IP is not the address we asked about */
    if (memcmp(a.sha, eth.src, 6) != 0)
        return -1; /* Ethernet/ARP MAC inconsistency */
    if (memcmp(eth.dst, our_mac, 6) != 0 && memcmp(eth.dst, bcast, 6) != 0)
        return 0; /* not addressed to us */
    if (our_ip != 0 && memcmp(a.tpa, (uint8_t[]){ (uint8_t)(our_ip >> 24),
             (uint8_t)(our_ip >> 16), (uint8_t)(our_ip >> 8), (uint8_t)our_ip }, 4) != 0)
        return 0; /* reply targets a different address than ours */
    memcpy(sha, a.sha, 6);
    return 1;
}

static int run_resolve(const char *iface, uint32_t target, int probe, long tries, long timeout_ms)
{
    uint8_t our_mac[6];
    uint32_t our_ip = 0;
    if (iface_mac_ip(iface, our_mac, &our_ip) != 0) {
        fprintf(stderr, "arp: %s: cannot read MAC/address: %s\n", iface, strerror(errno));
        return 1;
    }
    int ifindex;
    int fd = arp_socket(iface, &ifindex);
    if (fd < 0) {
        fprintf(stderr, "arp: socket: %s (need root/CAP_NET_RAW)\n", strerror(errno));
        return 1;
    }

    nt_arp_in req;
    memset(&req, 0, sizeof req);
    memcpy(req.eth_src, our_mac, 6);
    memcpy(req.eth_dst, bcast, 6);
    req.op = 1;
    memcpy(req.sha, our_mac, 6);
    put_v4(req.spa, probe ? 0 : our_ip);
    put_v4(req.tpa, target);

    uint8_t frame[NT_ETH_MIN];
    size_t frame_len = 0;
    if (nt_build_arp_frame(frame, sizeof frame, &frame_len, &req) != NT_OK) {
        fprintf(stderr, "arp: build failed\n");
        close(fd);
        return 1;
    }
    if (frame_len < NT_ETH_MIN) {
        memset(frame + frame_len, 0, NT_ETH_MIN - frame_len);
        frame_len = NT_ETH_MIN;
    }

    struct sockaddr_ll to;
    memset(&to, 0, sizeof to);
    to.sll_family = AF_PACKET;
    to.sll_protocol = htons(ETH_P_ARP);
    to.sll_ifindex = ifindex;
    to.sll_halen = 6;
    memcpy(to.sll_addr, bcast, 6);

    char ttxt[16], iptxt[16], mac_txt[18];
    fmt_v4(ttxt, target);
    fmt_v4(iptxt, our_ip);
    fmt_mac(mac_txt, our_mac);
    printf("%s %s from %s [%s] on %s\n",
           probe ? "PROBE" : "ARPING", ttxt, probe ? "0.0.0.0" : iptxt, mac_txt, iface);

    int found = 0;
    long mismatched = 0, ignored = 0;
    for (long try = 1; try <= tries && !found; try++) {
        uint64_t send_ns = nt_now_ns();
        if (sendto(fd, frame, frame_len, 0, (struct sockaddr *)&to, sizeof to) < 0) {
            fprintf(stderr, "arp: sendto: %s\n", strerror(errno));
            break;
        }
        uint64_t deadline = send_ns + nt_ms_to_ns((uint64_t)timeout_ms);

        while (nt_poll_until(fd, POLLIN, deadline) > 0) {
            uint8_t buf[NT_ARP_RECV_CAP];
            struct sockaddr_ll from;
            socklen_t flen = sizeof from;
            ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (from.sll_pkttype == PACKET_OUTGOING)
                continue;
            uint8_t sha[6];
            uint16_t op = 0;
            int r = arp_reply_ok(buf, (size_t)n, target, probe ? 0 : our_ip, our_mac, sha, &op);
            if (r < 0) { mismatched++; continue; }
            if (r == 0) {
                if (op == 2)
                    ignored++;
                continue;
            }
            uint64_t now = nt_now_ns();
            fmt_mac(mac_txt, sha);
            printf("Unicast reply from %s [%s]  %.3f ms\n",
                   ttxt, mac_txt, (double)(now - send_ns) / 1e6);
            found = 1;
            break;
        }
        timeout_ms *= 2; /* backoff between retries */
    }

    if (!found)
        printf("no reply from %s\n", ttxt);
    if (mismatched || ignored)
        printf("ignored %ld replies (%ld Ethernet/ARP MAC mismatches)\n", ignored + mismatched, mismatched);
    close(fd);
    return found ? 0 : 1;
}

typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
    uint8_t  mac2[6];
    int      have;
    int      conflict;
} scan_slot;

static int parse_cidr(const char *s, uint32_t *network, int *prefix)
{
    char buf[64];
    snprintf(buf, sizeof buf, "%s", s);
    char *slash = strchr(buf, '/');
    if (slash == NULL)
        return -1;
    *slash = '\0';
    char *end = NULL;
    long p = strtol(slash + 1, &end, 10);
    if (end == slash + 1 || *end != '\0' || p < 0 || p > 32)
        return -1;
    struct in_addr a;
    if (inet_aton(buf, &a) == 0)
        return -1;
    *prefix = (int)p;
    *network = ntohl(a.s_addr);
    return 0;
}

static void scan_reply(scan_slot *slots, int nslots, uint32_t network, int prefix,
                       const uint8_t *buf, size_t len, const uint8_t our_mac[6])
{
    nt_eth_hdr eth;
    nt_vlan vlan;
    if (nt_eth_decode(buf, len, &eth, &vlan) != NT_OK || eth.ethertype != 0x0806)
        return;
    nt_arp a;
    if (nt_arp_decode(buf + 14, len - 14, &a) != NT_OK || a.op != 2)
        return;
    if (memcmp(a.sha, eth.src, 6) != 0)
        return; /* MAC inconsistency: ignore, not attributed to a host */
    uint32_t ip = ((uint32_t)a.spa[0] << 24) | ((uint32_t)a.spa[1] << 16) |
                  ((uint32_t)a.spa[2] << 8) | a.spa[3];
    uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
    if ((ip & mask) != (network & mask))
        return;
    uint32_t idx = ip - network - 1;
    if ((int)idx >= nslots)
        return;
    scan_slot *s = &slots[idx];
    s->ip = ip;
    if (!s->have) {
        memcpy(s->mac, a.sha, 6);
        s->have = 1;
    } else if (memcmp(s->mac, a.sha, 6) != 0) {
        memcpy(s->mac2, a.sha, 6);
        s->conflict = 1;
    }
    (void)our_mac;
}

static int run_scan(const char *iface, const char *cidr, long rate)
{
    uint32_t network;
    int prefix;
    if (parse_cidr(cidr, &network, &prefix) != 0) {
        fprintf(stderr, "arp scan: bad CIDR '%s'\n", cidr);
        return 2;
    }
    if (prefix < 24) {
        fprintf(stderr, "arp scan: at most a /24 (%d is too broad)\n", prefix);
        return 2;
    }
    if (rate < 1)
        rate = 1;
    if (rate > 1000)
        rate = 1000;

    uint32_t mask = 0xffffffffu << (32 - prefix);
    uint32_t first = (network & mask) + 1;
    uint32_t last = (network | ~mask) - 1;
    int nslots = (int)(last - first + 1);
    if (nslots < 1 || nslots > NT_SCAN_MAX_HOSTS) {
        fprintf(stderr, "arp scan: no usable hosts\n");
        return 2;
    }
    if (nt_guard_ipv4(network) != 0)
        return 1;
    if (nt_guard_iface_veth(iface) != 0)
        return 1;

    uint8_t our_mac[6];
    uint32_t our_ip = 0;
    if (iface_mac_ip(iface, our_mac, &our_ip) != 0) {
        fprintf(stderr, "arp: %s: cannot read MAC/address: %s\n", iface, strerror(errno));
        return 1;
    }
    int ifindex;
    int fd = arp_socket(iface, &ifindex);
    if (fd < 0) {
        fprintf(stderr, "arp: socket: %s (need root/CAP_NET_RAW)\n", strerror(errno));
        return 1;
    }

    scan_slot *slots = calloc((size_t)nslots, sizeof *slots);
    if (slots == NULL) {
        close(fd);
        return 1;
    }
    for (int i = 0; i < nslots; i++)
        slots[i].ip = first + (uint32_t)i;

    struct sockaddr_ll to;
    memset(&to, 0, sizeof to);
    to.sll_family = AF_PACKET;
    to.sll_protocol = htons(ETH_P_ARP);
    to.sll_ifindex = ifindex;
    to.sll_halen = 6;
    memcpy(to.sll_addr, bcast, 6);

    uint64_t interval = 1000000000ull / (uint64_t)rate;
    printf("arp scan %s on %s (%d hosts, %ld pps)\n", cidr, iface, nslots, rate);

    uint64_t next = nt_now_ns();
    for (int i = 0; i < nslots; i++) {
        uint64_t now = nt_now_ns();
        while (now < next) {
            if (nt_poll_until(fd, POLLIN, next) > 0) {
                uint8_t buf[NT_ARP_RECV_CAP];
                struct sockaddr_ll from;
                socklen_t flen = sizeof from;
                ssize_t n = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT,
                                     (struct sockaddr *)&from, &flen);
                if (n > 0 && from.sll_pkttype != PACKET_OUTGOING)
                    scan_reply(slots, nslots, network, prefix, buf, (size_t)n, our_mac);
            }
            now = nt_now_ns();
        }
        nt_arp_in req;
        memset(&req, 0, sizeof req);
        memcpy(req.eth_src, our_mac, 6);
        memcpy(req.eth_dst, bcast, 6);
        req.op = 1;
        memcpy(req.sha, our_mac, 6);
        put_v4(req.spa, our_ip);
        put_v4(req.tpa, slots[i].ip);
        uint8_t frame[NT_ETH_MIN];
        size_t flen2 = 0;
        if (nt_build_arp_frame(frame, sizeof frame, &flen2, &req) == NT_OK) {
            if (flen2 < NT_ETH_MIN) {
                memset(frame + flen2, 0, NT_ETH_MIN - flen2);
                flen2 = NT_ETH_MIN;
            }
            sendto(fd, frame, flen2, 0, (struct sockaddr *)&to, sizeof to);
        }
        next += interval;
    }

    uint64_t grace = nt_now_ns() + nt_ms_to_ns(2000);
    while (nt_poll_until(fd, POLLIN, grace) > 0) {
        uint8_t buf[NT_ARP_RECV_CAP];
        struct sockaddr_ll from;
        socklen_t flen = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT,
                             (struct sockaddr *)&from, &flen);
        if (n <= 0 || from.sll_pkttype == PACKET_OUTGOING)
            continue;
        scan_reply(slots, nslots, network, prefix, buf, (size_t)n, our_mac);
    }

    int answered = 0;
    for (int i = 0; i < nslots; i++) {
        if (!slots[i].have)
            continue;
        char ipt[16], m1[18], m2[18];
        fmt_v4(ipt, slots[i].ip);
        fmt_mac(m1, slots[i].mac);
        answered++;
        if (slots[i].conflict) {
            fmt_mac(m2, slots[i].mac2);
            printf("%s is-at %s  CONFLICT %s\n", ipt, m1, m2);
        } else {
            printf("%s is-at %s\n", ipt, m1);
        }
    }
    printf("%d of %d hosts answered\n", answered, nslots);
    free(slots);
    close(fd);
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: arp -i <iface> [--probe] [-c tries] [-W timeout_ms] <ipv4>\n"
            "       arp scan -i <iface> [--rate pps] <cidr>   (at most a /24)\n");
}

int main(int argc, char **argv)
{
    const char *iface = NULL, *host = NULL;
    int probe = 0;
    long tries = 3, timeout_ms = 500, rate = 100;

    if (argc >= 2 && strcmp(argv[1], "scan") == 0) {
        const char *cidr = NULL;
        for (int i = 2; i < argc; i++) {
            const char *a = argv[i];
            const char *v;
            if ((v = nt_opt_value(a, 'i', &i, argc, argv)) != NULL) iface = v;
            else if (strcmp(a, "--rate") == 0 && i + 1 < argc) rate = strtol(argv[++i], NULL, 10);
            else if (a[0] == '-' && a[1] != '\0') { usage(); return 2; }
            else cidr = a;
        }
        if (iface == NULL || cidr == NULL) { usage(); return 2; }
        return run_scan(iface, cidr, rate);
    }

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if ((v = nt_opt_value(a, 'i', &i, argc, argv)) != NULL) iface = v;
        else if (strcmp(a, "--probe") == 0) probe = 1;
        else if ((v = nt_opt_value(a, 'c', &i, argc, argv)) != NULL) tries = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 'W', &i, argc, argv)) != NULL) timeout_ms = strtol(v, NULL, 10);
        else if (a[0] == '-' && a[1] != '\0') { fprintf(stderr, "arp: unknown option %s\n", a); return 2; }
        else host = a;
    }
    if (iface == NULL || host == NULL || tries < 1 || timeout_ms <= 0) {
        usage();
        return 2;
    }

    struct in_addr t;
    if (inet_aton(host, &t) == 0) {
        fprintf(stderr, "arp: bad IPv4 address '%s'\n", host);
        return 2;
    }
    uint32_t target = ntohl(t.s_addr);
    if (nt_guard_ipv4(target) != 0)
        return 1;
    if (nt_guard_iface_veth(iface) != 0)
        return 1;
    return run_resolve(iface, target, probe, tries, timeout_ms);
}
