#include "guard.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/ethtool.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SIOCETHTOOL
#define SIOCETHTOOL 0x8946
#endif

#define NT_LAB_V4_NET  0x0a000000u /* 10.0.0.0 */
#define NT_LAB_V4_MASK 0xffff0000u /* /16 */

int nt_in_lab_v4(uint32_t addr)
{
    return (addr & NT_LAB_V4_MASK) == NT_LAB_V4_NET;
}

int nt_in_lab_v6(const uint8_t a[16])
{
    if (a[0] == 0xfd)
        return 1; /* fd00::/8 (ULA) */
    return a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8; /* 2001:db8::/32 */
}

int nt_in_lab_ip(const char *text)
{
    struct in_addr  v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, text, &v4) == 1)
        return nt_in_lab_v4(ntohl(v4.s_addr));
    if (inet_pton(AF_INET6, text, &v6) == 1)
        return nt_in_lab_v6(v6.s6_addr);
    return 0;
}

static void fmt_v4(char out[16], uint32_t ip)
{
    snprintf(out, 16, "%u.%u.%u.%u",
             (ip >> 24) & 0xffu, (ip >> 16) & 0xffu, (ip >> 8) & 0xffu, ip & 0xffu);
}

int nt_guard_lab(void)
{
    const char *lab = getenv("NT_LAB");
    if (lab != NULL && strcmp(lab, "1") == 0)
        return 0;
    fprintf(stderr, "nettk: refusing to send: NT_LAB is not set "
                    "(run inside the lab via lab/ex)\n");
    return -1;
}

int nt_guard_ipv4(uint32_t dst)
{
    if (nt_guard_lab() != 0)
        return -1;
    if (!nt_in_lab_v4(dst)) {
        char b[16];
        fmt_v4(b, dst);
        fprintf(stderr, "nettk: refusing to send to %s: outside 10.0.0.0/16\n", b);
        return -1;
    }
    return 0;
}

int nt_guard_ipv6(const uint8_t dst[16])
{
    if (nt_guard_lab() != 0)
        return -1;
    if (!nt_in_lab_v6(dst)) {
        char b[INET6_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET6, dst, b, sizeof b);
        fprintf(stderr, "nettk: refusing to send to %s: outside fd00::/8 and 2001:db8::/32\n", b);
        return -1;
    }
    return 0;
}

int nt_guard_iface_veth(const char *ifname)
{
    if (nt_guard_lab() != 0)
        return -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "nettk: guard: socket: %s\n", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    struct ethtool_drvinfo info;
    memset(&info, 0, sizeof info);
    info.cmd = ETHTOOL_GDRVINFO;
    ifr.ifr_data = (char *)&info;

    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        fprintf(stderr, "nettk: %s: cannot query driver: %s\n", ifname, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    if (strcmp(info.driver, "veth") != 0) {
        fprintf(stderr, "nettk: refusing ARP/NDP on %s: driver '%s' is not veth\n",
                ifname, info.driver);
        return -1;
    }
    return 0;
}
