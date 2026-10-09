/* Live AF_PACKET capture (M7). No libpcap: socket(AF_PACKET, SOCK_RAW) gives
 * whole Ethernet frames, so no SLL header to strip. PACKET_AUXDATA recovers the
 * 802.1Q tag the kernel removed; it is re-inserted at offset 12 so the decode
 * library sees an in-band frame. Privileges are dropped after the socket is
 * open, keeping only CAP_NET_RAW. */
#include "live.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/capability.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#ifndef TP_STATUS_VLAN_VALID
#define TP_STATUS_VLAN_VALID 0x10
#endif
#ifndef TP_STATUS_VLAN_TPID_VALID
#define TP_STATUS_VLAN_TPID_VALID 0x40
#endif

/* Confirm the process effective set is exactly {CAP_NET_RAW} (M12 hardening). */
static int caps_are_minimal(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (f == NULL)
        return -1;
    char line[256];
    unsigned long low = 0, high = 0;
    int found = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            if (sscanf(line + 7, "%lx %lx", &low, &high) < 1)
                break;
            found = 1;
            break;
        }
    }
    fclose(f);
    if (!found)
        return -1;
    unsigned long want = 1ul << (CAP_NET_RAW & 31);
    return ((low & ~want) != 0 || high != 0) ? -1 : 0;
}

/* Drop from root to the invoking user while retaining CAP_NET_RAW only.
 * Under `sudo` the target is SUDO_UID/SUDO_GID; otherwise the real uid. */
static int drop_privileges(void)
{
    if (geteuid() != 0)
        return 0;

    uid_t uid = getuid();
    gid_t gid = getgid();
    const char *su = getenv("SUDO_UID");
    const char *sg = getenv("SUDO_GID");
    if (su != NULL && *su != '\0') {
        uid_t u = (uid_t)strtoul(su, NULL, 10);
        if (u != 0)
            uid = u;
    }
    if (sg != NULL && *sg != '\0') {
        gid_t g = (gid_t)strtoul(sg, NULL, 10);
        if (g != 0)
            gid = g;
    }
    if (uid == 0)
        return 0; /* genuinely root with no other user to drop to */

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0)
        return -1;
    if (setresgid(gid, gid, gid) != 0)
        return -1;
    if (setresuid(uid, uid, uid) != 0)
        return -1;

    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    unsigned long cap_bit = 1ul << (CAP_NET_RAW & 31);
    data[CAP_NET_RAW >> 5].effective = (uint32_t)cap_bit;
    data[CAP_NET_RAW >> 5].permitted = (uint32_t)cap_bit;
    if (syscall(SYS_capset, &hdr, data) != 0)
        return -1;
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0)
        return -1;
    if (caps_are_minimal() != 0)
        return -1;
    return 0;
}

int nt_live_open(nt_live *l, const char *iface)
{
    memset(l, 0, sizeof *l);
    l->fd = -1;
    l->ifindex = (int)if_nametoindex(iface);
    if (l->ifindex == 0) {
        fprintf(stderr, "nettk: no such interface '%s'\n", iface);
        return -1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "nettk: socket(AF_PACKET): %s (need root/CAP_NET_RAW)\n",
                strerror(errno));
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = l->ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
        fprintf(stderr, "nettk: bind %s: %s\n", iface, strerror(errno));
        close(fd);
        return -1;
    }

    struct packet_mreq mr;
    memset(&mr, 0, sizeof mr);
    mr.mr_ifindex = l->ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    (void)setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr);

    int one = 1;
    (void)setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof one);
#ifdef PACKET_IGNORE_OUTGOING
    (void)setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof one);
#endif

    struct timeval tv = { 1, 0 }; /* so the loop can notice SIGINT */
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int rcvbuf = 4 * 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

    if (drop_privileges() != 0) {
        fprintf(stderr, "nettk: privilege drop failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    l->fd = fd;
    return 0;
}

int nt_live_next(nt_live *l, uint8_t *buf, size_t cap, size_t *caplen, uint64_t *ts_us)
{
    uint8_t ctrl[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    struct sockaddr_ll from;
    struct iovec iov = { .iov_base = buf, .iov_len = cap };
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    memset(&from, 0, sizeof from);
    msg.msg_name = &from;
    msg.msg_namelen = sizeof from;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof ctrl;

    ssize_t n = recvmsg(l->fd, &msg, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
        fprintf(stderr, "nettk: recvmsg: %s\n", strerror(errno));
        return -1;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    *ts_us = (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);

    if (from.sll_pkttype == PACKET_OUTGOING)
        l->outgoing++;
    else
        l->incoming++;

    size_t len = (size_t)n;
    if (msg.msg_flags & MSG_TRUNC)
        len = cap;

    /* Re-insert a stripped 802.1Q tag at offset 12 (after the MACs). */
    uint16_t tci = 0, tpid = ETH_P_8021Q;
    int have_vlan = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c != NULL; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_PACKET && c->cmsg_type == PACKET_AUXDATA) {
            struct tpacket_auxdata aux;
            memcpy(&aux, CMSG_DATA(c), sizeof aux);
            if (aux.tp_status & TP_STATUS_VLAN_VALID) {
                tci = aux.tp_vlan_tci;
                if (aux.tp_status & TP_STATUS_VLAN_TPID_VALID)
                    tpid = aux.tp_vlan_tpid;
                have_vlan = 1;
            }
        }
    }
    if (have_vlan && len >= 12 && len + 4 <= cap + 4) {
        memmove(buf + 16, buf + 12, len - 12);
        buf[12] = (uint8_t)(tpid >> 8);
        buf[13] = (uint8_t)tpid;
        buf[14] = (uint8_t)(tci >> 8);
        buf[15] = (uint8_t)tci;
        len += 4;
    }

    *caplen = len;
    return 1;
}

void nt_live_close(nt_live *l)
{
    if (l->fd >= 0) {
        close(l->fd);
        l->fd = -1;
    }
}
