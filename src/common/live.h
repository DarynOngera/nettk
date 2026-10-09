#ifndef NT_LIVE_H
#define NT_LIVE_H

#include <stddef.h>
#include <stdint.h>

/* AF_PACKET SOCK_RAW capture on one interface (M7). Frames are raw Ethernet.
 * The kernel strips 802.1Q tags from incoming frames and reports them via
 * PACKET_AUXDATA; nt_live_next re-inserts the tag so decoders see it in-band.
 * buf must therefore hold cap + 4 bytes. */
typedef struct {
    int fd;
    int ifindex;
    unsigned long incoming;
    unsigned long outgoing;
} nt_live;

/* Open AF_PACKET bound to iface, enable promiscuous mode and auxdata, then drop
 * to the real uid keeping only CAP_NET_RAW. 0 on success, -1 on error. */
int nt_live_open(nt_live *l, const char *iface);

/* 1 = frame in buf, 0 = no frame this timeout, -1 = error.
 * ts_us is CLOCK_REALTIME at receipt, in microseconds. */
int nt_live_next(nt_live *l, uint8_t *buf, size_t cap, size_t *caplen, uint64_t *ts_us);

void nt_live_close(nt_live *l);

#endif /* NT_LIVE_H */
