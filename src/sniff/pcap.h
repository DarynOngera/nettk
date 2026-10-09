#ifndef SNIFF_PCAP_H
#define SNIFF_PCAP_H

#include "nettk.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Reader: classic libpcap only, Ethernet (link type 1), both byte orders,
 * microsecond and nanosecond magics. */
typedef struct {
    FILE    *f;
    int      swapped;  /* file byte order differs from host */
    int      nano;     /* timestamps are nanoseconds */
    uint32_t snaplen;
    uint32_t linktype;
} nt_pcap;

/* NT_OK, or NT_ERR_* after printing a reason to stderr. */
nt_status nt_pcap_open(nt_pcap *p, const char *path);

/* 1 = packet in buf, 0 = clean EOF, -1 = read error.
 * caplen is the bytes written to buf; origlen the on-wire length from the record.
 * ts_sec/ts_frac are the record timestamp (frac is us or ns per the file magic). */
int nt_pcap_next(nt_pcap *p, uint8_t *buf, size_t cap, size_t *caplen, size_t *origlen,
                 uint32_t *ts_sec, uint32_t *ts_frac);

void nt_pcap_close(nt_pcap *p);

/* Writer: classic pcap in host byte order, link type 1 (Ethernet) only. */
typedef struct {
    FILE *f;
    int   nano;
} nt_pcap_writer;

int nt_pcap_writer_open(nt_pcap_writer *w, const char *path, int nano, uint32_t snaplen);
int nt_pcap_writer_write(nt_pcap_writer *w, const uint8_t *buf, size_t caplen, size_t origlen,
                         uint32_t ts_sec, uint32_t ts_frac);
void nt_pcap_writer_close(nt_pcap_writer *w);

#endif /* SNIFF_PCAP_H */
