/* Minimal classic-pcap reader/writer (M6).
 *
 * Reader rules (docs/phase1.md section 7, phase1-prompt rule 15):
 *   - both byte orders; us and ns magics
 *   - Ethernet link type (1) only; anything else -> NT_ERR_UNSUPPORTED
 *   - reject caplen > snaplen, caplen > 256 KiB, caplen > bytes left in file
 *   - reject a short record header
 * Writer emits little-endian classic pcap, link type 1. No I/O in src/lib/. */
#include "pcap.h"

#include <errno.h>
#include <string.h>

#define PCAP_MAGIC_US   0xa1b2c3d4u
#define PCAP_MAGIC_NS   0xa1b23c4dU
#define PCAP_GLOBAL_LEN 24u
#define PCAP_RECORD_LEN 16u
#define PCAP_CAP_MAX    262144u
#define PCAP_LINKTYPE_ETHERNET 1u
#define PCAP_VERSION_MAJOR 2u
#define PCAP_VERSION_MINOR 4u

static uint32_t sw32(int swapped, uint32_t v)
{
    return swapped ? ((v >> 24) | ((v >> 8) & 0x0000ff00u) |
                      ((v << 8) & 0x00ff0000u) | (v << 24))
                   : v;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

nt_status nt_pcap_open(nt_pcap *p, const char *path)
{
    memset(p, 0, sizeof *p);
    p->f = fopen(path, "rb");
    if (p->f == NULL) {
        fprintf(stderr, "pcap: cannot open %s: %s\n", path, strerror(errno));
        return NT_ERR_TRUNCATED;
    }

    uint8_t hdr[PCAP_GLOBAL_LEN];
    if (fread(hdr, 1, sizeof hdr, p->f) != sizeof hdr) {
        fprintf(stderr, "pcap: %s: short global header\n", path);
        nt_pcap_close(p);
        return NT_ERR_TRUNCATED;
    }

    uint32_t magic = le32(hdr);
    uint32_t bswapped = (magic >> 24) | ((magic >> 8) & 0x0000ff00u) |
                        ((magic << 8) & 0x00ff0000u) | (magic << 24);
    if (magic == PCAP_MAGIC_US) {
        p->swapped = 0;
        p->nano = 0;
    } else if (magic == PCAP_MAGIC_NS) {
        p->swapped = 0;
        p->nano = 1;
    } else if (bswapped == PCAP_MAGIC_US) {
        p->swapped = 1;
        p->nano = 0;
    } else if (bswapped == PCAP_MAGIC_NS) {
        p->swapped = 1;
        p->nano = 1;
    } else {
        fprintf(stderr, "pcap: %s: bad magic 0x%08x\n", path, magic);
        nt_pcap_close(p);
        return NT_ERR_MALFORMED;
    }

    p->snaplen = sw32(p->swapped, le32(hdr + 16));
    p->linktype = sw32(p->swapped, le32(hdr + 20));
    if (p->linktype != PCAP_LINKTYPE_ETHERNET) {
        fprintf(stderr, "pcap: %s: link type %u is not Ethernet\n", path, p->linktype);
        nt_pcap_close(p);
        return NT_ERR_UNSUPPORTED;
    }
    return NT_OK;
}

int nt_pcap_next(nt_pcap *p, uint8_t *buf, size_t cap, size_t *caplen, size_t *origlen,
                 uint32_t *ts_sec, uint32_t *ts_frac)
{
    uint8_t rh[PCAP_RECORD_LEN];
    size_t got = fread(rh, 1, sizeof rh, p->f);
    if (got == 0) {
        return feof(p->f) ? 0 : -1;
    }
    if (got != sizeof rh) {
        if (ferror(p->f))
            fprintf(stderr, "pcap: read error on record header\n");
        else
            fprintf(stderr, "pcap: short record header\n");
        return -1;
    }

    uint32_t sec = sw32(p->swapped, le32(rh + 0));
    uint32_t frac = sw32(p->swapped, le32(rh + 4));
    uint32_t incl = sw32(p->swapped, le32(rh + 8));
    uint32_t orig = sw32(p->swapped, le32(rh + 12));

    if (incl > PCAP_CAP_MAX) {
        fprintf(stderr, "pcap: caplen %u exceeds cap max %u\n", incl, PCAP_CAP_MAX);
        return -1;
    }
    if (incl > cap) {
        fprintf(stderr, "pcap: caplen %u exceeds buffer (%zu)\n", incl, cap);
        return -1;
    }
    if (p->snaplen != 0 && incl > p->snaplen) {
        fprintf(stderr, "pcap: caplen %u exceeds snaplen %u\n", incl, p->snaplen);
        return -1;
    }

    long pos = ftell(p->f);
    if (pos < 0 || fseek(p->f, 0, SEEK_END) != 0) {
        fprintf(stderr, "pcap: seek failed\n");
        return -1;
    }
    long end = ftell(p->f);
    if (end < 0 || fseek(p->f, pos, SEEK_SET) != 0) {
        fprintf(stderr, "pcap: seek failed\n");
        return -1;
    }
    if ((uint64_t)(end - pos) < incl) {
        fprintf(stderr, "pcap: caplen %u exceeds %ld bytes left in file\n", incl, end - pos);
        return -1;
    }

    if (fread(buf, 1, incl, p->f) != incl) {
        fprintf(stderr, "pcap: truncated packet data\n");
        return -1;
    }
    *caplen = incl;
    *origlen = orig;
    *ts_sec = sec;
    *ts_frac = frac;
    return 1;
}

void nt_pcap_close(nt_pcap *p)
{
    if (p->f != NULL) {
        fclose(p->f);
        p->f = NULL;
    }
}

int nt_pcap_writer_open(nt_pcap_writer *w, const char *path, int nano, uint32_t snaplen)
{
    memset(w, 0, sizeof *w);
    w->nano = nano;
    w->f = fopen(path, "wb");
    if (w->f == NULL) {
        fprintf(stderr, "pcap: cannot create %s: %s\n", path, strerror(errno));
        return -1;
    }
    uint8_t hdr[PCAP_GLOBAL_LEN];
    memset(hdr, 0, sizeof hdr);
    hdr[0] = 0xd4; hdr[1] = 0xc3; hdr[2] = 0xb2; hdr[3] = 0xa1; /* magic, LE */
    if (nano) {
        hdr[0] = 0x4d; hdr[1] = 0x3c; hdr[2] = 0xb2; hdr[3] = 0xa1;
    }
    hdr[4] = PCAP_VERSION_MAJOR; hdr[5] = 0;
    hdr[6] = PCAP_VERSION_MINOR; hdr[7] = 0;
    /* thiszone (8..11) and sigfigs (12..15) stay zero */
    hdr[16] = (uint8_t)(snaplen >> 0); hdr[17] = (uint8_t)(snaplen >> 8);
    hdr[18] = (uint8_t)(snaplen >> 16); hdr[19] = (uint8_t)(snaplen >> 24);
    hdr[20] = (uint8_t)(PCAP_LINKTYPE_ETHERNET >> 0);
    hdr[21] = (uint8_t)(PCAP_LINKTYPE_ETHERNET >> 8);
    hdr[22] = (uint8_t)(PCAP_LINKTYPE_ETHERNET >> 16);
    hdr[23] = (uint8_t)(PCAP_LINKTYPE_ETHERNET >> 24);
    if (fwrite(hdr, 1, sizeof hdr, w->f) != sizeof hdr) {
        fprintf(stderr, "pcap: write global header failed\n");
        nt_pcap_writer_close(w);
        return -1;
    }
    return 0;
}

int nt_pcap_writer_write(nt_pcap_writer *w, const uint8_t *buf, size_t caplen, size_t origlen,
                         uint32_t ts_sec, uint32_t ts_frac)
{
    uint8_t rh[PCAP_RECORD_LEN];
    uint32_t fields[4] = { ts_sec, ts_frac, (uint32_t)caplen, (uint32_t)origlen };
    for (size_t i = 0; i < 4; i++) {
        rh[i * 4 + 0] = (uint8_t)(fields[i] >> 0);
        rh[i * 4 + 1] = (uint8_t)(fields[i] >> 8);
        rh[i * 4 + 2] = (uint8_t)(fields[i] >> 16);
        rh[i * 4 + 3] = (uint8_t)(fields[i] >> 24);
    }
    if (fwrite(rh, 1, sizeof rh, w->f) != sizeof rh ||
        fwrite(buf, 1, caplen, w->f) != caplen) {
        fprintf(stderr, "pcap: write record failed\n");
        return -1;
    }
    return 0;
}

void nt_pcap_writer_close(nt_pcap_writer *w)
{
    if (w->f != NULL) {
        fclose(w->f);
        w->f = NULL;
    }
}
