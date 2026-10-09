/* M6: classic-pcap reader/writer hardening. */
#include "nt_test.h"
#include "pcap.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAGIC_US 0xa1b2c3d4u
#define MAGIC_NS 0xa1b23c4du

static const uint8_t FRAME[14] = {
    0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x08, 0x00,
};

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static size_t mk_global_le(uint8_t *h, uint32_t magic, uint32_t snaplen, uint32_t linktype)
{
    put_le32(h, magic);
    h[4] = 2; h[5] = 0; h[6] = 4; h[7] = 0;
    put_le32(h + 8, 0); put_le32(h + 12, 0);
    put_le32(h + 16, snaplen);
    put_le32(h + 20, linktype);
    return 24;
}

static size_t mk_record_le(uint8_t *r, uint32_t sec, uint32_t frac, uint32_t incl, uint32_t orig)
{
    put_le32(r, sec); put_le32(r + 4, frac); put_le32(r + 8, incl); put_le32(r + 12, orig);
    return 16;
}

static int write_bytes(const char *path, const uint8_t *b, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) return -1;
    size_t w = fwrite(b, 1, n, f);
    fclose(f);
    return w == n ? 0 : -1;
}

static int temp_path(char *tmpl)
{
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

int main(void)
{
    /* Round trip: writer output reads back byte-for-byte, ts preserved. */
    char p_rt[] = "/tmp/nettk_pcap_rtXXXXXX";
    NT_EQ_INT(temp_path(p_rt), 0);
    nt_pcap_writer w;
    NT_EQ_INT(nt_pcap_writer_open(&w, p_rt, 0, 65535), 0);
    NT_EQ_INT(nt_pcap_writer_write(&w, FRAME, sizeof FRAME, sizeof FRAME, 1234, 5678), 0);
    nt_pcap_writer_close(&w);

    nt_pcap pc;
    NT_EQ_INT(nt_pcap_open(&pc, p_rt), NT_OK);
    NT_EQ_INT(pc.nano, 0);
    NT_EQ_INT(pc.snaplen, 65535);
    NT_EQ_INT(pc.linktype, 1);
    uint8_t buf[128];
    size_t caplen = 0, origlen = 0;
    uint32_t sec = 0, frac = 0;
    NT_EQ_INT(nt_pcap_next(&pc, buf, sizeof buf, &caplen, &origlen, &sec, &frac), 1);
    NT_EQ_INT(caplen, sizeof FRAME);
    NT_EQ_INT(origlen, sizeof FRAME);
    NT_EQ_INT(sec, 1234);
    NT_EQ_INT(frac, 5678);
    NT_EQ_MEM(buf, FRAME, sizeof FRAME);
    NT_EQ_INT(nt_pcap_next(&pc, buf, sizeof buf, &caplen, &origlen, &sec, &frac), 0);
    nt_pcap_close(&pc);
    unlink(p_rt);

    /* Byte-swapped (big-endian) file: fields converted, magics recognized. */
    char p_be[] = "/tmp/nettk_pcap_beXXXXXX";
    NT_EQ_INT(temp_path(p_be), 0);
    uint8_t be[24 + 16 + 14];
    put_be32(be, MAGIC_US);
    be[4] = 0; be[5] = 2; be[6] = 0; be[7] = 4;
    put_be32(be + 8, 0); put_be32(be + 12, 0);
    put_be32(be + 16, 65535); put_be32(be + 20, 1);
    put_be32(be + 24, 1); put_be32(be + 28, 2);
    put_be32(be + 32, 14); put_be32(be + 36, 14);
    for (size_t i = 0; i < 14; i++) be[40 + i] = FRAME[i];
    NT_EQ_INT(write_bytes(p_be, be, sizeof be), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_be), NT_OK);
    NT_CHECK(pc.swapped == 1);
    NT_EQ_INT(pc.nano, 0);
    NT_EQ_INT(nt_pcap_next(&pc, buf, sizeof buf, &caplen, &origlen, &sec, &frac), 1);
    NT_EQ_INT(caplen, 14);
    NT_EQ_INT(sec, 1);
    NT_EQ_INT(frac, 2);
    NT_EQ_MEM(buf, FRAME, 14);
    nt_pcap_close(&pc);
    unlink(p_be);

    /* Nanosecond magic. */
    char p_ns[] = "/tmp/nettk_pcap_nsXXXXXX";
    NT_EQ_INT(temp_path(p_ns), 0);
    uint8_t ns[24 + 16 + 14];
    mk_global_le(ns, MAGIC_NS, 65535, 1);
    mk_record_le(ns + 24, 7, 999, 14, 14);
    for (size_t i = 0; i < 14; i++) ns[40 + i] = FRAME[i];
    NT_EQ_INT(write_bytes(p_ns, ns, sizeof ns), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_ns), NT_OK);
    NT_EQ_INT(pc.nano, 1);
    NT_EQ_INT(nt_pcap_next(&pc, buf, sizeof buf, &caplen, &origlen, &sec, &frac), 1);
    NT_EQ_INT(frac, 999);
    nt_pcap_close(&pc);
    unlink(p_ns);

    /* Bad magic -> MALFORMED. */
    char p_bad[] = "/tmp/nettk_pcap_badXXXXXX";
    NT_EQ_INT(temp_path(p_bad), 0);
    uint8_t bad[24];
    mk_global_le(bad, 0xdeadbeefu, 65535, 1);
    NT_EQ_INT(write_bytes(p_bad, bad, sizeof bad), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_bad), NT_ERR_MALFORMED);
    unlink(p_bad);

    /* Short global header -> TRUNCATED. */
    char p_short[] = "/tmp/nettk_pcap_shortXXXXXX";
    NT_EQ_INT(temp_path(p_short), 0);
    uint8_t sh[10] = { 0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0 };
    NT_EQ_INT(write_bytes(p_short, sh, sizeof sh), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_short), NT_ERR_TRUNCATED);
    unlink(p_short);

    /* Non-Ethernet link type -> UNSUPPORTED. */
    char p_lt[] = "/tmp/nettk_pcap_ltXXXXXX";
    NT_EQ_INT(temp_path(p_lt), 0);
    uint8_t lt[24];
    mk_global_le(lt, MAGIC_US, 65535, 101); /* DLT_RAW */
    NT_EQ_INT(write_bytes(p_lt, lt, sizeof lt), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_lt), NT_ERR_UNSUPPORTED);
    unlink(p_lt);

    /* caplen > snaplen -> read error. */
    char p_snap[] = "/tmp/nettk_pcap_snapXXXXXX";
    NT_EQ_INT(temp_path(p_snap), 0);
    uint8_t snap[24 + 16 + 14];
    mk_global_le(snap, MAGIC_US, 10, 1);
    mk_record_le(snap + 24, 0, 0, 14, 14);
    for (size_t i = 0; i < 14; i++) snap[40 + i] = FRAME[i];
    NT_EQ_INT(write_bytes(p_snap, snap, sizeof snap), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_snap), NT_OK);
    NT_EQ_INT(nt_pcap_next(&pc, buf, sizeof buf, &caplen, &origlen, &sec, &frac), -1);
    nt_pcap_close(&pc);
    unlink(p_snap);

    /* caplen beyond end of file -> read error. */
    char p_eof[] = "/tmp/nettk_pcap_eofXXXXXX";
    NT_EQ_INT(temp_path(p_eof), 0);
    uint8_t eof[24 + 16 + 14];
    mk_global_le(eof, MAGIC_US, 65535, 1);
    mk_record_le(eof + 24, 0, 0, 20, 20);
    for (size_t i = 0; i < 14; i++) eof[40 + i] = FRAME[i];
    NT_EQ_INT(write_bytes(p_eof, eof, sizeof eof), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_eof), NT_OK);
    NT_EQ_INT(nt_pcap_next(&pc, buf, sizeof buf, &caplen, &origlen, &sec, &frac), -1);
    nt_pcap_close(&pc);
    unlink(p_eof);

    /* caplen larger than the caller's buffer -> read error. */
    char p_cap[] = "/tmp/nettk_pcap_capXXXXXX";
    NT_EQ_INT(temp_path(p_cap), 0);
    uint8_t cap[24 + 16 + 14];
    mk_global_le(cap, MAGIC_US, 65535, 1);
    mk_record_le(cap + 24, 0, 0, 14, 14);
    for (size_t i = 0; i < 14; i++) cap[40 + i] = FRAME[i];
    NT_EQ_INT(write_bytes(p_cap, cap, sizeof cap), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_cap), NT_OK);
    NT_EQ_INT(nt_pcap_next(&pc, buf, 8, &caplen, &origlen, &sec, &frac), -1);
    nt_pcap_close(&pc);
    unlink(p_cap);

    /* Short record header -> read error. */
    char p_rh[] = "/tmp/nettk_pcap_rhXXXXXX";
    NT_EQ_INT(temp_path(p_rh), 0);
    uint8_t rh[24 + 8];
    mk_global_le(rh, MAGIC_US, 65535, 1);
    NT_EQ_INT(write_bytes(p_rh, rh, sizeof rh), 0);
    NT_EQ_INT(nt_pcap_open(&pc, p_rh), NT_OK);
    NT_EQ_INT(nt_pcap_next(&pc, buf, sizeof buf, &caplen, &origlen, &sec, &frac), -1);
    nt_pcap_close(&pc);
    unlink(p_rh);

    NT_DONE();
}
