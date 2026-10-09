/* M1: packet builders, checked byte-for-byte against scapy golden vectors. */
#include "nt_test.h"
#include "nettk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOLDEN_DIR "fixtures/golden"

static const uint8_t H1[6]  = { 0x02, 0x00, 0x00, 0x00, 0x01, 0x02 };
static const uint8_t BC[6]  = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t ZERO6[6] = { 0, 0, 0, 0, 0, 0 };
static const uint8_t IPA[4] = { 10, 0, 1, 2 };
static const uint8_t IPB[4] = { 10, 0, 1, 1 };

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Read a one-line hex file into buf; returns length or -1. */
static long load_hex(const char *name, uint8_t *buf, size_t cap)
{
    char path[256];
    snprintf(path, sizeof path, "%s/%s", GOLDEN_DIR, name);
    FILE *f = fopen(path, "r");
    if (f == NULL) { perror(path); return -1; }
    char line[4096];
    size_t n = fread(line, 1, sizeof line - 1, f);
    fclose(f);
    line[n] = '\0';

    size_t len = 0;
    for (size_t i = 0; line[i] != '\0' && line[i] != '\n'; ) {
        int hi = hexval(line[i]);
        int lo = hexval(line[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        if (len >= cap) return -1;
        buf[len++] = (uint8_t)((hi << 4) | lo);
        i += 2;
    }
    return (long)len;
}

static void test_icmp_echo(void)
{
    uint8_t want[64], got[64];
    long wlen = load_hex("icmp_echo.hex", want, sizeof want);
    NT_CHECK(wlen == 20);

    const uint8_t data[] = "nettk-golden";
    size_t outlen = 0;
    NT_EQ_INT(nt_build_icmp_echo(got, sizeof got, &outlen, 8, 0x1234, 9, data, 12), NT_OK);
    NT_EQ_INT(outlen, (size_t)wlen);
    NT_EQ_MEM(got, want, outlen);

    nt_icmp ic;
    NT_EQ_INT(nt_icmp_decode(got, outlen, &ic), NT_OK);
    NT_EQ_INT(ic.type, 8);
    NT_EQ_INT(ic.code, 0);
    NT_EQ_INT(ic.csum_state, NT_CSUM_VALID);
    NT_EQ_INT(ic.rest.len, 16);
    NT_EQ_INT(ic.rest.data[0], 0x12); /* identifier high byte */
    NT_EQ_INT(ic.rest.data[1], 0x34);
    NT_EQ_INT(ic.rest.data[3], 0x09); /* sequence low byte */
}

static void test_arp_request(void)
{
    uint8_t want[64], got[64];
    long wlen = load_hex("arp_request.hex", want, sizeof want);
    NT_CHECK(wlen == 42);

    nt_arp_in in;
    memset(&in, 0, sizeof in);
    memcpy(in.eth_src, H1, 6);
    memcpy(in.eth_dst, BC, 6);
    in.op = 1;
    memcpy(in.sha, H1, 6);
    memcpy(in.spa, IPA, 4);
    memcpy(in.tpa, IPB, 4);

    size_t outlen = 0;
    NT_EQ_INT(nt_build_arp_frame(got, sizeof got, &outlen, &in), NT_OK);
    NT_EQ_INT(outlen, (size_t)wlen);
    NT_EQ_MEM(got, want, outlen);

    nt_eth_hdr eth;
    nt_vlan vlan;
    NT_EQ_INT(nt_eth_decode(got, outlen, &eth, &vlan), NT_OK);
    NT_EQ_INT(eth.ethertype, NT_ETHERTYPE_ARP);

    nt_arp arp;
    NT_EQ_INT(nt_arp_decode(got + 14, outlen - 14, &arp), NT_OK);
    NT_EQ_INT(arp.htype, 1);
    NT_EQ_INT(arp.ptype, NT_ETHERTYPE_IPV4);
    NT_EQ_INT(arp.op, 1);
    NT_EQ_MEM(arp.sha, H1, 6);
    NT_EQ_MEM(arp.spa, IPA, 4);
    NT_EQ_MEM(arp.tha, ZERO6, 6);
    NT_EQ_MEM(arp.tpa, IPB, 4);
}

static void test_icmp6_ns(void)
{
    uint8_t want[64], got[64];
    long wlen = load_hex("icmp6_ns.hex", want, sizeof want);
    NT_CHECK(wlen == 32);

    static const uint8_t src[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2 };
    static const uint8_t dst[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x00, 0x01, 0x01 };
    static const uint8_t tgt[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 };

    size_t outlen = 0;
    NT_EQ_INT(nt_build_icmp6_ns(got, sizeof got, &outlen, src, dst, tgt, H1), NT_OK);
    NT_EQ_INT(outlen, (size_t)wlen);
    NT_EQ_MEM(got, want, outlen);

    nt_pseudo ph;
    memset(&ph, 0, sizeof ph);
    ph.family = 6;
    memcpy(ph.src6, src, 16);
    memcpy(ph.dst6, dst, 16);
    nt_icmp ic;
    NT_EQ_INT(nt_icmp6_decode(got, outlen, &ph, &ic), NT_OK);
    NT_EQ_INT(ic.type, 135);
    NT_EQ_INT(ic.has_target, 1);
    NT_EQ_MEM(ic.target, tgt, 16);
    NT_EQ_INT(ic.csum_state, NT_CSUM_VALID);
}

static void test_icmp6_echo(void)
{
    uint8_t want[64], got[64];
    long wlen = load_hex("icmp6_echo.hex", want, sizeof want);
    NT_CHECK(wlen == 20);

    static const uint8_t src[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2 };
    static const uint8_t dst[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 };
    const uint8_t data[] = "nettk-golden";

    size_t outlen = 0;
    NT_EQ_INT(nt_build_icmp6_echo(got, sizeof got, &outlen, 128, 0x1234, 9,
                                  data, 12, src, dst), NT_OK);
    NT_EQ_INT(outlen, (size_t)wlen);
    NT_EQ_MEM(got, want, outlen);

    nt_pseudo ph;
    memset(&ph, 0, sizeof ph);
    ph.family = 6;
    memcpy(ph.src6, src, 16);
    memcpy(ph.dst6, dst, 16);
    nt_icmp ic;
    NT_EQ_INT(nt_icmp6_decode(got, outlen, &ph, &ic), NT_OK);
    NT_EQ_INT(ic.type, 128);
    NT_EQ_INT(ic.csum_state, NT_CSUM_VALID);

    NT_EQ_INT(nt_build_icmp6_echo(got, 19, &outlen, 128, 1, 1, data, 12, src, dst),
              NT_ERR_TRUNCATED);
    NT_EQ_INT(nt_build_icmp6_echo(got, 64, &outlen, 128, 1, 1, data, 12, NULL, dst),
              NT_ERR_MALFORMED);
}

static void test_ns_no_option(void)
{
    static const uint8_t src[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2 };
    static const uint8_t dst[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x00, 0x01, 0x01 };
    static const uint8_t tgt[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 };
    uint8_t got[64];
    size_t outlen = 0;
    NT_EQ_INT(nt_build_icmp6_ns(got, sizeof got, &outlen, src, dst, tgt, NULL), NT_OK);
    NT_EQ_INT(outlen, 24u);

    nt_pseudo ph;
    memset(&ph, 0, sizeof ph);
    ph.family = 6;
    memcpy(ph.src6, src, 16);
    memcpy(ph.dst6, dst, 16);
    nt_icmp ic;
    NT_EQ_INT(nt_icmp6_decode(got, outlen, &ph, &ic), NT_OK);
    NT_EQ_INT(ic.csum_state, NT_CSUM_VALID);
}

static void test_limits(void)
{
    const uint8_t data[4] = { 1, 2, 3, 4 };
    uint8_t small[16];
    uint8_t big[64];
    size_t outlen = 0;

    /* cap one byte short: refuse and leave the tail untouched */
    memset(small, 0xa5, sizeof small);
    NT_EQ_INT(nt_build_icmp_echo(small, 11, &outlen, 8, 1, 1, data, 4), NT_ERR_TRUNCATED);
    NT_EQ_INT(small[11], 0xa5);
    NT_EQ_INT(small[15], 0xa5);

    NT_EQ_INT(nt_build_icmp_echo(NULL, 16, &outlen, 8, 1, 1, data, 4), NT_ERR_MALFORMED);
    NT_EQ_INT(nt_build_icmp_echo(small, 16, NULL, 8, 1, 1, data, 4), NT_ERR_MALFORMED);
    NT_EQ_INT(nt_build_icmp_echo(small, 16, &outlen, 8, 1, 1, NULL, 4), NT_ERR_MALFORMED);

    nt_arp_in in;
    memset(&in, 0, sizeof in);
    NT_EQ_INT(nt_build_arp_frame(small, 41, &outlen, &in), NT_ERR_TRUNCATED);
    NT_EQ_INT(nt_build_arp_frame(small, 42, &outlen, NULL), NT_ERR_MALFORMED);

    static const uint8_t a[16] = { 1 };
    NT_EQ_INT(nt_build_icmp6_ns(small, 31, &outlen, a, a, a, H1), NT_ERR_TRUNCATED);
    NT_EQ_INT(nt_build_icmp6_ns(big, 64, &outlen, a, a, a, H1), NT_OK);
}

int main(void)
{
    test_icmp_echo();
    test_arp_request();
    test_icmp6_ns();
    test_icmp6_echo();
    test_ns_no_option();
    test_limits();
    NT_DONE();
}
