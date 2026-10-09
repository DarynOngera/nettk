/* M2: echo-reply matcher: id/seq/source/payload/checksum. */
#include "nt_test.h"
#include "nettk.h"

#include <string.h>

/* rest buffer layout: id(2) seq(2) payload(n) */
static void mk_icmp(nt_icmp *ic, uint8_t *rest, uint8_t type, uint16_t id, uint16_t seq,
                    const char *payload, nt_csum_state cs)
{
    memset(ic, 0, sizeof *ic);
    rest[0] = (uint8_t)(id >> 8); rest[1] = (uint8_t)id;
    rest[2] = (uint8_t)(seq >> 8); rest[3] = (uint8_t)seq;
    size_t plen = payload ? strlen(payload) : 0;
    if (plen) memcpy(rest + 4, payload, plen);
    ic->type = type;
    ic->rest.data = rest;
    ic->rest.len = 4 + plen;
    ic->csum_state = cs;
}

static void test_quote(void)
{
    uint8_t err[64];
    memset(err, 0, sizeof err);
    err[0] = 3; /* destination unreachable */
    err[1] = 3; /* port unreachable */
    size_t q = 8;
    err[q + 0] = 0x45;          /* IPv4, IHL 5 */
    err[q + 3] = 40;            /* original totlen (larger than the quote) */
    err[q + 9] = 1;             /* ICMP */
    err[q + 12] = 10; err[q + 14] = 1; err[q + 15] = 1; /* src 10.0.1.1 */
    err[q + 16] = 10; err[q + 18] = 1; err[q + 19] = 2; /* dst 10.0.1.2 */
    err[q + 20] = 8;            /* quoted ICMP type = echo request */
    err[q + 24] = 0x12; err[q + 25] = 0x34; /* id */
    err[q + 27] = 9;                        /* seq */

    nt_icmp ic;
    NT_EQ_INT(nt_icmp_decode(err, 36, &ic), NT_OK);
    nt_quote tq;
    NT_EQ_INT(nt_icmp_quote_parse(&ic, &tq), NT_OK);
    NT_EQ_INT(tq.proto, NT_IPPROTO_ICMP);
    NT_EQ_INT(tq.id, 0x1234);
    NT_EQ_INT(tq.seq, 9);
    NT_EQ_INT(tq.src, 0x0a000101u);
    NT_EQ_INT(tq.dst, 0x0a000102u);

    /* UDP probe inside the quote: ports are read instead of id/seq */
    err[q + 9] = 17;
    err[q + 20] = 0xc3; err[q + 21] = 0x50; /* sport 50000 */
    err[q + 22] = 0x82; err[q + 23] = 0x1c; /* dport 33308 */
    NT_EQ_INT(nt_icmp_decode(err, 36, &ic), NT_OK);
    NT_EQ_INT(nt_icmp_quote_parse(&ic, &tq), NT_OK);
    NT_EQ_INT(tq.proto, NT_IPPROTO_UDP);
    NT_EQ_INT(tq.sport, 50000);
    NT_EQ_INT(tq.dport, 33308);

    /* no room for the 8 L4 quote bytes */
    NT_EQ_INT(nt_icmp_decode(err, 20, &ic), NT_OK);
    NT_EQ_INT(nt_icmp_quote_parse(&ic, &tq), NT_ERR_TRUNCATED);
}

int main(void)
{
    uint8_t rest[64];
    nt_icmp ic;    nt_echo_probe p = { .id = 0x1234, .seq = 7, .src = 0x0a000202u,
                        .data = (const uint8_t *)"hello", .datalen = 5 };

    mk_icmp(&ic, rest, 0, 0x1234, 7, "hello", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000202u, &p), NT_MATCH);

    /* request type, not a reply */
    mk_icmp(&ic, rest, 8, 0x1234, 7, "hello", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000202u, &p), NT_NO_MATCH);

    /* bad checksum is untrusted */
    mk_icmp(&ic, rest, 0, 0x1234, 7, "hello", NT_CSUM_INVALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000202u, &p), NT_INVALID);

    /* wrong source */
    mk_icmp(&ic, rest, 0, 0x1234, 7, "hello", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000299u, &p), NT_NO_MATCH);

    /* wrong id and seq */
    mk_icmp(&ic, rest, 0, 0x9999, 7, "hello", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000202u, &p), NT_NO_MATCH);
    mk_icmp(&ic, rest, 0, 0x1234, 8, "hello", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000202u, &p), NT_NO_MATCH);

    /* payload differs (reflection attack / stale reply) */
    mk_icmp(&ic, rest, 0, 0x1234, 7, "HELLO", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000202u, &p), NT_NO_MATCH);
    mk_icmp(&ic, rest, 0, 0x1234, 7, "hell", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000202u, &p), NT_NO_MATCH);

    /* no expected payload: length/bytes are not compared */
    nt_echo_probe q = { .id = 0x1234, .seq = 7, .src = 0, .data = NULL, .datalen = 0 };
    mk_icmp(&ic, rest, 0, 0x1234, 7, "anything", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x11223344u, &q), NT_MATCH);

    /* truncated rest cannot carry id/seq */
    mk_icmp(&ic, rest, 0, 0x1234, 7, "", NT_CSUM_VALID);
    ic.rest.len = 3;
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0x0a000202u, &p), NT_INVALID);

    /* NULL arguments */
    NT_EQ_INT(nt_match_icmp_echo_reply(NULL, 0, &p), NT_INVALID);
    NT_EQ_INT(nt_match_icmp_echo_reply(&ic, 0, NULL), NT_INVALID);

    /* ICMPv6 echo reply (type 129) */
    uint8_t src6[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2 };
    mk_icmp(&ic, rest, 129, 0x1234, 7, "hello", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp6_echo_reply(&ic, src6, &p), NT_MATCH);
    mk_icmp(&ic, rest, 128, 0x1234, 7, "hello", NT_CSUM_VALID);
    NT_EQ_INT(nt_match_icmp6_echo_reply(&ic, src6, &p), NT_NO_MATCH);
    NT_EQ_INT(nt_match_icmp6_echo_reply(&ic, NULL, &p), NT_INVALID);

    test_quote();

    NT_DONE();
}
