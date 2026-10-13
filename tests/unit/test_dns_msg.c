/* DNS message codec (M11): header, question, RR/RDATA, OPT, matcher,
 * classifier. Messages are built by hand here; the same shapes are
 * cross-checked against tshark on fixtures/dns-*.pcap by scripts/tshark-dns.sh
 * and tested/decoded by test_parse_fixture below. */
#include "nt_test.h"
#include "dns.h"

#include <string.h>

static size_t put16(uint8_t *b, size_t o, uint16_t v)
{
    b[o] = (uint8_t)(v >> 8);
    b[o + 1] = (uint8_t)v;
    return o + 2;
}

static size_t put32(uint8_t *b, size_t o, uint32_t v)
{
    b[o] = (uint8_t)(v >> 24);
    b[o + 1] = (uint8_t)(v >> 16);
    b[o + 2] = (uint8_t)(v >> 8);
    b[o + 3] = (uint8_t)v;
    return o + 4;
}

static size_t name_wire(uint8_t *b, size_t o, const char *dotted)
{
    const char *p = dotted;
    while (*p) {
        const char *d = strchr(p, '.');
        size_t l = d ? (size_t)(d - p) : strlen(p);
        b[o++] = (uint8_t)l;
        memcpy(b + o, p, l);
        o += l;
        if (!d) break;
        p = d + 1;
    }
    b[o++] = 0;
    return o;
}

static size_t hdr(uint8_t *b, uint16_t id, uint16_t flags,
                  uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar)
{
    size_t o = 0;
    o = put16(b, o, id);
    o = put16(b, o, flags);
    o = put16(b, o, qd);
    o = put16(b, o, an);
    o = put16(b, o, ns);
    o = put16(b, o, ar);
    return o;
}

static size_t question(uint8_t *b, size_t o, const char *name, uint16_t type)
{
    o = name_wire(b, o, name);
    o = put16(b, o, type);
    o = put16(b, o, NT_DNS_CLASS_IN);
    return o;
}

static size_t rr(uint8_t *b, size_t o, const char *owner, uint16_t type,
                 uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
    o = name_wire(b, o, owner);
    o = put16(b, o, type);
    o = put16(b, o, NT_DNS_CLASS_IN);
    o = put32(b, o, ttl);
    o = put16(b, o, rdlen);
    if (rdlen) memcpy(b + o, rdata, rdlen);
    return o + rdlen;
}

static void test_decode_query(void)
{
    uint8_t b[64];
    size_t o = hdr(b, 0x1234, NT_DNS_FLAG_RD, 1, 0, 0, 0);
    o = question(b, o, "www.example.test", NT_DNS_TYPE_A);

    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_OK);
    NT_EQ_INT(m.id, 0x1234);
    NT_EQ_INT(m.qr, 0);
    NT_EQ_INT(m.opcode, 0);
    NT_EQ_INT(m.rd, 1);
    NT_EQ_INT(m.qd, 1);
    NT_EQ_INT(m.an, 0);
    NT_CHECK(strcmp(m.q[0].qname, "www.example.test") == 0);
    NT_EQ_INT(m.q[0].qtype, NT_DNS_TYPE_A);
    NT_EQ_INT(m.q[0].qname_off, 12);
    NT_EQ_INT(m.full_rcode, 0);
    NT_EQ_INT(m.has_opt, 0);
}

static void test_decode_answer_compressed(void)
{
    /* query + answer whose owner is a pointer to the qname at offset 12 */
    uint8_t b[128];
    size_t o = hdr(b, 0xBEEF, 0x8180, 1, 1, 0, 0);
    o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
    b[o++] = 0xc0; b[o++] = 0x0c;                     /* owner -> 12 */
    o = put16(b, o, NT_DNS_TYPE_A);
    o = put16(b, o, NT_DNS_CLASS_IN);
    o = put32(b, o, 300);
    o = put16(b, o, 4);
    b[o++] = 10; b[o++] = 0; b[o++] = 5; b[o++] = 200;

    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_OK);
    NT_EQ_INT(m.an, 1);
    NT_EQ_INT(m.an_rr[0].type, NT_DNS_TYPE_A);
    NT_EQ_INT(m.an_rr[0].rdlen, 4);
    char out[64];
    NT_EQ_INT(nt_dns_rdata_str(&m, &m.an_rr[0], out, sizeof out), NT_OK);
    NT_CHECK(strcmp(out, "10.0.5.200") == 0);

    char own[128];
    size_t end;
    NT_EQ_INT(nt_dns_name_parse(m.buf, m.len, m.an_rr[0].name_off, own, sizeof own, &end), NT_OK);
    NT_CHECK(strcmp(own, "www.example.test") == 0);
}

static void test_decode_opt(void)
{
    uint8_t b[80];
    size_t o = hdr(b, 1, NT_DNS_FLAG_RD, 1, 0, 0, 1);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);
    b[o++] = 0;                                       /* root owner */
    o = put16(b, o, NT_DNS_TYPE_OPT);
    o = put16(b, o, 4096);
    o = put32(b, o, 0x01010000u);                     /* ext-rcode 1, ver 1 */
    o = put16(b, o, 0);

    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_OK);
    NT_EQ_INT(m.has_opt, 1);
    NT_EQ_INT(m.opt_udpsize, 4096);
    NT_EQ_INT(m.opt_rcode, 1);
    NT_EQ_INT(m.opt_version, 1);
    NT_EQ_INT(m.full_rcode, (1u << 4) | 0u);          /* header rcode 0 */
    uint16_t sz, fl;
    uint8_t ver;
    unsigned frc;
    int dobit;
    NT_EQ_INT(nt_dns_opt(&m, &sz, &ver, &fl, &frc, &dobit), NT_OK);
    NT_EQ_INT(sz, 4096);
    NT_EQ_INT(ver, 1);
    NT_EQ_INT(fl, 0);
    NT_EQ_INT(frc, 16);
    NT_EQ_INT(dobit, 0);

    char out[64];
    NT_EQ_INT(nt_dns_rdata_str(&m, &m.ar_rr[0], out, sizeof out), NT_OK);
    NT_CHECK(strcmp(out, "size=4096 rcode=1 version=1 do=0") == 0);
}

static void test_opt_floor_and_do(void)
{
    /* CLASS below 512 counts as 512; DO is bit 15 of the TTL flags */
    uint8_t b[64];
    size_t o = hdr(b, 2, 0, 1, 0, 0, 1);
    o = question(b, o, "a.test", NT_DNS_TYPE_AAAA);
    b[o++] = 0;
    o = put16(b, o, NT_DNS_TYPE_OPT);
    o = put16(b, o, 300);
    o = put32(b, o, 0x00008000u);                     /* DO set */
    o = put16(b, o, 0);
    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_OK);
    NT_EQ_INT(m.opt_udpsize, NT_DNS_EDNS_MIN);
    int dobit = -1;
    NT_EQ_INT(nt_dns_opt(&m, NULL, NULL, NULL, NULL, &dobit), NT_OK);
    NT_EQ_INT(dobit, 1);
}

static void test_decode_errors(void)
{
    uint8_t b[256];
    nt_dns_msg m;
    size_t o;

    NT_EQ_INT(nt_dns_msg_decode(NULL, 0, &m), NT_ERR_MALFORMED);
    NT_EQ_INT(nt_dns_msg_decode(b, 11, &m), NT_ERR_TRUNCATED);

    /* two questions -> UNSUPPORTED */
    o = hdr(b, 3, 0, 2, 0, 0, 0);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);
    o = question(b, o, "b.test", NT_DNS_TYPE_A);
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_UNSUPPORTED);

    /* counts claiming far more RRs than the buffer -> UNSUPPORTED */
    o = hdr(b, 3, 0, 1, 0xffff, 0, 0);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_UNSUPPORTED);

    /* plausible count that cannot fit the remaining length -> TRUNCATED */
    o = hdr(b, 3, 0, 1, 20, 0, 0);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_TRUNCATED);

    /* A with RDLENGTH 3 -> MALFORMED */
    o = hdr(b, 4, 0x8180, 1, 1, 0, 0);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);
    { static const uint8_t bad[3] = { 1, 2, 3 };
      o = rr(b, o, "a.test", NT_DNS_TYPE_A, 60, bad, 3); }
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_MALFORMED);

    /* self-pointing compression pointer -> MALFORMED */
    o = hdr(b, 5, 0, 1, 0, 0, 0);
    b[o++] = 0xc0; b[o++] = 0x0c;
    o = put16(b, o, NT_DNS_TYPE_A);
    o = put16(b, o, NT_DNS_CLASS_IN);
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_MALFORMED);

    /* NS whose rdata name overruns RDLENGTH -> MALFORMED */
    o = hdr(b, 6, 0x8180, 1, 0, 1, 0);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);
    { static const uint8_t ns[6] = { 3, 'n', 's', 'x', 0, 0 };
      o = rr(b, o, "test", NT_DNS_TYPE_NS, 60, ns, 6); }
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_MALFORMED);

    /* TXT char-string overruns RDATA -> MALFORMED */
    o = hdr(b, 7, 0x8180, 1, 1, 0, 0);
    o = question(b, o, "a.test", NT_DNS_TYPE_TXT);
    { static const uint8_t tx[4] = { 5, 'a', 'b', 'c' };
      o = rr(b, o, "a.test", NT_DNS_TYPE_TXT, 60, tx, 4); }
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_MALFORMED);
}

static void test_decode_second_opt_and_owner(void)
{
    uint8_t b[128];
    nt_dns_msg m;
    size_t o = hdr(b, 8, 0, 1, 0, 0, 2);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);
    for (int i = 0; i < 2; i++) {
        b[o++] = 0;
        o = put16(b, o, NT_DNS_TYPE_OPT);
        o = put16(b, o, 512);
        o = put32(b, o, 0);
        o = put16(b, o, 0);
    }
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_MALFORMED); /* two OPT */

    o = hdr(b, 9, 0, 1, 0, 0, 1);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);
    o = name_wire(b, o, "not.root");                  /* OPT owner must be root */
    o = put16(b, o, NT_DNS_TYPE_OPT);
    o = put16(b, o, 512);
    o = put32(b, o, 0);
    o = put16(b, o, 0);
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_ERR_MALFORMED);
}

static void test_match(void)
{
    uint8_t b[64];
    size_t o = hdr(b, 0x4242, 0x8180, 1, 0, 0, 0);
    o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_OK);

    NT_EQ_INT(nt_dns_match(&m, 0x4242, "WWW.example.TEST", NT_DNS_TYPE_A,
                           NT_DNS_CLASS_IN, 0x0a000501u, 53, 0x0a000501u, 53),
              NT_MATCH);
    NT_EQ_INT(nt_dns_match(&m, 0x4243, "www.example.test", NT_DNS_TYPE_A,
                           NT_DNS_CLASS_IN, 0x0a000501u, 53, 0x0a000501u, 53),
              NT_NO_MATCH);
    NT_EQ_INT(nt_dns_match(&m, 0x4242, "www.example.test", NT_DNS_TYPE_A,
                           NT_DNS_CLASS_IN, 0x0a000501u, 53, 0x0a000566u, 53),
              NT_NO_MATCH);
    NT_EQ_INT(nt_dns_match(&m, 0x4242, "www.example.test", NT_DNS_TYPE_AAAA,
                           NT_DNS_CLASS_IN, 0x0a000501u, 53, 0x0a000501u, 53),
              NT_NO_MATCH);
    NT_EQ_INT(nt_dns_match(&m, 0x4242, NULL, NT_DNS_TYPE_A,
                           NT_DNS_CLASS_IN, 0, 53, 0, 53), NT_INVALID);

    /* a query (QR=0) presented as a response: well-formed, not ours */
    uint8_t q[64];
    size_t qo = hdr(q, 0x4242, NT_DNS_FLAG_RD, 1, 0, 0, 0);
    qo = question(q, qo, "www.example.test", NT_DNS_TYPE_A);
    nt_dns_msg qm;
    NT_EQ_INT(nt_dns_msg_decode(q, qo, &qm), NT_OK);
    NT_EQ_INT(nt_dns_match(&qm, 0x4242, "www.example.test", NT_DNS_TYPE_A,
                           NT_DNS_CLASS_IN, 0x0a000501u, 53, 0x0a000501u, 53),
              NT_NO_MATCH);
}

/* Build a message with a question and one answer, decode and classify. */
static void classify_case(const char *qname, uint16_t qtype, const char *zone,
                          const uint8_t *msg, size_t len, nt_dns_class want,
                          unsigned want_chain)
{
    nt_dns_msg m;
    nt_dns_state st = { 0 };
    NT_EQ_INT(nt_dns_msg_decode(msg, len, &m), NT_OK);
    nt_dns_qd q;
    memset(&q, 0, sizeof q);
    snprintf(q.qname, sizeof q.qname, "%s", qname);
    q.qtype = qtype;
    q.qclass = NT_DNS_CLASS_IN;
    NT_EQ_INT(nt_dns_classify(&m, &q, zone, &st), want);
    if (want_chain != (unsigned)-1) NT_EQ_INT(st.chain, want_chain);
}

static void test_classify(void)
{
    uint8_t b[512];
    size_t o;
    static const uint8_t a4[4] = { 10, 0, 5, 200 };

    /* ANSWER */
    o = hdr(b, 1, 0x8580, 1, 1, 0, 0);
    o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
    o = rr(b, o, "www.example.test", NT_DNS_TYPE_A, 60, a4, 4);
    classify_case("www.example.test", NT_DNS_TYPE_A, "example.test", b, o,
                  NT_DNS_C_ANSWER, 0);

    /* CNAME chain a -> b -> A */
    {
        uint8_t rd[64];
        size_t rl = name_wire(rd, 0, "b.example.test");
        o = hdr(b, 2, 0x8580, 1, 2, 0, 0);
        o = question(b, o, "a.example.test", NT_DNS_TYPE_A);
        o = rr(b, o, "a.example.test", NT_DNS_TYPE_CNAME, 60, rd, (uint16_t)rl);
        o = rr(b, o, "b.example.test", NT_DNS_TYPE_A, 60, a4, 4);
        classify_case("a.example.test", NT_DNS_TYPE_A, "example.test", b, o,
                      NT_DNS_C_ANSWER, 1);

        /* CNAME with no final record -> CNAME */
        o = hdr(b, 3, 0x8580, 1, 1, 0, 0);
        o = question(b, o, "a.example.test", NT_DNS_TYPE_A);
        o = rr(b, o, "a.example.test", NT_DNS_TYPE_CNAME, 60, rd, (uint16_t)rl);
        classify_case("a.example.test", NT_DNS_TYPE_A, "example.test", b, o,
                      NT_DNS_C_CNAME, 1);

        /* self-CNAME -> BOGUS (loop) */
        uint8_t self[64];
        size_t sl = name_wire(self, 0, "a.example.test");
        o = hdr(b, 4, 0x8580, 1, 1, 0, 0);
        o = question(b, o, "a.example.test", NT_DNS_TYPE_A);
        o = rr(b, o, "a.example.test", NT_DNS_TYPE_CNAME, 60, self, (uint16_t)sl);
        classify_case("a.example.test", NT_DNS_TYPE_A, "example.test", b, o,
                      NT_DNS_C_BOGUS, (unsigned)-1);
    }

    /* answer for another name -> BOGUS */
    o = hdr(b, 5, 0x8580, 1, 1, 0, 0);
    o = question(b, o, "a.example.test", NT_DNS_TYPE_A);
    o = rr(b, o, "z.example.test", NT_DNS_TYPE_A, 60, a4, 4);
    classify_case("a.example.test", NT_DNS_TYPE_A, "example.test", b, o,
                  NT_DNS_C_BOGUS, (unsigned)-1);

    /* NODATA: NOERROR, no answers, SOA in authority */
    {
        uint8_t soa[64];
        size_t sl = name_wire(soa, 0, "ns.example.test");
        sl = name_wire(soa, sl, "hostmaster.example.test");
        memset(soa + sl, 0, 20);
        sl += 20;
        o = hdr(b, 6, 0x8580, 1, 0, 1, 0);
        o = question(b, o, "host.example.test", NT_DNS_TYPE_MX);
        o = rr(b, o, "example.test", NT_DNS_TYPE_SOA, 60, soa, (uint16_t)sl);
        classify_case("host.example.test", NT_DNS_TYPE_MX, "example.test", b, o,
                      NT_DNS_C_NODATA, 0);
    }

    /* NXDOMAIN */
    o = hdr(b, 7, 0x8583, 1, 0, 1, 0);
    o = question(b, o, "nope.example.test", NT_DNS_TYPE_A);
    {
        uint8_t soa[64];
        size_t sl = name_wire(soa, 0, "ns.example.test");
        sl = name_wire(soa, sl, "hostmaster.example.test");
        memset(soa + sl, 0, 20); sl += 20;
        o = rr(b, o, "example.test", NT_DNS_TYPE_SOA, 60, soa, (uint16_t)sl);
    }
    classify_case("nope.example.test", NT_DNS_TYPE_A, "example.test", b, o,
                  NT_DNS_C_NXDOMAIN, 0);

    /* NXDOMAIN carrying answers -> BOGUS */
    o = hdr(b, 8, 0x8583, 1, 1, 0, 0);
    o = question(b, o, "nope.example.test", NT_DNS_TYPE_A);
    o = rr(b, o, "nope.example.test", NT_DNS_TYPE_A, 60, a4, 4);
    classify_case("nope.example.test", NT_DNS_TYPE_A, "example.test", b, o,
                  NT_DNS_C_BOGUS, (unsigned)-1);

    /* REFERRAL from the root to test. with glue */
    {
        uint8_t nsrd[64];
        size_t nl = name_wire(nsrd, 0, "ns.test");
        o = hdr(b, 9, 0x0000, 1, 0, 1, 0);
        o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
        o = rr(b, o, "test", NT_DNS_TYPE_NS, 60, nsrd, (uint16_t)nl);
        classify_case("www.example.test", NT_DNS_TYPE_A, "", b, o,
                      NT_DNS_C_REFERRAL, 0);

        /* referral back to the zone we just asked -> BOGUS */
        o = hdr(b, 10, 0x0000, 1, 0, 1, 0);
        o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
        o = rr(b, o, "test", NT_DNS_TYPE_NS, 60, nsrd, (uint16_t)nl);
        classify_case("www.example.test", NT_DNS_TYPE_A, "test", b, o,
                      NT_DNS_C_BOGUS, (unsigned)-1);

        /* referral to an unrelated zone -> BOGUS */
        o = hdr(b, 11, 0x0000, 1, 0, 1, 0);
        o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
        o = rr(b, o, "other", NT_DNS_TYPE_NS, 60, nsrd, (uint16_t)nl);
        classify_case("www.example.test", NT_DNS_TYPE_A, "", b, o,
                      NT_DNS_C_BOGUS, (unsigned)-1);
    }

    /* TRUNCATED */
    o = hdr(b, 12, 0x8380, 1, 0, 0, 0);
    o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
    classify_case("www.example.test", NT_DNS_TYPE_A, "", b, o,
                  NT_DNS_C_TRUNCATED, 0);

    /* SERVFAIL / REFUSED */
    o = hdr(b, 13, 0x8182, 1, 0, 0, 0);
    o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
    classify_case("www.example.test", NT_DNS_TYPE_A, "", b, o, NT_DNS_C_SERVFAIL, 0);
    o = hdr(b, 14, 0x8185, 1, 0, 0, 0);
    o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
    classify_case("www.example.test", NT_DNS_TYPE_A, "", b, o, NT_DNS_C_REFUSED, 0);
}

static void test_glue(void)
{
    uint8_t b[256];
    static const uint8_t a4[4] = { 10, 0, 5, 2 };
    size_t o = hdr(b, 1, 0, 1, 0, 1, 1);
    o = question(b, o, "www.example.test", NT_DNS_TYPE_A);
    { uint8_t nsrd[64]; size_t nl = name_wire(nsrd, 0, "ns.test");
      o = rr(b, o, "test", NT_DNS_TYPE_NS, 60, nsrd, (uint16_t)nl); }
    o = rr(b, o, "ns.test", NT_DNS_TYPE_A, 60, a4, 4);
    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_OK);
    uint32_t ip = 0;
    NT_EQ_INT(nt_dns_glue(&m, "ns.test", &ip), 1);
    NT_EQ_INT(ip, 0x0a000502u);
    NT_EQ_INT(nt_dns_glue(&m, "absent.test", &ip), 0);
}

static void test_build_query(void)
{
    uint8_t b[128];
    size_t n = 0;
    nt_dns_query q;
    memset(&q, 0, sizeof q);
    q.id = 0xABCD;
    q.qname = "www.example.test";
    q.qtype = NT_DNS_TYPE_A;
    q.qclass = NT_DNS_CLASS_IN;
    q.rd = 1;
    q.edns = 1;
    q.edns_size = 4096;

    NT_EQ_INT(nt_dns_msg_build_query(&q, b, sizeof b, &n), NT_OK);
    NT_EQ_INT(n, 12 + 18 + 4 + 11);
    NT_EQ_INT(rd16be(b, 0), 0xABCD);
    NT_EQ_INT(rd16be(b, 2), NT_DNS_FLAG_RD);
    NT_EQ_INT(rd16be(b, 4), 1);
    NT_EQ_INT(rd16be(b, 10), 1);
    NT_EQ_INT(b[12], 3);                              /* first label length */
    NT_EQ_INT(rd16be(b, 12 + 18), NT_DNS_TYPE_A);
    NT_EQ_INT(rd16be(b, 12 + 18 + 2), NT_DNS_CLASS_IN);
    NT_EQ_INT(rd16be(b, 35), NT_DNS_TYPE_OPT);
    NT_EQ_INT(rd16be(b, 37), 4096);
    NT_EQ_INT(rd16be(b, 43), 0);                      /* rdlen 0 */

    /* round-trips through decode */
    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(b, n, &m), NT_OK);
    NT_CHECK(strcmp(m.q[0].qname, "www.example.test") == 0);
    NT_EQ_INT(m.has_opt, 1);
    NT_EQ_INT(m.opt_udpsize, 4096);

    /* advertised size below 512 is floored; zero means the default */
    q.edns_size = 300;
    NT_EQ_INT(nt_dns_msg_build_query(&q, b, sizeof b, &n), NT_OK);
    NT_EQ_INT(rd16be(b, 37), 512);
    q.edns_size = 0;
    NT_EQ_INT(nt_dns_msg_build_query(&q, b, sizeof b, &n), NT_OK);
    NT_EQ_INT(rd16be(b, 37), NT_DNS_EDNS_DEFAULT);
    /* no EDNS: ARCOUNT 0, shorter message */
    q.edns = 0;
    NT_EQ_INT(nt_dns_msg_build_query(&q, b, sizeof b, &n), NT_OK);
    NT_EQ_INT(rd16be(b, 10), 0);
    NT_EQ_INT(n, 12 + 18 + 4);

    /* invalid names are rejected before any write */
    q.qname = "bad..name";
    NT_EQ_INT(nt_dns_msg_build_query(&q, b, sizeof b, &n), NT_ERR_MALFORMED);
    q.qname = NULL;
    NT_EQ_INT(nt_dns_msg_build_query(&q, b, sizeof b, &n), NT_ERR_MALFORMED);

    /* cap too small */
    q.qname = "www.example.test";
    NT_EQ_INT(nt_dns_msg_build_query(&q, b, 10, &n), NT_ERR_TRUNCATED);
}

static void test_name_helpers(void)
{
    NT_EQ_INT(nt_dns_name_suffix("www.example.test", "example.test"), 1);
    NT_EQ_INT(nt_dns_name_suffix("www.example.test", "test"), 1);
    NT_EQ_INT(nt_dns_name_suffix("www.example.test", ""), 1);
    NT_EQ_INT(nt_dns_name_suffix("www.example.test", "www.example.test"), 1);
    NT_EQ_INT(nt_dns_name_suffix("example.test", "www.example.test"), 0);
    NT_EQ_INT(nt_dns_name_suffix("www.ample.test", "example.test"), 0);
    NT_EQ_INT(nt_dns_name_suffix("xexample.test", "example.test"), 0);
    NT_EQ_INT(nt_dns_name_suffix("a.example.test", "TEST"), 1);

    NT_EQ_INT(nt_dns_name_labels(""), 0);
    NT_EQ_INT(nt_dns_name_labels("test"), 1);
    NT_EQ_INT(nt_dns_name_labels("example.test"), 2);
    NT_EQ_INT(nt_dns_name_labels("www.example.test."), 3);
}

static void test_rdata_str_types(void)
{
    uint8_t b[512];
    size_t o = hdr(b, 1, 0x8180, 1, 1, 0, 0);
    o = question(b, o, "a.test", NT_DNS_TYPE_A);

    /* TXT: two character-strings joined by a space */
    { static const uint8_t txt[9] = { 5, 'h', 'e', 'l', 'l', 'o', 2, 'h', 'i' };
      o = rr(b, o, "a.test", NT_DNS_TYPE_TXT, 60, txt, 9); }

    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(b, o, &m), NT_OK);
    char out[128];
    NT_EQ_INT(nt_dns_rdata_str(&m, &m.an_rr[0], out, sizeof out), NT_OK);
    NT_CHECK(strcmp(out, "hello hi") == 0);
}

static void test_parse_fixture(void)
{
    /* frame 2 of fixtures/dns-good.pcap: answer owner is a pointer to the
     * qname; tshark reports qname www.example.com and A 93.184.216.34 */
    static const uint8_t p2[] = {
        0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
        0x03,'w','w','w',0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,
        0x00,0x01,0x00,0x01,
        0xc0,0x0c,
        0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,
        0x5d,0xb8,0xd8,0x22,
    };
    nt_dns_msg m;
    NT_EQ_INT(nt_dns_msg_decode(p2, sizeof p2, &m), NT_OK);
    NT_EQ_INT(m.id, 0x1234);
    NT_EQ_INT(m.qr, 1);
    NT_EQ_INT(m.aa, 0);   /* fixture flags 0x8180: scapy did not set AA */
    NT_EQ_INT(m.rd, 1);
    NT_EQ_INT(m.ra, 1);
    NT_CHECK(strcmp(m.q[0].qname, "www.example.com") == 0);
    char out[64];
    NT_EQ_INT(nt_dns_rdata_str(&m, &m.an_rr[0], out, sizeof out), NT_OK);
    NT_CHECK(strcmp(out, "93.184.216.34") == 0);
}

int main(void)
{
    test_decode_query();
    test_decode_answer_compressed();
    test_decode_opt();
    test_opt_floor_and_do();
    test_decode_errors();
    test_decode_second_opt_and_owner();
    test_match();
    test_classify();
    test_glue();
    test_build_query();
    test_name_helpers();
    test_rdata_str_types();
    test_parse_fixture();
    NT_DONE();
}
