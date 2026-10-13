/* DNS name codec (M10): parse with compression, encode, compare, escape.
 * Good-name vectors are the exact wire bytes of fixtures/dns-good.pcap and
 * were cross-checked against tshark -r (name strings quoted in comments);
 * malformed vectors are fixtures/dns-malformed.pcap. */
#include "nt_test.h"
#include "dns.h"

#include <string.h>

static void check_name(const uint8_t *msg, size_t len, size_t off,
                       const char *want, size_t want_end)
{
    char out[1200];
    size_t end = 0xfeed;
    nt_status st = nt_dns_name_parse(msg, len, off, out, sizeof out, &end);

    NT_EQ_INT(st, NT_OK);
    if (st == NT_OK) {
        NT_CHECK(strcmp(out, want) == 0);
        NT_EQ_INT((long)end, (long)want_end);
    }
}

static void test_parse_good(void)
{
    /* packet 2 of dns-good.pcap (tshark: www.example.com both places) */
    static const uint8_t p2[] = {
        0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
        0x03,'w','w','w',0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,
        0x00,0x01,0x00,0x01,
        0xc0,0x0c,                                   /* owner: pointer to qname */
        0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,
        0x5d,0xb8,0xd8,0x22,
    };
    /* tshark: qname www.example.com at 12, answer owner www.example.com at 33 */
    check_name(p2, sizeof p2, 12, "www.example.com", 29);
    check_name(p2, sizeof p2, 33, "www.example.com", 35);

    /* packet 3 (tshark: alpha.example.com, alpha.example.com; cname www) */
    static const uint8_t p3[] = {
        0x12,0x35,0x81,0x80,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x00,
        0x03,'w','w','w',0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,
        0x00,0x01,0x00,0x01,
        0x05,'a','l','p','h','a',0xc0,0x10,           /* label + ptr to example.com */
        0x00,0x01,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x04,
        0x5d,0xb8,0xd8,0x22,
        0xc0,0x21,                                   /* ptr to the RR1 owner */
        0x00,0x05,0x00,0x01,0x00,0x00,0x01,0x2c,0x00,0x05,
        0x03,'w','w','w',0x00,
    };
    check_name(p3, sizeof p3, 12, "www.example.com", 29);
    check_name(p3, sizeof p3, 33, "alpha.example.com", 41); /* label+ptr */
    check_name(p3, sizeof p3, 55, "alpha.example.com", 57); /* ptr-to-owner */
    check_name(p3, sizeof p3, 67, "www", 72);              /* CNAME rdata */

    /* packet 4 (tshark: x\001y.example.com) and 5 (z\255z.example.com) */
    static const uint8_t p4[] = {
        0x12,0x36,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x03,'x',0x01,'y',0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,
        0x00,0x01,0x00,0x01,
    };
    static const uint8_t p5[] = {
        0x12,0x37,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x03,'z',0xff,'z',0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,
        0x00,0x01,0x00,0x01,
    };
    check_name(p4, sizeof p4, 12, "x\\001y.example.com", 29);
    check_name(p5, sizeof p5, 12, "z\\255z.example.com", 29);

    /* root name */
    static const uint8_t root[] = { 0x00 };
    check_name(root, sizeof root, 0, "", 1);

    /* plain label run, no compression, message-relative endoff */
    static const uint8_t plain[] = {
        0x03,'w','w','w', 0x07,'e','x','a','m','p','l','e',
        0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01, 0xde,0xad,
    };
    check_name(plain, sizeof plain, 0, "www.example.com", 17);
    /* parse the name starting at 4: the endoff is always message-relative */
    check_name(plain, sizeof plain, 4, "example.com", 17);
}

static void test_parse_malformed(void)
{
    char out[1200];
    size_t end;

    /* reserved label type bits 01 (0x41): neither length nor pointer */
    static const uint8_t m1[] = {
        0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x41,'x','x','x','x','x','x','x','x',
    };
    NT_EQ_INT(nt_dns_name_parse(m1, sizeof m1, 12, out, sizeof out, &end),
              NT_ERR_MALFORMED);

    /* compression pointer to itself (offset 12 -> 12) */
    static const uint8_t m2[] = {
        0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0xc0,0x0c, 0x00,0x01,0x00,0x01,
    };
    NT_EQ_INT(nt_dns_name_parse(m2, sizeof m2, 12, out, sizeof out, &end),
              NT_ERR_MALFORMED);

    /* forward pointer: target 14 is its own offset */
    static const uint8_t m3[] = {
        0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x01,'a',0xc0,0x0e, 0x00,0x01,0x00,0x01,
    };
    NT_EQ_INT(nt_dns_name_parse(m3, sizeof m3, 12, out, sizeof out, &end),
              NT_ERR_MALFORMED);

    /* 130-pointer chain: every hop decreases, but exceeds the hop cap */
    {
        uint8_t chain[275];
        size_t o = 12;
        size_t i;
        chain[o++] = 0x01; chain[o++] = 'a'; chain[o++] = 0x00;
        for (i = 0; i < 130; i++) {
            size_t t = (i == 0) ? 12 : 12 + 3 + 2 * (i - 1);
            chain[o++] = (uint8_t)(0xc0 | (t >> 8));
            chain[o++] = (uint8_t)(t & 0xff);
        }
        /* the chain head is the last pointer, at offset 273 */
        NT_EQ_INT(nt_dns_name_parse(chain, o, 273, out, sizeof out, &end),
                  NT_ERR_MALFORMED);
    }

    /* expanded name longer than 255 wire octets (5 x 52-byte labels) */
    {
        uint8_t big[12 + 266];
        size_t o = 12, i, j;
        for (i = 0; i < 5; i++) {
            big[o++] = 52;
            for (j = 0; j < 52; j++)
                big[o++] = (uint8_t)('a' + i);
        }
        big[o++] = 0;
        NT_EQ_INT(nt_dns_name_parse(big, o, 12, out, sizeof out, &end),
                  NT_ERR_MALFORMED);
    }

    /* label claims 7 octets but only 4 remain */
    static const uint8_t m6[] = {
        0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x03,'w','w','w', 0x07,'e','x','a','m',
    };
    NT_EQ_INT(nt_dns_name_parse(m6, sizeof m6, 12, out, sizeof out, &end),
              NT_ERR_TRUNCATED);

    /* pointer octet cut off (1 of 2 present) after a complete qname */
    static const uint8_t m7[] = {
        0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x03,'a','b','c',0x00,
        0xc0,
    };
    check_name(m7, sizeof m7, 12, "abc", 17);
    NT_EQ_INT(nt_dns_name_parse(m7, sizeof m7, 17, out, sizeof out, &end),
              NT_ERR_TRUNCATED);

    /* outcap too small for the escaped form */
    static const uint8_t p2[] = {
        0x03,'w','w','w', 0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m',0x00,
    };
    char small[6];
    NT_EQ_INT(nt_dns_name_parse(p2, sizeof p2, 0, small, sizeof small, &end),
              NT_ERR_TRUNCATED);
}

static void test_encode(void)
{
    uint8_t out[300];
    size_t n = 0;
    static const uint8_t want[] = {
        0x03,'w','w','w', 0x07,'e','x','a','m','p','l','e',
        0x04,'t','e','s','t', 0x00,
    };

    NT_EQ_INT(nt_dns_name_encode("www.example.test", out, sizeof out, &n), NT_OK);
    NT_EQ_INT((long)n, (long)sizeof want);
    NT_CHECK(memcmp(out, want, sizeof want) == 0);

    /* absolute trailing dot is tolerated, elsewhere empty labels are not */
    NT_EQ_INT(nt_dns_name_encode("www.example.test.", out, sizeof out, &n), NT_OK);
    NT_EQ_INT((long)n, (long)sizeof want);
    NT_EQ_INT(nt_dns_name_encode("a", out, sizeof out, &n), NT_OK);
    NT_EQ_INT((long)n, 3);
    NT_CHECK(out[0] == 1 && out[1] == 'a' && out[2] == 0);

    /* root */
    NT_EQ_INT(nt_dns_name_encode("", out, sizeof out, &n), NT_OK);
    NT_EQ_INT((long)n, 1);
    NT_CHECK(out[0] == 0);

    /* 63-byte label is the ceiling */
    {
        char l64[65];
        memset(l64, 'a', sizeof l64 - 1);
        l64[64] = '\0';
        NT_EQ_INT(nt_dns_name_encode(l64, out, sizeof out, &n), NT_ERR_MALFORMED);
        l64[63] = '\0';
        NT_EQ_INT(nt_dns_name_encode(l64, out, sizeof out, &n), NT_OK);
        NT_EQ_INT((long)n, 65);
        NT_CHECK(out[0] == 63);
    }

    /* empty labels */
    NT_EQ_INT(nt_dns_name_encode("a..b", out, sizeof out, &n), NT_ERR_MALFORMED);
    NT_EQ_INT(nt_dns_name_encode(".a", out, sizeof out, &n), NT_ERR_MALFORMED);

    /* total wire length > 255: five 51-byte labels */
    {
        char longname[300];
        size_t i;
        for (i = 0; i < 5; i++) {
            memset(longname + i * 51, 'a' + (int)i, 51);
            if (i < 4)
                longname[i * 51 + 51] = '.';
        }
        longname[5 * 51 + 4] = '\0';   /* 4 dots between 5 labels */
        NT_EQ_INT(nt_dns_name_encode(longname, out, sizeof out, &n),
                  NT_ERR_MALFORMED);
    }

    /* small output buffer */
    NT_EQ_INT(nt_dns_name_encode("www.example.test", out, 2, &n),
              NT_ERR_TRUNCATED);
}

static void test_cmp(void)
{
    NT_CHECK(nt_dns_name_cmp_ci("www.example.test", "WWW.Example.TEST") == 0);
    NT_CHECK(nt_dns_name_cmp_ci("example.test", "example.test.") == 0);
    NT_CHECK(nt_dns_name_cmp_ci("", ".") == 0);
    NT_CHECK(nt_dns_name_cmp_ci("", "") == 0);
    NT_CHECK(nt_dns_name_cmp_ci("a.com", "b.com") != 0);
    NT_CHECK(nt_dns_name_cmp_ci("a.com", "a.org") != 0);
    NT_CHECK(nt_dns_name_cmp_ci("a", "ab") < 0);
    NT_CHECK(nt_dns_name_cmp_ci("example.test", "example.test") == 0);
    /* escaped bytes compare literally */
    NT_CHECK(nt_dns_name_cmp_ci("x\\001y.example", "x\\001y.example") == 0);
}

static void test_escape(void)
{
    static const uint8_t in[] = { 0x00, 0x0a, 'A', '.', '\\', 0x7f, 0xff };
    char out[64];
    size_t n;

    /* \000 \010 A \. \\ \127 \255 */
    static const char want[] =
        "\\000\\010A\\.\\\\\\127\\255";
    n = nt_dns_str_escape(in, sizeof in, out, sizeof out);
    NT_EQ_INT((long)n, (long)(sizeof want - 1));
    NT_CHECK(strcmp(out, want) == 0);

    /* truncation: stops whole-escape, NUL-terminates */
    n = nt_dns_str_escape(in, sizeof in, out, 5);
    NT_EQ_INT((long)n, 4);
    NT_CHECK(strcmp(out, "\\000") == 0);
}

int main(void)
{
    test_parse_good();
    test_parse_malformed();
    test_encode();
    test_cmp();
    test_escape();
    NT_DONE();
}