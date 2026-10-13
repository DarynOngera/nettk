/* tcp_trace helpers: flag string, relative seq, options string. */
#include "nt_test.h"
#include "tcp_trace.h"

#include <string.h>

#define STR_EQ(got, want) NT_CHECK(strcmp((got), (want)) == 0)

static void test_flags(void)
{
    char s[10];
    STR_EQ(nt_tcp_flags_str(0, s), ".........");
    STR_EQ(nt_tcp_flags_str(0x001u, s), "F........");
    STR_EQ(nt_tcp_flags_str(0x002u, s), ".S.......");
    STR_EQ(nt_tcp_flags_str(0x004u, s), "..R......");
    STR_EQ(nt_tcp_flags_str(0x008u, s), "...P.....");
    STR_EQ(nt_tcp_flags_str(0x010u, s), "....A....");
    STR_EQ(nt_tcp_flags_str(0x020u, s), ".....U...");
    STR_EQ(nt_tcp_flags_str(0x040u, s), "......E..");
    STR_EQ(nt_tcp_flags_str(0x080u, s), ".......C.");
    STR_EQ(nt_tcp_flags_str(0x100u, s), "........N");
    /* SYN+ACK: tcpdump prints [S.] -- S in slot 2, A in slot 5 */
    STR_EQ(nt_tcp_flags_str(0x002u | 0x010u, s), ".S..A....");
    NT_CHECK(strcmp(nt_tcp_flags_str(0x012u, s), ".S..A....") == 0);
    /* the nine flags at once, tcpdump's order */
    STR_EQ(nt_tcp_flags_str(0x1ffu, s), "FSRPAUECN");
}

static void test_seq_rel(void)
{
    /* no wrap */
    NT_EQ_INT(nt_seq_rel(100u, 50u), 50u);
    NT_EQ_INT(nt_seq_rel(50u, 50u), 0u);
    /* the wrap case tcpdump relies on: seq - base in unsigned arithmetic
     * yields the correct signed distance across the 32-bit boundary. */
    NT_EQ_INT(nt_seq_rel(0u, 0xfffffffeu), 2u);
    NT_EQ_INT(nt_seq_rel(5u, 0xfffffffcu), 9u);
    /* base after seq would mean 4 GiB of traffic in this direction since
     * the base was sampled; unsigned subtraction still gives the wrap. */
    NT_EQ_INT(nt_seq_rel(10u, 20u), 0xfffffff6u);
}

static void test_opts(void)
{
    char out[256];
    nt_tcp t;
    memset(&t, 0, sizeof t);
    t.mss = -1;
    t.wscale = -1;

    /* nothing set on the wire -> "-" like tcpdump's empty options */
    nt_tcp_opts_str(&t, out, sizeof out);
    STR_EQ(out, "-");

    t.mss = 1460;
    nt_tcp_opts_str(&t, out, sizeof out);
    STR_EQ(out, "mss=1460");

    t.sack_ok = 1;
    nt_tcp_opts_str(&t, out, sizeof out);
    STR_EQ(out, "mss=1460,sack");

    t.has_ts = 1;
    t.ts_val = 0x01020304u; /* 16909060 decimal */
    t.ts_ecr = 0;
    nt_tcp_opts_str(&t, out, sizeof out);
    STR_EQ(out, "mss=1460,sack,ts=16909060<0>");

    t.wscale = 7;
    nt_tcp_opts_str(&t, out, sizeof out);
    STR_EQ(out, "mss=1460,sack,ts=16909060<0>,wscale=7");

    /* ts alone (mss/sack/wscale back to absent) */
    t.mss = -1;
    t.sack_ok = 0;
    t.wscale = -1;
    nt_tcp_opts_str(&t, out, sizeof out);
    STR_EQ(out, "ts=16909060<0>");

    /* NULL input is safe and yields an empty string */
    nt_tcp_opts_str(NULL, out, sizeof out);
    STR_EQ(out, "");

    /* a tiny buffer truncates without overflowing past the NUL */
    memset(out, 'x', 8);
    nt_tcp_opts_str(&t, out, 4);
    NT_CHECK(out[3] == '\0');
    NT_CHECK(strlen(out) <= 3);
}

int main(void)
{
    test_flags();
    test_seq_rel();
    test_opts();
    NT_DONE();
}