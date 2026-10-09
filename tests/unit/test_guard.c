/* M0: guard range predicates and the NT_LAB seatbelt. */
#include "nt_test.h"
#include "guard.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

static void test_v4(void)
{
    NT_CHECK(nt_in_lab_v4(0x0a000001u));   /* 10.0.0.1 */
    NT_CHECK(nt_in_lab_v4(0x0a00ffffu));   /* 10.0.255.255 */
    NT_CHECK(nt_in_lab_v4(0x0a000000u));   /* 10.0.0.0 */
    NT_CHECK(!nt_in_lab_v4(0x0a010000u));  /* 10.1.0.0 */
    NT_CHECK(!nt_in_lab_v4(0xc0a80001u));  /* 192.168.0.1 */
    NT_CHECK(!nt_in_lab_v4(0x0b000001u));  /* 11.0.0.1 */
    NT_CHECK(!nt_in_lab_v4(0x08080808u));  /* 8.8.8.8 */
}

static void test_v6(void)
{
    static const uint8_t ula[16]  = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const uint8_t ula2[16] = { 0xfd, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const uint8_t doc[16]  = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const uint8_t doc2[16] = { 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const uint8_t ll[16]   = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const uint8_t lo[16]   = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    NT_CHECK(nt_in_lab_v6(ula));
    NT_CHECK(nt_in_lab_v6(ula2));
    NT_CHECK(nt_in_lab_v6(doc));
    NT_CHECK(!nt_in_lab_v6(doc2));
    NT_CHECK(!nt_in_lab_v6(ll));
    NT_CHECK(!nt_in_lab_v6(lo));
}

static void test_parse(void)
{
    NT_CHECK(nt_in_lab_ip("10.0.9.2"));
    NT_CHECK(!nt_in_lab_ip("10.9.0.1"));
    NT_CHECK(nt_in_lab_ip("fd00:1::1"));
    NT_CHECK(nt_in_lab_ip("2001:db8::1"));
    NT_CHECK(!nt_in_lab_ip("8.8.8.8"));
    NT_CHECK(!nt_in_lab_ip("2606:4700::1111"));
    NT_CHECK(!nt_in_lab_ip("not-an-ip"));
}

static void test_lab_gate(void)
{
    unsetenv("NT_LAB");
    NT_EQ_INT(nt_guard_lab(), -1);

    setenv("NT_LAB", "0", 1);
    NT_EQ_INT(nt_guard_lab(), -1);

    setenv("NT_LAB", "1", 1);
    NT_EQ_INT(nt_guard_lab(), 0);

    NT_EQ_INT(nt_guard_ipv4(0x0a000001u), 0);
    NT_EQ_INT(nt_guard_ipv4(0x08080808u), -1);
}

static void test_iface_gate(void)
{
    setenv("NT_LAB", "1", 1);
    /* loopback is not veth, so the gate must refuse even inside the lab. */
    NT_EQ_INT(nt_guard_iface_veth("lo"), -1);
}

int main(void)
{
    test_v4();
    test_v6();
    test_parse();
    test_lab_gate();
    test_iface_gate();
    NT_DONE();
}
