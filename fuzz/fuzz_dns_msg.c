/* libFuzzer harness for the DNS message codec and helpers (M11, phase 5).
 *
 * Build:  make fuzz          (needs clang)
 * Seeds:  scripts/fuzz-seeds-dns.sh fuzz/corpus-dns
 * Run:    build/fuzz/fuzz_dns_msg fuzz/corpus-dns -max_total_time=300
 *
 * A whole message is untrusted. After a successful decode we render the RDATA
 * of every section entry, pull the OPT record, and run the matcher, glue
 * lookup and classifier with a fixed synthetic question. */
#include "dns.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nt_dns_msg m;
    nt_dns_qd q;
    nt_dns_state st;
    char s[4096];
    uint16_t udp = 0, flags = 0, ttl_flags = 0;
    uint8_t ver = 0;
    unsigned full_rcode = 0;
    int dobit = 0;
    uint32_t glue = 0;

    if (nt_dns_msg_decode(data, size, &m) != NT_OK)
        return 0;

    for (unsigned i = 0; i < m.an; i++)
        (void)nt_dns_rdata_str(&m, &m.an_rr[i], s, sizeof s);
    for (unsigned i = 0; i < m.ns; i++)
        (void)nt_dns_rdata_str(&m, &m.ns_rr[i], s, sizeof s);
    for (unsigned i = 0; i < m.ar; i++)
        (void)nt_dns_rdata_str(&m, &m.ar_rr[i], s, sizeof s);

    (void)nt_dns_opt(&m, &udp, &ver, &ttl_flags, &full_rcode, &dobit);

    memset(&q, 0, sizeof q);
    memcpy(q.qname, "www.example.test", 16);
    q.qtype = NT_DNS_TYPE_A;
    q.qclass = NT_DNS_CLASS_IN;

    (void)nt_dns_match(&m, m.id, q.qname, q.qtype, q.qclass,
                       0x0a000503u, 53, 0x0a000503u, 53);
    (void)nt_dns_glue(&m, q.qname, &glue);

    memset(&st, 0, sizeof st);
    (void)nt_dns_classify(&m, &q, "", &st);
    return 0;
}
