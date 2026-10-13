/* libFuzzer harness for the DNS walk classifier (M14, phase 5).
 *
 * Build:  make fuzz          (needs clang)
 * Seeds:  scripts/fuzz-seeds-dns.sh fuzz/corpus-dns
 * Run:    build/fuzz/fuzz_dns_classify fuzz/corpus-dns -max_total_time=300
 *
 * Drives nt_dns_classify over the same decoded message at three different
 * "current zone" depths (root, test, example.test), resetting the walk state
 * each time, so referral/NODATA/NXDOMAIN edge cases all get exercised. */
#include "dns.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *zones[] = { "", "test", "example.test" };
    nt_dns_msg m;
    nt_dns_qd q;

    if (nt_dns_msg_decode(data, size, &m) != NT_OK)
        return 0;

    memset(&q, 0, sizeof q);
    memcpy(q.qname, "www.example.test", 16);
    q.qtype = NT_DNS_TYPE_A;
    q.qclass = NT_DNS_CLASS_IN;

    for (size_t i = 0; i < sizeof zones / sizeof zones[0]; i++) {
        nt_dns_state st;
        memset(&st, 0, sizeof st);
        (void)nt_dns_classify(&m, &q, zones[i], &st);
    }
    return 0;
}
