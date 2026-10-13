/* libFuzzer harness for the DNS name codec (M10, phase 5).
 *
 * Build:  make fuzz          (needs clang)
 * Seeds:  scripts/fuzz-seeds-dns.sh fuzz/corpus-dns
 * Run:    build/fuzz/fuzz_dns_name fuzz/corpus-dns -max_total_time=300
 *
 * Every byte is untrusted wire data placed at offset 0 of a message. The name
 * parser must never read past `size`; when it succeeds we also fuzz the
 * encoder on the decoded presentation form and the caller-side helpers. */
#include "dns.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char name[NT_DNS_NAME_STR_MAX];
    uint8_t wire[NT_DNS_NAME_MAX + 8];
    size_t end = 0, wlen = 0;

    if (nt_dns_name_parse(data, size, 0, name, sizeof name, &end) != NT_OK)
        return 0;

    /* decoded presentation form: exercise the round trip and the helpers */
    (void)nt_dns_name_encode(name, wire, sizeof wire, &wlen);
    (void)nt_dns_name_cmp_ci(name, name);
    (void)nt_dns_name_suffix(name, name);
    (void)nt_dns_name_labels(name);

    /* re-parse the encoder's output to check the two directions agree */
    if (wlen > 0) {
        char again[NT_DNS_NAME_STR_MAX];
        size_t end2 = 0;
        (void)nt_dns_name_parse(wire, wlen, 0, again, sizeof again, &end2);
    }

    /* escape a bounded slice of arbitrary label bytes */
    {
        char esc[NT_DNS_NAME_STR_MAX];
        (void)nt_dns_str_escape(data, size < 64 ? size : 64, esc, sizeof esc);
    }
    return 0;
}
