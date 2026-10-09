/* libFuzzer harness for the decode library (M8).
 *
 * Build:  make fuzz          (needs clang)
 * Seeds:  scripts/fuzz-seeds.sh fuzz/corpus
 * Run:    build/fuzz/fuzz_decode fuzz/corpus -max_total_time=300
 *
 * Every byte is untrusted wire data; the decoder must never read past `size`,
 * never crash, and never leak. ASan+UBSan are enabled by the make target. */
#include "nettk.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nt_packet pkt;
    (void)nt_decode_frame(data, size, &pkt);
    return 0;
}
