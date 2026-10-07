/* libFuzzer stub. Phase 1 replaces the body with a call into the decode library:
 *   decode_frame(data, size, &out);
 * Build with: make fuzz   (needs clang). Seed corpus: fixtures/*.pcap payloads. */
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    return 0;
}
