#include "nettk.h"

/* One's-complement 16-bit sum over network-order bytes. An odd trailing byte is
 * treated as the high byte of a final zero-padded word (RFC 1071). */
uint32_t nt_csum_partial(const void *p, size_t n)
{
    const uint8_t *b = p;
    uint32_t sum = 0;
    size_t i = 0;

    while (i + 1 < n) {
        sum += (uint32_t)(((uint16_t)b[i] << 8) | (uint16_t)b[i + 1]);
        i += 2;
    }
    if (i < n) {
        sum += (uint32_t)((uint16_t)b[i] << 8);
    }
    return sum;
}

uint32_t nt_csum_add(uint32_t sum, const void *p, size_t n)
{
    return sum + nt_csum_partial(p, n);
}

uint16_t nt_csum_final(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

uint32_t nt_csum_pseudo4(uint32_t src, uint32_t dst, uint8_t proto, uint16_t l4len)
{
    return (src >> 16) + (src & 0xffffu) + (dst >> 16) + (dst & 0xffffu) +
           (uint32_t)proto + (uint32_t)l4len;
}

uint32_t nt_csum_pseudo6(const uint8_t src[16], const uint8_t dst[16], uint8_t nxt, uint32_t l4len)
{
    return nt_csum_partial(src, 16) + nt_csum_partial(dst, 16) +
           (l4len >> 16) + (l4len & 0xffffu) + (uint32_t)nxt;
}
