#include "nettk.h"

int need(size_t len, size_t off, size_t n)
{
    if (off > len) {
        return 0;
    }
    return n <= len - off;
}

uint8_t rd8(const uint8_t *buf, size_t off)
{
    return buf[off];
}

uint16_t rd16be(const uint8_t *buf, size_t off)
{
    return (uint16_t)(((uint16_t)buf[off] << 8) | (uint16_t)buf[off + 1]);
}

uint32_t rd32be(const uint8_t *buf, size_t off)
{
    return ((uint32_t)buf[off] << 24) | ((uint32_t)buf[off + 1] << 16) |
           ((uint32_t)buf[off + 2] << 8) | (uint32_t)buf[off + 3];
}
