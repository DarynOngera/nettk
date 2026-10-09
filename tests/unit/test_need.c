#include "nt_test.h"

#include <stdint.h>

int main(void)
{
    /* basic boundaries */
    NT_CHECK(need(10, 0, 10));
    NT_CHECK(need(10, 0, 0));
    NT_CHECK(need(10, 10, 0));
    NT_CHECK(!need(10, 11, 0));
    NT_CHECK(!need(10, 0, 11));
    NT_CHECK(!need(10, 5, 6));
    NT_CHECK(need(10, 5, 5));
    NT_CHECK(need(0, 0, 0));
    NT_CHECK(!need(0, 0, 1));

    /* overflow safety: off + n must never wrap */
    NT_CHECK(!need(SIZE_MAX, SIZE_MAX, 1));
    NT_CHECK(need(SIZE_MAX, 0, SIZE_MAX));
    NT_CHECK(need(SIZE_MAX, SIZE_MAX, 0));
    NT_CHECK(!need(SIZE_MAX, SIZE_MAX - 1, 2));

    /* reads are big-endian */
    const uint8_t b[4] = {0x12, 0x34, 0x56, 0x78};
    NT_EQ_INT(rd8(b, 0), 0x12);
    NT_EQ_INT(rd8(b, 3), 0x78);
    NT_EQ_INT(rd16be(b, 0), 0x1234);
    NT_EQ_INT(rd16be(b, 1), 0x3456);
    NT_EQ_INT(rd32be(b, 0), 0x12345678u);

    NT_DONE();
}
