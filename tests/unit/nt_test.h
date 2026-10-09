/* Tiny assertion harness for the unit tests. One test binary per file. */
#ifndef NT_TEST_H
#define NT_TEST_H

#include "nettk.h"

#include <stdio.h>
#include <string.h>

static int nt_checks = 0;
static int nt_failed = 0;

#define NT_CHECK(cond)                                                        \
    do {                                                                      \
        nt_checks++;                                                          \
        if (!(cond)) {                                                        \
            nt_failed++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
        }                                                                     \
    } while (0)

#define NT_EQ_INT(got, want)                                                  \
    do {                                                                      \
        long g_ = (long)(got);                                                \
        long w_ = (long)(want);                                               \
        nt_checks++;                                                          \
        if (g_ != w_) {                                                       \
            nt_failed++;                                                      \
            fprintf(stderr, "FAIL %s:%d: got %ld want %ld\n",                 \
                    __FILE__, __LINE__, g_, w_);                              \
        }                                                                     \
    } while (0)

#define NT_EQ_MEM(got, want, n)                                               \
    do {                                                                      \
        nt_checks++;                                                          \
        if (memcmp((got), (want), (n)) != 0) {                                \
            nt_failed++;                                                      \
            fprintf(stderr, "FAIL %s:%d: buffers differ\n", __FILE__, __LINE__); \
        }                                                                     \
    } while (0)

#define NT_DONE()                                                             \
    do {                                                                      \
        fprintf(stderr, "%s: %d/%d checks passed\n", __FILE__,                \
                nt_checks - nt_failed, nt_checks);                            \
        return nt_failed ? 1 : 0;                                             \
    } while (0)

#endif /* NT_TEST_H */
