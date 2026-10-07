/*
 * smoke: proves the toolchain, the sanitizers, and raw-socket capability.
 *
 *   smoke              open an AF_PACKET socket (needs CAP_NET_RAW)
 *   smoke --asan-test  deliberate heap overflow; AddressSanitizer must trip
 *   smoke --ubsan-test deliberate signed overflow; UBSan must trip
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void print_build(void)
{
#if defined(__SANITIZE_ADDRESS__)
    puts("build: AddressSanitizer enabled");
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
    puts("build: AddressSanitizer enabled");
#endif
#endif
}

static int probe_raw(void)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "AF_PACKET socket: %s\n", strerror(errno));
        fputs("hint: needs CAP_NET_RAW (sudo, or setcap cap_net_raw+ep)\n", stderr);
        return 1;
    }
    puts("AF_PACKET raw socket: ok");
    close(fd);
    return 0;
}

static void asan_trip(int argc)
{
    /* heap-buffer-overflow, on purpose. The size depends on argc so the compiler
     * cannot prove the access is out of bounds (UBSan would pre-empt ASan), and the
     * volatile store stops the optimiser from deleting the whole malloc/free pair. */
    size_t sz = (size_t)argc + 6; /* 8 when run as: smoke --asan-test */
    char *p = malloc(sz);
    if (p == NULL) {
        return;
    }
    volatile char *vp = p;
    vp[sz] = 1; /* one byte past the end */
    free(p);
}

static void ubsan_trip(void)
{
    volatile int x = INT_MAX;
    x += 1; /* signed overflow, on purpose */
    printf("x=%d\n", x);
}

int main(int argc, char **argv)
{
    print_build();
    if (argc > 1 && strcmp(argv[1], "--asan-test") == 0) {
        asan_trip(argc);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--ubsan-test") == 0) {
        ubsan_trip();
        return 0;
    }
    return probe_raw();
}
