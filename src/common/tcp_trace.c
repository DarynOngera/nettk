#include "tcp_trace.h"

#include <stdio.h>
#include <string.h>

/* tcpdump's flag order; bit values are the on-wire TCP flag bits. */
const char *nt_tcp_flags_str(uint16_t flags, char out[10])
{
    static const struct { uint16_t bit; char c; } map[] = {
        { 0x001u, 'F' }, /* FIN */
        { 0x002u, 'S' }, /* SYN */
        { 0x004u, 'R' }, /* RST */
        { 0x008u, 'P' }, /* PSH */
        { 0x010u, 'A' }, /* ACK */
        { 0x020u, 'U' }, /* URG */
        { 0x040u, 'E' }, /* ECE */
        { 0x080u, 'C' }, /* CWR */
        { 0x100u, 'N' }, /* NS  */
    };
    size_t i;
    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        out[i] = (flags & map[i].bit) ? map[i].c : '.';
    out[i] = '\0';
    return out;
}

uint32_t nt_seq_rel(uint32_t seq, uint32_t base)
{
    return seq - base; /* unsigned wrap gives the signed distance correctly */
}

void nt_tcp_opts_str(const nt_tcp *t, char *out, size_t cap)
{
    size_t off = 0;
    int first = 1;
    out[0] = '\0';
    if (t == NULL)
        return;

#define APPEND(...)                                                          \
    do {                                                                     \
        int _n = snprintf(out + off, cap - off, __VA_ARGS__);                \
        if (_n < 0 || (size_t)_n >= cap - off)                              \
            return;                                                          \
        off += (size_t)_n;                                                   \
    } while (0)
#define SEP()                                                                \
    do {                                                                     \
        if (!first)                                                          \
            APPEND(",");                                                     \
        first = 0;                                                           \
    } while (0)

    if (t->mss > 0) {
        SEP();
        APPEND("mss=%d", t->mss);
    }
    if (t->sack_ok) {
        SEP();
        APPEND("sack");
    }
    if (t->has_ts) {
        SEP();
        APPEND("ts=%u<%u>", t->ts_val, t->ts_ecr);
    }
    if (t->wscale >= 0) {
        SEP();
        APPEND("wscale=%d", t->wscale);
    }
    if (first)
        snprintf(out, cap, "-");
#undef SEP
#undef APPEND
}
