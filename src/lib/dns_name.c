/* DNS name codec (phase 5 M10): parse (with compression), encode, compare,
 * escape. See dns.h for the contracts and safety rules. */
#include "dns.h"

#include <string.h>

/* Writes one byte's presentation escape into d (4 bytes max), returns its
 * length: printable ASCII verbatim ('.' and '\\' doubled), everything else
 * as \DDD (RFC 1035 section 5.1). */
static size_t escape_byte(uint8_t b, char *d)
{
    if (b == (uint8_t)'.') {
        d[0] = '\\';
        d[1] = '.';
        return 2;
    }
    if (b == (uint8_t)'\\') {
        d[0] = '\\';
        d[1] = '\\';
        return 2;
    }
    if (b >= 0x21u && b <= 0x7eu) {
        d[0] = (char)b;
        return 1;
    }
    d[0] = '\\';
    d[1] = (char)('0' + b / 100);
    d[2] = (char)('0' + (b / 10) % 10);
    d[3] = (char)('0' + b % 10);
    return 4;
}

nt_status nt_dns_name_parse(const uint8_t *msg, size_t len, size_t off,
                            char *out, size_t outcap, size_t *endoff)
{
    size_t outpos = 0;   /* chars written to out, NUL excluded */
    size_t wire = 0;     /* expanded wire octets: sum(1+label) + 1 for the zero */
    size_t hops = 0;
    size_t end = off;    /* where the name ends in msg; fixed once the */
    int     scanning = 1;/*   first pointer/terminator is reached */

    if (out == NULL || endoff == NULL || outcap == 0)
        return NT_ERR_MALFORMED;

    for (;;) {
        uint8_t l;
        size_t j, p;

        if (!need(len, off, 1))
            return NT_ERR_TRUNCATED;
        l = rd8(msg, off);

        if ((l & 0xc0u) == 0xc0u) {          /* 11: compression pointer */
            if (!need(len, off, 2))
                return NT_ERR_TRUNCATED;
            if (scanning) {                  /* first octet run = next field */
                end = off + 2;
                scanning = 0;
            }
            p = ((size_t)(l & 0x3fu) << 8) | rd8(msg, off + 1);
            if (p >= off)                    /* RFC 1035 4.1.4: prior occurrence */
                return NT_ERR_MALFORMED;
            if (++hops > NT_DNS_PTR_HOP_MAX) /* second barrier, defense in depth */
                return NT_ERR_MALFORMED;
            off = p;
            continue;
        }

        if ((l & 0xc0u) != 0x00u)            /* 01/10: reserved type bits */
            return NT_ERR_MALFORMED;

        if (l == 0u) {                       /* root / terminator */
            if (scanning) {
                end = off + 1;
                scanning = 0;
            }
            wire++;
            break;
        }
        /* 1..63: a label (mask guarantees l <= NT_DNS_LABEL_MAX) */
        if (scanning)
            end = off + 1 + l;
        if (!need(len, off + 1, l))
            return NT_ERR_TRUNCATED;
        wire += 1u + l;
        if (wire > NT_DNS_NAME_MAX)          /* expanded name too long, RFC 1035 3.1 */
            return NT_ERR_MALFORMED;

        if (outpos > 0) {                    /* separator dot between labels */
            if (outpos + 1 >= outcap)        /* dot + room for the NUL */
                return NT_ERR_TRUNCATED;
            out[outpos++] = '.';
        }
        for (j = 0; j < l; j++) {
            char tmp[4];
            size_t t = escape_byte(rd8(msg, off + 1 + j), tmp);
            if (outpos + t >= outcap)        /* leave room for the NUL */
                return NT_ERR_TRUNCATED;
            memcpy(out + outpos, tmp, t);
            outpos += t;
        }
        off += 1u + l;
        if (scanning)
            end = off;
    }

    *endoff = end;
    out[outpos] = '\0';
    return NT_OK;
}

nt_status nt_dns_name_encode(const char *name, uint8_t *out, size_t cap,
                             size_t *outlen)
{
    size_t n, i = 0, start = 0, wire = 0, pos = 0, lab;

    if (name == NULL || out == NULL || outlen == NULL || cap == 0)
        return NT_ERR_MALFORMED;

    n = strlen(name);
    if (n == 0) {                            /* root name */
        out[0] = 0;
        *outlen = 1;
        return NT_OK;
    }

    while (i <= n) {
        if (i == n || name[i] == '.') {
            lab = i - start;
            if (lab == 0) {
                if (i == n)          /* trailing dot: absolute form */
                    break;
                return NT_ERR_MALFORMED;   /* leading / doubled dot */
            }
            if (lab > NT_DNS_LABEL_MAX)
                return NT_ERR_MALFORMED;
            wire += 1u + lab;
            if (wire + 1u > NT_DNS_NAME_MAX)
                return NT_ERR_MALFORMED;
            if (pos + 1u + lab >= cap)       /* label + NUL must fit */
                return NT_ERR_TRUNCATED;
            out[pos++] = (uint8_t)lab;
            memcpy(out + pos, name + start, lab);
            pos += lab;
            if (i == n)
                break;
            start = i + 1;
        }
        i++;
    }

    if (pos >= cap)                          /* the terminator + NUL */
        return NT_ERR_TRUNCATED;
    out[pos++] = 0;
    out[pos] = '\0';                         /* safety for string printing */
    *outlen = pos;
    return NT_OK;
}

int nt_dns_name_cmp_ci(const char *a, const char *b)
{
    size_t al, bl, i;
    unsigned char ca, cb;

    if (a == NULL || b == NULL)
        return a == b ? 0 : (a == NULL ? -1 : 1);
    al = strlen(a);
    bl = strlen(b);
    if (al && a[al - 1] == '.')
        al--;
    if (bl && b[bl - 1] == '.')
        bl--;
    for (i = 0; i < al && i < bl; i++) {
        ca = (unsigned char)a[i];
        cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb)
            return ca < cb ? -1 : 1;
    }
    if (al == bl)
        return 0;
    return al < bl ? -1 : 1;
}

size_t nt_dns_str_escape(const uint8_t *s, size_t n, char *out, size_t outcap)
{
    size_t pos = 0, i;

    if (out == NULL || outcap == 0)
        return 0;
    for (i = 0; i < n && s != NULL; i++) {
        char tmp[4];
        size_t t = escape_byte(s[i], tmp);
        if (pos + t >= outcap)               /* leave room for the NUL */
            break;
        memcpy(out + pos, tmp, t);
        pos += t;
    }
    out[pos] = '\0';
    return pos;
}