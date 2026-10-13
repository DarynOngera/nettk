/*
 * nettk DNS codec (phase 5, M10+). Pure, no I/O, no allocation, no globals.
 *
 * Names travel in PRESENTATION form (RFC 1035 section 5.1 escaping as
 * implemented by nt_dns_str_escape): printable ASCII verbatim, '.' inside a
 * label as "\."  , '\' as "\\"  , every other byte as \DDD. The root name is
 * the empty string. Comparison is case-insensitive ASCII (RFC 4343
 * section 4.2.3). A parse output has no trailing dot.
 */
#ifndef NETTK_DNS_H
#define NETTK_DNS_H

#include <stddef.h>
#include <stdint.h>

#include "nettk.h"

#define NT_DNS_NAME_MAX   255u /* total wire length cap, RFC 1035 section 3.1 */
#define NT_DNS_LABEL_MAX  63u  /* label length cap, RFC 1035 section 3.1 */
#define NT_DNS_PTR_HOP_MAX 128u /* compression-pointer chain cap (lab rule) */

/* Parses one (possibly compressed) name out of a DNS message, RFC 1035
 * section 4.1.4.
 *
 *   msg/len   the whole DNS message (pointers are message-relative)
 *   off       offset of the name's first octet
 *   out       presentation form, no trailing dot; root = ""
 *   outcap    capacity of out (must hold the escaped form + NUL)
 *   endoff    offset just past the last octet the name consumed in msg
 *             (where the next field starts); required, non-NULL
 *
 * Safety guarantees:
 *  - every read is bounds-checked against len (NT_ERR_TRUNCATED otherwise);
 *  - label length octets 01/10 type bits are rejected (NT_ERR_MALFORMED);
 *  - a compression pointer must point strictly before itself (RFC 1035
 *    section 4.1.4: "points to a prior occurrence"), which by itself rules
 *    out loops; the hop count is additionally capped at NT_DNS_PTR_HOP_MAX;
 *  - the fully expanded name never exceeds NT_DNS_NAME_MAX wire octets.
 */
nt_status nt_dns_name_parse(const uint8_t *msg, size_t len, size_t off,
                            char *out, size_t outcap, size_t *endoff);

/* Encodes a dotted presentation name (root = "", absolute trailing dot
 * optional) into uncompressed wire labels in out[cap]. *outlen is the bytes
 * written (label octets + terminating zero). Rejects empty labels, labels
 * longer than NT_DNS_LABEL_MAX, and names longer than NT_DNS_NAME_MAX wire
 * octets. NT_ERR_TRUNCATED when cap is too small (outlen untouched).
 *
 * NOTE: encode is for building queries from trusted strings (argv); it does
 * not interpret "{escaped}" input. parse is the only direction that decodes.
 */
nt_status nt_dns_name_encode(const char *name, uint8_t *out, size_t cap,
                             size_t *outlen);

/* Case-insensitive ASCII comparison of two presentation names (RFC 4343
 * section 4.2.3). At most one trailing dot per side is ignored. Returns 0
 * when equal, <0 / >0 otherwise. */
int nt_dns_name_cmp_ci(const char *a, const char *b);

/* Print-safe escaping (RFC 1035 section 5.1): the presentation rule that
 * parse already applies, exposed for label bytes decoded elsewhere (e.g. an
 * rdata name's raw label bytes). Always NUL-terminates out (outcap > 0) and
 * never writes past outcap; returns the number of chars written before the
 * NUL (capped at outcap-1). */
size_t nt_dns_str_escape(const uint8_t *s, size_t n, char *out, size_t outcap);

#endif /* NETTK_DNS_H */