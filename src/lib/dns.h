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

/* ------------------------------------------------------------------ *
 * Message codec (M11). Decode validates every count, length and rdata
 * layout up front; the fixed arrays mean no allocation and no globals.
 * ------------------------------------------------------------------ */

/* RR types we decode (RFC 1035 section 3.2.2, RFC 3596 section 2.2, RFC 6891
 * section 6); anything else is kept as opaque RDATA. */
#define NT_DNS_TYPE_A     1u
#define NT_DNS_TYPE_NS    2u
#define NT_DNS_TYPE_CNAME 5u
#define NT_DNS_TYPE_SOA   6u
#define NT_DNS_TYPE_PTR   12u
#define NT_DNS_TYPE_MX    15u
#define NT_DNS_TYPE_TXT   16u
#define NT_DNS_TYPE_AAAA  28u
#define NT_DNS_TYPE_OPT   41u

#define NT_DNS_CLASS_IN   1u

/* Header flag masks (RFC 1035 section 4.1.1; AD/CD from RFC 4035 section 4.1.2). */
#define NT_DNS_FLAG_QR 0x8000u
#define NT_DNS_FLAG_AA 0x0400u
#define NT_DNS_FLAG_TC 0x0200u
#define NT_DNS_FLAG_RD 0x0100u
#define NT_DNS_FLAG_RA 0x0080u
#define NT_DNS_FLAG_AD 0x0020u
#define NT_DNS_FLAG_CD 0x0010u

/* RCODEs (RFC 1035 section 4.1.1). */
#define NT_DNS_RCODE_NOERROR  0u
#define NT_DNS_RCODE_FORMERR  1u
#define NT_DNS_RCODE_SERVFAIL 2u
#define NT_DNS_RCODE_NXDOMAIN 3u
#define NT_DNS_RCODE_REFUSED  5u

/* EDNS0 (RFC 6891 section 6.2.3): values below 512 MUST be treated as 512. */
#define NT_DNS_EDNS_MIN     512u
#define NT_DNS_EDNS_DEFAULT 1232u

/* One decoded section entry may hold up to this many RRs (sanity cap; the
 * decoder returns NT_ERR_UNSUPPORTED above it). Worst-case silent truncation
 * would hide hostile structure, so the cap is enforced, not clipped. */
#define NT_DNS_RR_MAX 256u

/* Longest presentation form: every content octet escaped as \DDD. */
#define NT_DNS_NAME_STR_MAX (NT_DNS_NAME_MAX * 4u + 4u)

typedef struct {
    char     qname[NT_DNS_NAME_STR_MAX]; /* presentation, no trailing dot */
    uint16_t qtype, qclass;
    size_t   qname_off;                  /* offset of the name's first octet */
} nt_dns_qd;

typedef struct {
    size_t   name_off;   /* owner name's first octet (may be compressed) */
    uint16_t type, klass;
    uint32_t ttl;
    size_t   rdata_off;  /* offset of RDATA within the message */
    uint16_t rdlen;
} nt_dns_rr;

typedef struct {
    const uint8_t *buf;  /* message view; RDATA names are decoded lazily */
    size_t    len;       /* message length (UDP payload / TCP body) */
    uint16_t  id, flags;
    uint8_t   qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode;
    unsigned  full_rcode;        /* header 4 bits + OPT extended 8 bits */
    unsigned  qd, an, ns, ar;    /* section counts as decoded */
    nt_dns_qd q[1];              /* qd <= 1: more questions is UNSUPPORTED */
    nt_dns_rr an_rr[NT_DNS_RR_MAX];
    nt_dns_rr ns_rr[NT_DNS_RR_MAX];
    nt_dns_rr ar_rr[NT_DNS_RR_MAX];
    int       has_opt;
    uint16_t  opt_udpsize;       /* OPT CLASS, floored at NT_DNS_EDNS_MIN */
    uint8_t   opt_rcode, opt_version;
    uint16_t  opt_flags;         /* OPT TTL flags; DO = bit 15 */
} nt_dns_msg;

/* Parses a whole DNS message. Validates the header, that each section count
 * fits the remaining length before looping (a question needs >= 5 bytes, an
 * RR >= 11), the RDATA layout of every type above, and at most one OPT whose
 * owner is the root. Returns NT_ERR_UNSUPPORTED for more than one question or
 * a section above NT_DNS_RR_MAX. */
nt_status nt_dns_msg_decode(const uint8_t *buf, size_t len, nt_dns_msg *m);

/* Inputs for one query (rule 27). qname is presentation form without the
 * escapes being interpreted (encode() does not expand \DDD); rd sets RD. */
typedef struct {
    uint16_t    id;
    const char *qname;
    uint16_t    qtype, qclass;
    int         rd;
    int         edns;        /* append an OPT record */
    uint16_t    edns_size;   /* advertised UDP payload size, floored at 512 */
    int         do_bit;      /* DNSSEC OK in the OPT TTL */
} nt_dns_query;

/* Builds the 12-byte header + one question + optional OPT into buf. Validates
 * the name via nt_dns_name_encode and bounds-checks cap before every write. */
nt_status nt_dns_msg_build_query(const nt_dns_query *q, uint8_t *buf, size_t cap,
                                 size_t *outlen);

/* Renders one RR's RDATA into out (presentation, escaped, NUL-terminated).
 * A/AAAA -> address; NS/CNAME/PTR -> name; MX -> "pref name"; SOA -> the seven
 * fields; TXT -> 1..n escaped character-strings separated by a space; OPT ->
 * "size=.. rcode=.. version=.. do=.."; anything else -> "\\x" hex. */
nt_status nt_dns_rdata_str(const nt_dns_msg *m, const nt_dns_rr *rr,
                           char *out, size_t cap);

/* Extracts the OPT record (if any): advertised size (floored at 512),
 * extended RCODE, version and TTL flags, plus the full RCODE and DO bit. */
nt_status nt_dns_opt(const nt_dns_msg *m, uint16_t *udpsize, uint8_t *version,
                     uint16_t *flags, unsigned *full_rcode, int *do_bit);

/* True when `suffix` equals `name` or is a proper ancestor of it, compared by
 * whole labels (RFC 1035 section 3.1): "ample.test" is not a parent of
 * "example.test". Case-insensitive; a single trailing dot is ignored; root is
 * the empty string. */
int nt_dns_name_suffix(const char *name, const char *suffix);

/* Number of labels in a presentation name (root = 0). */
unsigned nt_dns_name_labels(const char *name);

/* Reply matcher (rules 28). MATCH only when the message is a response
 * (QR=1), opcode QUERY, echoes the transaction id, carries exactly one
 * question equal (case-insensitive) to the one sent, and comes from the
 * expected server address and port. Well-formed but not ours -> NO_MATCH
 * (drop and count); a NULL/garbled argument -> INVALID. */
nt_match nt_dns_match(const nt_dns_msg *rx, uint16_t txid, const char *qname,
                      uint16_t qtype, uint16_t qclass,
                      uint32_t server4, uint16_t serverport,
                      uint32_t src4, uint16_t srcport);

/* Classifier (rule 29). `zone` is the zone the query was sent to (presentation
 * form, root = ""); the walk updates `st` across referrals/CNAMEs. */
typedef enum {
    NT_DNS_C_ANSWER,     /* records for the qname (after <= 8 CNAME hops) */
    NT_DNS_C_CNAME,      /* answer is a CNAME chain pointing onward */
    NT_DNS_C_NODATA,     /* NOERROR, no answers, SOA in authority */
    NT_DNS_C_NXDOMAIN,   /* RCODE 3, no answers */
    NT_DNS_C_REFERRAL,   /* NS in authority, a delegation below `zone` */
    NT_DNS_C_TRUNCATED,  /* TC=1: retry over TCP */
    NT_DNS_C_SERVFAIL,
    NT_DNS_C_REFUSED,
    NT_DNS_C_BOGUS       /* everything else: drop and count */
} nt_dns_class;

typedef struct {
    unsigned chain;      /* CNAME hops consumed so far (cap 8) */
} nt_dns_state;

nt_dns_class nt_dns_classify(const nt_dns_msg *m, const nt_dns_qd *q,
                             const char *zone, nt_dns_state *st);

/* Human-readable names for the printer / trace (never NULL). */
const char *nt_dns_class_str(nt_dns_class c);
const char *nt_dns_type_str(uint16_t type);

/* Glue lookup for a referral: the first A record in the additional section
 * whose owner equals `nsname`, or 0 when there is none. `out4` is host order. */
int nt_dns_glue(const nt_dns_msg *m, const char *nsname, uint32_t *out4);

#endif /* NETTK_DNS_H */