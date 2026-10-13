/* DNS message codec (phase 5 M11): header, question, RR, RDATA, OPT, the
 * reply matcher and the section classifier. Pure: no I/O, no allocation, no
 * globals. See dns.h for the contracts and safety rules. */
#include "dns.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define NT_DNS_CNAME_MAX 8u /* lab cap: CNAME chain (docs/phase5.md) */

/* ---- small helpers -------------------------------------------------- */

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int ascii_ci_eq(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i], cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return 1;
}

/* Splits off the final label of s[0..len). *lab and *lablen are the tail label;
 * *parent is the length of the parent text (a prefix of the same buffer). Only
 * an unescaped '.' separates labels, so "\." stays inside a label. */
static void split_last(const char *s, size_t len, const char **lab, size_t *lablen,
                       size_t *parent)
{
    size_t sep = 0;
    int have = 0;

    for (size_t i = 0; i < len; i++) {
        if (s[i] == '\\') {
            if (i + 1 < len) i++;
            continue;
        }
        if (s[i] == '.') {
            sep = i;
            have = 1;
        }
    }
    if (have) {
        *lab = s + sep + 1;
        *lablen = len - sep - 1;
        *parent = sep;
    } else {
        *lab = s;
        *lablen = len;
        *parent = 0;
    }
}

static size_t strip_dot(const char *s)
{
    size_t n = strlen(s);
    if (n > 0 && s[n - 1] == '.') n--;
    return n;
}

/* ---- public name helpers -------------------------------------------- */

int nt_dns_name_suffix(const char *name, const char *suffix)
{
    size_t nlen, slen;

    if (name == NULL || suffix == NULL) return 0;
    nlen = strip_dot(name);
    slen = strip_dot(suffix);

    for (;;) {
        const char *nl, *sl;
        size_t nlz, slz, np, sp;

        if (slen == 0) return 1; /* suffix exhausted: name is at or below it */
        if (nlen == 0) return 0; /* name runs out before the suffix */

        split_last(name, nlen, &nl, &nlz, &np);
        split_last(suffix, slen, &sl, &slz, &sp);
        if (nlz != slz || !ascii_ci_eq(nl, sl, nlz)) return 0;
        nlen = np;
        slen = sp;
    }
}

unsigned nt_dns_name_labels(const char *name)
{
    size_t len;
    unsigned n = 0;

    if (name == NULL) return 0;
    len = strip_dot(name);
    while (len > 0) {
        const char *lab;
        size_t lablen, parent;
        split_last(name, len, &lab, &lablen, &parent);
        (void)lab;
        (void)lablen;
        n++;
        len = parent;
    }
    return n;
}

const char *nt_dns_class_str(nt_dns_class c)
{
    switch (c) {
    case NT_DNS_C_ANSWER:    return "ANSWER";
    case NT_DNS_C_CNAME:     return "CNAME";
    case NT_DNS_C_NODATA:    return "NODATA";
    case NT_DNS_C_NXDOMAIN:  return "NXDOMAIN";
    case NT_DNS_C_REFERRAL:  return "REFERRAL";
    case NT_DNS_C_TRUNCATED: return "TRUNCATED";
    case NT_DNS_C_SERVFAIL:  return "SERVFAIL";
    case NT_DNS_C_REFUSED:   return "REFUSED";
    case NT_DNS_C_BOGUS:     return "BOGUS";
    }
    return "?";
}

const char *nt_dns_type_str(uint16_t type)
{
    switch (type) {
    case NT_DNS_TYPE_A:     return "A";
    case NT_DNS_TYPE_NS:    return "NS";
    case NT_DNS_TYPE_CNAME: return "CNAME";
    case NT_DNS_TYPE_SOA:   return "SOA";
    case NT_DNS_TYPE_PTR:   return "PTR";
    case NT_DNS_TYPE_MX:    return "MX";
    case NT_DNS_TYPE_TXT:   return "TXT";
    case NT_DNS_TYPE_AAAA:  return "AAAA";
    case NT_DNS_TYPE_OPT:   return "OPT";
    default:                return "?";
    }
}

/* ---- RDATA validation and rendering --------------------------------- */

/* Validates that RDATA parses exactly for the types we understand. Anything
 * else is opaque and accepted as-is (rule 25). */
static nt_status rr_rdata_ok(const uint8_t *buf, size_t len, const nt_dns_rr *rr)
{
    char tmp[NT_DNS_NAME_STR_MAX];
    size_t end;

    switch (rr->type) {
    case NT_DNS_TYPE_A:
        return rr->rdlen == 4u ? NT_OK : NT_ERR_MALFORMED;
    case NT_DNS_TYPE_AAAA:
        return rr->rdlen == 16u ? NT_OK : NT_ERR_MALFORMED;
    case NT_DNS_TYPE_NS:
    case NT_DNS_TYPE_CNAME:
    case NT_DNS_TYPE_PTR:
        if (nt_dns_name_parse(buf, len, rr->rdata_off, tmp, sizeof tmp, &end) != NT_OK)
            return NT_ERR_MALFORMED;
        return end == rr->rdata_off + rr->rdlen ? NT_OK : NT_ERR_MALFORMED;
    case NT_DNS_TYPE_MX:
        if (rr->rdlen < 2u) return NT_ERR_MALFORMED;
        if (nt_dns_name_parse(buf, len, rr->rdata_off + 2, tmp, sizeof tmp, &end) != NT_OK)
            return NT_ERR_MALFORMED;
        return end == rr->rdata_off + rr->rdlen ? NT_OK : NT_ERR_MALFORMED;
    case NT_DNS_TYPE_SOA: {
        size_t e2;
        if (nt_dns_name_parse(buf, len, rr->rdata_off, tmp, sizeof tmp, &end) != NT_OK)
            return NT_ERR_MALFORMED;
        if (nt_dns_name_parse(buf, len, end, tmp, sizeof tmp, &e2) != NT_OK)
            return NT_ERR_MALFORMED;
        return e2 + 20u == rr->rdata_off + rr->rdlen ? NT_OK : NT_ERR_MALFORMED;
    }
    case NT_DNS_TYPE_TXT: {
        size_t o = rr->rdata_off, e = rr->rdata_off + rr->rdlen;
        if (rr->rdlen == 0u) return NT_ERR_MALFORMED; /* needs >= 1 char-string */
        while (o < e) {
            uint8_t sl = buf[o];
            if (o + 1u + sl > e) return NT_ERR_MALFORMED;
            o += 1u + sl;
        }
        return NT_OK;
    }
    case NT_DNS_TYPE_OPT: {
        size_t o = rr->rdata_off, e = rr->rdata_off + rr->rdlen;
        while (o < e) {
            uint16_t ol;
            if (e - o < 4u) return NT_ERR_MALFORMED;
            ol = rd16be(buf, o + 2);
            if ((size_t)ol > e - o - 4u) return NT_ERR_MALFORMED;
            o += 4u + ol;
        }
        return NT_OK;
    }
    default:
        return NT_OK;
    }
}

static size_t app(char *out, size_t cap, size_t pos, const char *s)
{
    size_t n = strlen(s);
    if (pos + n < cap) {
        memcpy(out + pos, s, n);
        pos += n;
    }
    return pos;
}

static size_t appu(char *out, size_t cap, size_t pos, unsigned long v)
{
    char b[24];
    int n = snprintf(b, sizeof b, "%lu", v);
    if (n > 0) pos = app(out, cap, pos, b);
    return pos;
}

nt_status nt_dns_rdata_str(const nt_dns_msg *m, const nt_dns_rr *rr,
                           char *out, size_t cap)
{
    const uint8_t *buf;
    size_t ro, rl, pos = 0;

    if (m == NULL || rr == NULL || out == NULL || cap == 0) return NT_ERR_MALFORMED;
    buf = m->buf;
    ro = rr->rdata_off;
    rl = rr->rdlen;
    if (!need(m->len, ro, rl)) return NT_ERR_TRUNCATED;
    out[0] = '\0';

    switch (rr->type) {
    case NT_DNS_TYPE_A:
        if (rl != 4u) return NT_ERR_MALFORMED;
        for (int i = 0; i < 4; i++) {
            if (i) pos = app(out, cap, pos, ".");
            pos = appu(out, cap, pos, buf[ro + (size_t)i]);
        }
        out[pos < cap ? pos : cap - 1] = '\0';
        return NT_OK;
    case NT_DNS_TYPE_AAAA: {
        if (rl != 16u) return NT_ERR_MALFORMED;
        if (inet_ntop(AF_INET6, buf + ro, out, (socklen_t)cap) == NULL)
            return NT_ERR_MALFORMED;
        return NT_OK;
    }
    case NT_DNS_TYPE_NS:
    case NT_DNS_TYPE_CNAME:
    case NT_DNS_TYPE_PTR: {
        size_t end;
        if (nt_dns_name_parse(buf, m->len, ro, out, cap, &end) != NT_OK)
            return NT_ERR_MALFORMED;
        return end == ro + rl ? NT_OK : NT_ERR_MALFORMED;
    }
    case NT_DNS_TYPE_MX: {
        char name[NT_DNS_NAME_STR_MAX];
        size_t end;
        if (rl < 2u) return NT_ERR_MALFORMED;
        if (nt_dns_name_parse(buf, m->len, ro + 2, name, sizeof name, &end) != NT_OK)
            return NT_ERR_MALFORMED;
        if (end != ro + rl) return NT_ERR_MALFORMED;
        pos = appu(out, cap, pos, rd16be(buf, ro));
        pos = app(out, cap, pos, " ");
        pos = app(out, cap, pos, name);
        out[pos < cap ? pos : cap - 1] = '\0';
        return NT_OK;
    }
    case NT_DNS_TYPE_SOA: {
        char mname[NT_DNS_NAME_STR_MAX], rname[NT_DNS_NAME_STR_MAX];
        size_t e1, e2;
        if (nt_dns_name_parse(buf, m->len, ro, mname, sizeof mname, &e1) != NT_OK)
            return NT_ERR_MALFORMED;
        if (nt_dns_name_parse(buf, m->len, e1, rname, sizeof rname, &e2) != NT_OK)
            return NT_ERR_MALFORMED;
        if (e2 + 20u != ro + rl) return NT_ERR_MALFORMED;
        pos = app(out, cap, pos, mname);
        pos = app(out, cap, pos, " ");
        pos = app(out, cap, pos, rname);
        for (int i = 0; i < 5; i++) {
            pos = app(out, cap, pos, " ");
            pos = appu(out, cap, pos, rd32be(buf, e2 + (size_t)i * 4u));
        }
        out[pos < cap ? pos : cap - 1] = '\0';
        return NT_OK;
    }
    case NT_DNS_TYPE_TXT: {
        size_t o = ro, e = ro + rl;
        int first = 1;
        if (rl == 0u) return NT_ERR_MALFORMED;
        while (o < e) {
            uint8_t sl = buf[o];
            if (o + 1u + sl > e) return NT_ERR_MALFORMED;
            if (!first) pos = app(out, cap, pos, " ");
            {
                size_t rem = pos < cap ? cap - pos : 0;
                pos += nt_dns_str_escape(buf + o + 1, sl, out + pos, rem);
            }
            first = 0;
            o += 1u + sl;
        }
        out[pos < cap ? pos : cap - 1] = '\0';
        return NT_OK;
    }
    case NT_DNS_TYPE_OPT:
        pos = app(out, cap, pos, "size=");
        pos = appu(out, cap, pos, m->opt_udpsize);
        pos = app(out, cap, pos, " rcode=");
        pos = appu(out, cap, pos, m->opt_rcode);
        pos = app(out, cap, pos, " version=");
        pos = appu(out, cap, pos, m->opt_version);
        pos = app(out, cap, pos, " do=");
        pos = appu(out, cap, pos, (m->opt_flags >> 15) & 1u);
        out[pos < cap ? pos : cap - 1] = '\0';
        return NT_OK;
    default: {
        for (size_t i = 0; i < rl; i++) {
            char b[3] = { 0, 0, 0 };
            b[0] = "0123456789abcdef"[buf[ro + i] >> 4];
            b[1] = "0123456789abcdef"[buf[ro + i] & 0xf];
            pos = app(out, cap, pos, b);
        }
        out[pos < cap ? pos : cap - 1] = '\0';
        return NT_OK;
    }
    }
}

/* ---- decode --------------------------------------------------------- */

nt_status nt_dns_msg_decode(const uint8_t *buf, size_t len, nt_dns_msg *m)
{
    nt_dns_rr *sec_arr[3];
    unsigned sec_cnt[3];
    unsigned qd, an, ns, ar;
    size_t off = 12;
    uint16_t f;

    if (buf == NULL || m == NULL) return NT_ERR_MALFORMED;
    memset(m, 0, sizeof *m);
    if (len < 12u) return NT_ERR_TRUNCATED;

    m->buf = buf;
    m->len = len;
    m->id = rd16be(buf, 0);
    f = rd16be(buf, 2);
    m->flags = f;
    m->qr     = (uint8_t)((f >> 15) & 1u);
    m->opcode = (uint8_t)((f >> 11) & 0xfu);
    m->aa     = (uint8_t)((f >> 10) & 1u);
    m->tc     = (uint8_t)((f >> 9) & 1u);
    m->rd     = (uint8_t)((f >> 8) & 1u);
    m->ra     = (uint8_t)((f >> 7) & 1u);
    m->z      = (uint8_t)((f >> 6) & 1u);
    m->ad     = (uint8_t)((f >> 5) & 1u);
    m->cd     = (uint8_t)((f >> 4) & 1u);
    m->rcode  = (uint8_t)(f & 0xfu);

    qd = rd16be(buf, 4);
    an = rd16be(buf, 6);
    ns = rd16be(buf, 8);
    ar = rd16be(buf, 10);

    if (qd > 1u) return NT_ERR_UNSUPPORTED; /* more than one question */
    if (an > NT_DNS_RR_MAX || ns > NT_DNS_RR_MAX || ar > NT_DNS_RR_MAX)
        return NT_ERR_UNSUPPORTED;
    m->qd = qd;
    m->an = an;
    m->ns = ns;
    m->ar = ar;

    /* counts must fit the remaining length before any section loop runs */
    if (!need(len, 12, (size_t)qd * 5u + ((size_t)an + ns + ar) * 11u))
        return NT_ERR_TRUNCATED;

    for (unsigned i = 0; i < qd; i++) {
        size_t end;
        nt_status s = nt_dns_name_parse(buf, len, off, m->q[i].qname,
                                        sizeof m->q[i].qname, &end);
        if (s != NT_OK) return s;
        m->q[i].qname_off = off;
        off = end;
        if (!need(len, off, 4)) return NT_ERR_TRUNCATED;
        m->q[i].qtype = rd16be(buf, off);
        m->q[i].qclass = rd16be(buf, off + 2);
        off += 4;
    }

    sec_arr[0] = m->an_rr;
    sec_arr[1] = m->ns_rr;
    sec_arr[2] = m->ar_rr;
    sec_cnt[0] = an;
    sec_cnt[1] = ns;
    sec_cnt[2] = ar;

    for (int sec = 0; sec < 3; sec++) {
        for (unsigned i = 0; i < sec_cnt[sec]; i++) {
            nt_dns_rr *rr = &sec_arr[sec][i];
            char own[NT_DNS_NAME_STR_MAX];
            size_t end;
            nt_status s;

            s = nt_dns_name_parse(buf, len, off, own, sizeof own, &end);
            if (s != NT_OK) return s;
            rr->name_off = off;
            off = end;

            if (!need(len, off, 10)) return NT_ERR_TRUNCATED;
            rr->type = rd16be(buf, off);
            rr->klass = rd16be(buf, off + 2);
            rr->ttl = rd32be(buf, off + 4);
            rr->rdlen = rd16be(buf, off + 8);
            off += 10;

            if (!need(len, off, rr->rdlen)) return NT_ERR_TRUNCATED;
            rr->rdata_off = off;
            off += rr->rdlen;

            /* an OPT is only legal in the additional section (RFC 6891 6.1.1) */
            if (rr->type == NT_DNS_TYPE_OPT && sec != 2) return NT_ERR_MALFORMED;

            s = rr_rdata_ok(buf, len, rr);
            if (s != NT_OK) return s;

            if (sec == 2 && rr->type == NT_DNS_TYPE_OPT) {
                if (m->has_opt) return NT_ERR_MALFORMED;  /* a second OPT */
                if (own[0] != '\0') return NT_ERR_MALFORMED; /* owner must be root */
                m->has_opt = 1;
                m->opt_rcode = (uint8_t)((rr->ttl >> 24) & 0xffu);
                m->opt_version = (uint8_t)((rr->ttl >> 16) & 0xffu);
                m->opt_flags = (uint16_t)(rr->ttl & 0xffffu);
                m->opt_udpsize = rr->klass < NT_DNS_EDNS_MIN ? NT_DNS_EDNS_MIN : rr->klass;
            }
        }
    }

    m->full_rcode = m->rcode;
    if (m->has_opt) m->full_rcode |= (unsigned)m->opt_rcode << 4;
    return NT_OK;
}

nt_status nt_dns_msg_build_query(const nt_dns_query *q, uint8_t *buf, size_t cap,
                                 size_t *outlen)
{
    uint8_t name[NT_DNS_NAME_MAX];
    size_t nl = 0, need_len, off;
    uint16_t flags = 0, edns_size = 0;
    nt_status s;

    if (q == NULL || buf == NULL || outlen == NULL || q->qname == NULL)
        return NT_ERR_MALFORMED;

    s = nt_dns_name_encode(q->qname, name, sizeof name, &nl);
    if (s != NT_OK) return s;

    if (q->edns) {
        edns_size = q->edns_size < NT_DNS_EDNS_MIN ? NT_DNS_EDNS_MIN : q->edns_size;
        if (q->edns_size == 0) edns_size = NT_DNS_EDNS_DEFAULT;
    }

    need_len = 12u + nl + 4u + (q->edns ? 11u : 0u);
    if (cap < need_len) return NT_ERR_TRUNCATED;

    if (q->rd) flags |= NT_DNS_FLAG_RD;
    wr16(buf, q->id);
    wr16(buf + 2, flags);
    wr16(buf + 4, 1);                                  /* QDCOUNT */
    wr16(buf + 6, 0);
    wr16(buf + 8, 0);
    wr16(buf + 10, q->edns ? 1u : 0u);                 /* OPT counts in ARCOUNT */

    off = 12;
    memcpy(buf + off, name, nl);
    off += nl;
    wr16(buf + off, q->qtype);
    wr16(buf + off + 2, q->qclass);
    off += 4;

    if (q->edns) {
        buf[off++] = 0;                                /* root owner */
        wr16(buf + off, NT_DNS_TYPE_OPT); off += 2;
        wr16(buf + off, edns_size);       off += 2;
        wr32(buf + off, q->do_bit ? 0x00008000u : 0u); off += 4;
        wr16(buf + off, 0);               off += 2;    /* no options */
    }

    *outlen = off;
    return NT_OK;
}

nt_status nt_dns_opt(const nt_dns_msg *m, uint16_t *udpsize, uint8_t *version,
                     uint16_t *flags, unsigned *full_rcode, int *do_bit)
{
    if (m == NULL) return NT_ERR_MALFORMED;
    if (udpsize) *udpsize = m->has_opt ? m->opt_udpsize : 0;
    if (version) *version = m->opt_version;
    if (flags) *flags = m->opt_flags;
    if (full_rcode) *full_rcode = m->full_rcode;
    if (do_bit) *do_bit = m->has_opt ? (int)((m->opt_flags >> 15) & 1u) : 0;
    return NT_OK;
}

/* ---- matcher -------------------------------------------------------- */

nt_match nt_dns_match(const nt_dns_msg *rx, uint16_t txid, const char *qname,
                      uint16_t qtype, uint16_t qclass,
                      uint32_t server4, uint16_t serverport,
                      uint32_t src4, uint16_t srcport)
{
    if (rx == NULL || qname == NULL) return NT_INVALID;
    if (rx->qr != 1u) return NT_NO_MATCH;
    if (rx->opcode != 0u) return NT_NO_MATCH;
    if (rx->id != txid) return NT_NO_MATCH;
    if (src4 != server4 || srcport != serverport) return NT_NO_MATCH;
    if (rx->qd != 1u) return NT_NO_MATCH;
    if (rx->q[0].qtype != qtype || rx->q[0].qclass != qclass) return NT_NO_MATCH;
    if (nt_dns_name_cmp_ci(rx->q[0].qname, qname) != 0) return NT_NO_MATCH;
    return NT_MATCH;
}

/* ---- classifier ----------------------------------------------------- */

static int rr_owner(const nt_dns_msg *m, const nt_dns_rr *rr, char *out, size_t cap)
{
    size_t end;
    return nt_dns_name_parse(m->buf, m->len, rr->name_off, out, cap, &end) == NT_OK;
}

static nt_dns_class classify_answer(const nt_dns_msg *m, const nt_dns_qd *q,
                                    nt_dns_state *st)
{
    char cur[NT_DNS_NAME_STR_MAX];
    unsigned hops = 0;
    int followed = 0;
    size_t ql = strlen(q->qname);

    if (ql >= sizeof cur) return NT_DNS_C_BOGUS;
    memcpy(cur, q->qname, ql + 1);

    for (;;) {
        int got_answer = 0, got_cname = 0;

        if (hops > NT_DNS_CNAME_MAX) return NT_DNS_C_BOGUS;
        for (unsigned i = 0; i < m->an; i++) {
            const nt_dns_rr *rr = &m->an_rr[i];
            char own[NT_DNS_NAME_STR_MAX];

            if (!rr_owner(m, rr, own, sizeof own)) return NT_DNS_C_BOGUS;
            if (nt_dns_name_cmp_ci(own, cur) != 0) continue;
            if (rr->type == q->qtype && rr->klass == q->qclass) {
                got_answer = 1;
                break;
            }
            if (rr->type == NT_DNS_TYPE_CNAME && rr->klass == q->qclass) {
                char tgt[NT_DNS_NAME_STR_MAX];
                size_t tl;
                if (nt_dns_rdata_str(m, rr, tgt, sizeof tgt) != NT_OK)
                    return NT_DNS_C_BOGUS;
                tl = strlen(tgt);
                if (tl >= sizeof cur) return NT_DNS_C_BOGUS;
                memcpy(cur, tgt, tl + 1);
                got_cname = 1;
                followed = 1;
                hops++;
                break;
            }
        }
        if (got_answer) {
            if (st) st->chain += hops;
            return NT_DNS_C_ANSWER;
        }
        if (!got_cname) break;
        if (st && st->chain + hops > NT_DNS_CNAME_MAX) return NT_DNS_C_BOGUS;
    }
    if (followed) {
        if (st) st->chain += hops;
        return NT_DNS_C_CNAME;
    }
    return NT_DNS_C_BOGUS; /* answers that connect to nothing */
}

static nt_dns_class classify_referral(const nt_dns_msg *m, const nt_dns_qd *q,
                                      const char *zone)
{
    unsigned zl = nt_dns_name_labels(zone);
    int found = 0;

    for (unsigned i = 0; i < m->ns; i++) {
        const nt_dns_rr *rr = &m->ns_rr[i];
        char own[NT_DNS_NAME_STR_MAX];

        if (rr->type != NT_DNS_TYPE_NS) continue;
        if (!rr_owner(m, rr, own, sizeof own)) return NT_DNS_C_BOGUS;
        if (!nt_dns_name_suffix(q->qname, own)) return NT_DNS_C_BOGUS; /* unrelated */
        if (nt_dns_name_labels(own) <= zl) return NT_DNS_C_BOGUS;      /* back up */
        found = 1;
    }
    return found ? NT_DNS_C_REFERRAL : NT_DNS_C_BOGUS;
}

nt_dns_class nt_dns_classify(const nt_dns_msg *m, const nt_dns_qd *q,
                             const char *zone, nt_dns_state *st)
{
    unsigned rc;

    if (m == NULL || q == NULL || zone == NULL) return NT_DNS_C_BOGUS;
    if (m->tc) return NT_DNS_C_TRUNCATED;

    rc = m->full_rcode;
    if (rc == NT_DNS_RCODE_SERVFAIL) return NT_DNS_C_SERVFAIL;
    if (rc == NT_DNS_RCODE_REFUSED) return NT_DNS_C_REFUSED;
    if (rc != NT_DNS_RCODE_NOERROR && rc != NT_DNS_RCODE_NXDOMAIN)
        return NT_DNS_C_BOGUS;

    if (rc == NT_DNS_RCODE_NXDOMAIN) {
        if (m->an > 0u) return NT_DNS_C_BOGUS; /* NXDOMAIN carrying answers */
        return NT_DNS_C_NXDOMAIN;
    }

    if (m->an > 0u) return classify_answer(m, q, st);

    /* NOERROR with an empty answer section */
    for (unsigned i = 0; i < m->ns; i++) {
        const nt_dns_rr *rr = &m->ns_rr[i];
        char own[NT_DNS_NAME_STR_MAX];
        if (rr->type != NT_DNS_TYPE_SOA) continue;
        if (!rr_owner(m, rr, own, sizeof own)) return NT_DNS_C_BOGUS;
        if (!nt_dns_name_suffix(q->qname, own)) return NT_DNS_C_BOGUS;
        return NT_DNS_C_NODATA;
    }
    if (m->ns > 0u) return classify_referral(m, q, zone);
    return NT_DNS_C_BOGUS;
}

int nt_dns_glue(const nt_dns_msg *m, const char *nsname, uint32_t *out4)
{
    if (m == NULL || nsname == NULL || out4 == NULL) return 0;
    for (unsigned i = 0; i < m->ar; i++) {
        const nt_dns_rr *rr = &m->ar_rr[i];
        char own[NT_DNS_NAME_STR_MAX];
        if (rr->type != NT_DNS_TYPE_A || rr->klass != NT_DNS_CLASS_IN || rr->rdlen != 4u)
            continue;
        if (!rr_owner(m, rr, own, sizeof own)) continue;
        if (nt_dns_name_cmp_ci(own, nsname) != 0) continue;
        *out4 = rd32be(m->buf, rr->rdata_off);
        return 1;
    }
    return 0;
}
