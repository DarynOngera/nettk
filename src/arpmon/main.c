/* arpmon: passive ARP anomaly monitor, from a pcap (-r) or live (-i).
 *
 * State is a fixed-capacity binding table with LRU eviction, so a flood of fake
 * bindings cannot grow memory. Detection rules (rate-limited per (IP, rule)):
 *   mac-mismatch      ARP sender hardware != Ethernet source
 *   binding-change    a known IP maps to a new MAC
 *   flip-flop         a changed IP maps back to a previous MAC
 *   gratuitous        a reply whose sender and target IP are equal (announcement)
 *   unsolicited-reply a reply with no request seen for that binding
 *   duplicate-ip      one IP claimed by more than one MAC over time
 */
#include "clock.h"
#include "live.h"
#include "nettk.h"
#include "pcap.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NT_RECV_CAP 2048
#define BIND_CAP 128
#define REQ_CAP 64
#define REQ_WINDOW_NS (5ull * 1000000000ull)
#define RULE_RATE_NS  (2ull * 1000000000ull)

enum { R_MISMATCH, R_CHANGE, R_FLIP, R_GRAT, R_UNSOL, R_DUP, NRULES };
static const char *rule_name[NRULES] = {
    "mac-mismatch", "binding-change", "flip-flop",
    "gratuitous", "unsolicited-reply", "duplicate-ip",
};

typedef struct {
    uint32_t ip;
    uint8_t  mac[6], prev_mac[6];
    int      have, have_prev, mac_count;
    uint64_t last_seen;
    uint64_t last_alert[NRULES];
} binding;

typedef struct { uint32_t tpa, spa; uint64_t ts; } reqrec;

static binding table[BIND_CAP];
static reqrec  reqs[REQ_CAP];
static int     req_head;
static long    alerts;
static volatile sig_atomic_t g_stop;

static void on_signal(int s) { (void)s; g_stop = 1; }

static void fmt_v4(char out[16], uint32_t ip)
{
    snprintf(out, 16, "%u.%u.%u.%u",
             (ip >> 24) & 0xffu, (ip >> 16) & 0xffu, (ip >> 8) & 0xffu, ip & 0xffu);
}

static void fmt_mac(char out[18], const uint8_t m[6])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static uint32_t v4(const uint8_t p[4])
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void emit(uint32_t ip, const uint8_t mac[6], int rule, uint64_t now,
                 uint64_t *last_alert)
{
    if (now - *last_alert < RULE_RATE_NS)
        return;
    *last_alert = now;
    char ipt[16], mact[18];
    fmt_v4(ipt, ip);
    fmt_mac(mact, mac);
    printf("ALERT %s ip=%s mac=%s\n", rule_name[rule], ipt, mact);
    alerts++;
}

static binding *table_get(uint32_t ip, uint64_t now)
{
    binding *lru = &table[0];
    for (int i = 0; i < BIND_CAP; i++) {
        if (table[i].have && table[i].ip == ip) {
            table[i].last_seen = now;
            return &table[i];
        }
        if (!table[i].have)
            return &table[i];
        if (table[i].last_seen < lru->last_seen)
            lru = &table[i];
    }
    /* full: evict the least recently used */
    memset(lru, 0, sizeof *lru);
    return lru;
}

static void note_request(uint32_t spa, uint32_t tpa, uint64_t ts)
{
    reqs[req_head].spa = spa;
    reqs[req_head].tpa = tpa;
    reqs[req_head].ts = ts;
    req_head = (req_head + 1) % REQ_CAP;
}

/* A reply is solicited if we saw a request with the reply's roles swapped:
 * request(tpa == reply.spa, spa == reply.tpa). */
static int request_seen(uint32_t reply_spa, uint32_t reply_tpa, uint64_t ts)
{
    for (int i = 0; i < REQ_CAP; i++) {
        if (reqs[i].ts != 0 && reqs[i].tpa == reply_spa && reqs[i].spa == reply_tpa &&
            ts - reqs[i].ts <= REQ_WINDOW_NS)
            return 1;
    }
    return 0;
}

static void observe(const uint8_t *buf, size_t len, uint64_t now)
{
    nt_eth_hdr eth;
    nt_vlan vlan;
    if (nt_eth_decode(buf, len, &eth, &vlan) != NT_OK || eth.ethertype != 0x0806)
        return;
    nt_arp a;
    if (nt_arp_decode(buf + 14, len - 14, &a) != NT_OK)
        return;

    uint32_t spa = v4(a.spa), tpa = v4(a.tpa);
    int mismatch = memcmp(a.sha, eth.src, 6) != 0;

    if (a.op == 1) { /* request: remember it, and treat the sender as a binding */
        note_request(spa, tpa, now);
        if (spa != 0) {
            binding *b = table_get(spa, now);
            if (!b->have) {
                b->have = 1;
                b->ip = spa;
                memcpy(b->mac, a.sha, 6);
                b->mac_count = 1;
            } else if (memcmp(b->mac, a.sha, 6) != 0) {
                memcpy(b->prev_mac, b->mac, 6);
                b->have_prev = 1;
                memcpy(b->mac, a.sha, 6);
                b->mac_count++;
                emit(spa, a.sha, R_CHANGE, now, b->last_alert + R_CHANGE);
            }
        }
        if (mismatch) {
            binding *b = table_get(spa, now);
            emit(spa, a.sha, R_MISMATCH, now, b->last_alert + R_MISMATCH);
        }
        return;
    }
    if (a.op != 2)
        return;

    if (mismatch) {
        binding *b = table_get(spa, now);
        emit(spa, a.sha, R_MISMATCH, now, b->last_alert + R_MISMATCH);
    }
    binding *b = table_get(spa, now);
    if (!b->have) {
        b->have = 1;
        b->ip = spa;
        memcpy(b->mac, a.sha, 6);
        b->mac_count = 1;
    } else if (memcmp(b->mac, a.sha, 6) != 0) {
        emit(spa, a.sha, R_CHANGE, now, b->last_alert + R_CHANGE);
        if (b->have_prev && memcmp(b->prev_mac, a.sha, 6) == 0)
            emit(spa, a.sha, R_FLIP, now, b->last_alert + R_FLIP);
        memcpy(b->prev_mac, b->mac, 6);
        b->have_prev = 1;
        memcpy(b->mac, a.sha, 6);
        b->mac_count++;
    }

    if (b->mac_count > 1)
        emit(spa, a.sha, R_DUP, now, b->last_alert + R_DUP);
    if (spa == tpa)
        emit(spa, a.sha, R_GRAT, now, b->last_alert + R_GRAT);
    if (!request_seen(spa, tpa, now))
        emit(spa, a.sha, R_UNSOL, now, b->last_alert + R_UNSOL);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *pcap_path = NULL, *iface = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-r") == 0 && i + 1 < argc) pcap_path = argv[++i];
        else if (strcmp(a, "-i") == 0 && i + 1 < argc) iface = argv[++i];
        else {
            fprintf(stderr, "usage: arpmon (-r <file.pcap> | -i <iface>)\n");
            return 2;
        }
    }
    if ((pcap_path == NULL) == (iface == NULL)) {
        fprintf(stderr, "usage: arpmon (-r <file.pcap> | -i <iface>)\n");
        return 2;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (pcap_path != NULL) {
        nt_pcap p;
        if (nt_pcap_open(&p, pcap_path) != NT_OK)
            return 1;
        printf("ARP monitor on %s\n", pcap_path);
        uint8_t buf[NT_RECV_CAP];
        size_t caplen, origlen;
        uint32_t sec, frac;
        int r;
        while (!g_stop &&
               (r = nt_pcap_next(&p, buf, sizeof buf, &caplen, &origlen, &sec, &frac)) > 0) {
            uint64_t now = (uint64_t)sec * 1000000000ull +
                           (p.nano ? (uint64_t)frac : (uint64_t)frac * 1000ull);
            observe(buf, caplen, now);
        }
        nt_pcap_close(&p);
    } else {
        nt_live l;
        if (nt_live_open(&l, iface) != 0)
            return 1;
        printf("ARP monitor on %s\n", iface);
        uint8_t buf[NT_RECV_CAP + 4];
        size_t caplen;
        uint64_t ts_us;
        while (!g_stop) {
            int r = nt_live_next(&l, buf, sizeof buf, &caplen, &ts_us);
            if (r < 0)
                break;
            if (r == 0)
                continue;
            observe(buf, caplen, ts_us * 1000ull);
        }
        nt_live_close(&l);
    }

    printf("alerts=%ld\n", alerts);
    return 0;
}
