/*
 * sniff: decode and print packets from a pcap file or live interface.
 *
 *   sniff -r <file> [--tsv] [-x] [-c N]        decode a capture
 *   sniff -i <if>   [--tsv] [-x] [-c N]        live capture (root/CAP_NET_RAW)
 *   sniff -r <file> -w <out>                   faithful pcap copy
 *   sniff -i <if>   -w <out>                   live capture to pcap
 *
 * --tsv columns and order match scripts/tshark-fields.sh exactly.
 */
#include "nettk.h"
#include "live.h"
#include "pcap.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NT_SNAP 65536

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(FILE *f, const char *prog)
{
    fprintf(f,
            "usage: %s (-r <file> | -i <if>) [-w <out>] [--tsv] [-x] [-c N]\n"
            "  -r <file>   read a classic pcap file\n"
            "  -i <if>     live AF_PACKET capture\n"
            "  -w <out>    write classic pcap (Ethernet)\n"
            "  -c <N>      stop after N packets\n"
            "  --tsv       TSV output matching scripts/tshark-fields.sh\n"
            "  -x          hex dump with field-offset annotations\n",
            prog);
}

static void fmt_mac(char out[18], const uint8_t m[6])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void fmt_v4(char out[16], uint32_t ip)
{
    snprintf(out, 16, "%u.%u.%u.%u",
             (ip >> 24) & 0xffu, (ip >> 16) & 0xffu, (ip >> 8) & 0xffu, ip & 0xffu);
}

static void fmt_v6(char out[46], const uint8_t ip[16])
{
    if (inet_ntop(AF_INET6, ip, out, 46) == NULL) {
        out[0] = '\0';
    }
}

static void print_tsv(const nt_packet *p, unsigned long long num, size_t framelen)
{
    char b[64];
    int first = 1;
#define COL(s) do { if (!first) putchar('\t'); first = 0; fputs((s), stdout); } while (0)
#define COLF(...) do { snprintf(b, sizeof b, __VA_ARGS__); COL(b); } while (0)

    COLF("%llu", num);
    COLF("%zu", framelen);

    if (p->has_eth) {
        fmt_mac(b, p->eth.src); COL(b);
        fmt_mac(b, p->eth.dst); COL(b);
        COLF("0x%04x", p->eth.ethertype);
    } else { COL(""); COL(""); COL(""); }

    if (p->vlan.count > 0) { COLF("%u", p->vlan.tag[p->vlan.count - 1].vid); }
    else { COL(""); }

    if (p->has_ipv4) {
        fmt_v4(b, p->ip4.src); COL(b);
        fmt_v4(b, p->ip4.dst); COL(b);
        COLF("%u", p->ip4.ttl);
        COLF("%u", p->ip4.proto);
        COL(p->ip4.flag_mf ? "True" : "False");
        COLF("%u", p->ip4.frag_off);
    } else { COL(""); COL(""); COL(""); COL(""); COL(""); COL(""); }

    if (p->has_ipv6) {
        fmt_v6(b, p->ip6.src); COL(b);
        fmt_v6(b, p->ip6.dst); COL(b);
        COLF("%u", p->ip6.next_hdr);
        COLF("%u", p->ip6.hop_limit);
    } else { COL(""); COL(""); COL(""); COL(""); }

    if (p->has_tcp) {
        COLF("%u", p->tcp.sport);
        COLF("%u", p->tcp.dport);
        COLF("0x%04x", p->tcp.flags & 0x00ffu);
    } else { COL(""); COL(""); COL(""); }

    if (p->has_udp) { COLF("%u", p->udp.sport); COLF("%u", p->udp.dport); }
    else { COL(""); COL(""); }

    if (p->has_icmp) { COLF("%u", p->icmp.type); COLF("%u", p->icmp.code); }
    else { COL(""); COL(""); }

    if (p->has_icmpv6) { COLF("%u", p->icmpv6.type); COLF("%u", p->icmpv6.code); }
    else { COL(""); COL(""); }

    putchar('\n');
#undef COL
#undef COLF
}

static void print_field(const char *name, size_t start, size_t end, const char *value)
{
    printf("  [%zu:%zu] %-10s %s\n", start, end, name, value);
}

static void print_hex(const nt_packet *p, const uint8_t *buf, size_t len)
{
    for (size_t off = 0; off < len; off += 16) {
        printf("%04zx  ", off);
        for (size_t i = 0; i < 16; i++) {
            if (off + i < len) { printf("%02x ", buf[off + i]); } else { fputs("   ", stdout); }
        }
        putchar(' ');
        for (size_t i = 0; i < 16 && off + i < len; i++) {
            unsigned char c = buf[off + i];
            putchar((c >= 32 && c < 127) ? c : '.');
        }
        putchar('\n');
    }

    char b[64];
    if (!p->has_eth) { return; }
    fmt_mac(b, p->eth.dst); print_field("eth.dst", 0, 6, b);
    fmt_mac(b, p->eth.src); print_field("eth.src", 6, 12, b);
    snprintf(b, sizeof b, "0x%04x", p->eth.ethertype); print_field("eth.type", 12, 14, b);

    for (int t = 0; t < p->vlan.count; t++) {
        size_t off = 12 + (size_t)t * 4;
        snprintf(b, sizeof b, "%u (tpid 0x%04x pcp %u dei %u)",
                 p->vlan.tag[t].vid, p->vlan.tag[t].tpid, p->vlan.tag[t].pcp, p->vlan.tag[t].dei);
        print_field("vlan", off, off + 4, b);
    }

    if (p->has_ipv4) {
        size_t l3 = p->l3_off;
        print_field("ipv4.hdr", l3, l3 + 20, "");
        snprintf(b, sizeof b, "%u", p->ip4.ttl);         print_field("ip.ttl", l3 + 8, l3 + 9, b);
        snprintf(b, sizeof b, "%u", p->ip4.proto);       print_field("ip.proto", l3 + 9, l3 + 10, b);
        fmt_v4(b, p->ip4.src);                            print_field("ip.src", l3 + 12, l3 + 16, b);
        fmt_v4(b, p->ip4.dst);                            print_field("ip.dst", l3 + 16, l3 + 20, b);
    }
    if (p->has_ipv6) {
        size_t l3 = p->l3_off;
        print_field("ipv6.hdr", l3, l3 + 40, "");
        snprintf(b, sizeof b, "%u", p->ip6.next_hdr);     print_field("ipv6.nxt", l3 + 6, l3 + 7, b);
        snprintf(b, sizeof b, "%u", p->ip6.hop_limit);    print_field("ipv6.hlim", l3 + 7, l3 + 8, b);
        fmt_v6(b, p->ip6.src);                            print_field("ipv6.src", l3 + 8, l3 + 24, b);
        fmt_v6(b, p->ip6.dst);                            print_field("ipv6.dst", l3 + 24, l3 + 40, b);
    }
    if (p->has_tcp) {
        size_t l4 = p->l4_off;
        snprintf(b, sizeof b, "ports %u->%u flags 0x%04x", p->tcp.sport, p->tcp.dport, p->tcp.flags & 0xffu);
        print_field("tcp.hdr", l4, l4 + (size_t)p->tcp.data_off * 4, b);
    }
    if (p->has_udp) {
        size_t l4 = p->l4_off;
        snprintf(b, sizeof b, "ports %u->%u len %u", p->udp.sport, p->udp.dport, p->udp.len);
        print_field("udp.hdr", l4, l4 + 8, b);
    }
    if (p->has_icmp)     { print_field("icmp", p->l4_off, p->l4_off + 8, ""); }
    if (p->has_icmpv6)   { print_field("icmpv6", p->l4_off, p->l4_off + 8, ""); }
}

static void emit(const nt_packet *pkt, const uint8_t *buf, size_t caplen,
                 unsigned long long num, size_t origlen, int tsv, int hex)
{
    if (tsv) {
        print_tsv(pkt, num, origlen);
    } else if (hex) {
        printf("#%llu len=%zu status=%s\n", num, origlen, nt_status_str(pkt->status));
        print_hex(pkt, buf, caplen);
    }
}

int main(int argc, char **argv)
{
    const char *infile = NULL;
    const char *iface = NULL;
    const char *outfile = NULL;
    long count = -1;
    int tsv = 0;
    int hex = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            infile = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            outfile = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            count = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--tsv") == 0) {
            tsv = 1;
        } else if (strcmp(argv[i], "-x") == 0) {
            hex = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        } else {
            fprintf(stderr, "sniff: unknown argument '%s'\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        }
    }

    if ((infile == NULL) == (iface == NULL)) {
        fprintf(stderr, "sniff: exactly one of -r/-i is required\n");
        usage(stderr, argv[0]);
        return 2;
    }

    uint8_t *buf = malloc(NT_SNAP + 4); /* +4 for a re-inserted VLAN tag */
    if (buf == NULL) {
        fprintf(stderr, "sniff: out of memory\n");
        return 1;
    }

    unsigned long long num = 0;
    long emitted = 0;
    unsigned long stats[4] = { 0, 0, 0, 0 };
    unsigned long incoming = 0, outgoing = 0;
    int rc = 0;

    if (infile != NULL) {
        nt_pcap pc;
        if (nt_pcap_open(&pc, infile) != NT_OK) {
            free(buf);
            return 1;
        }
        nt_pcap_writer w;
        int writing = 0;
        if (outfile != NULL) {
            uint32_t snap = pc.snaplen ? pc.snaplen : NT_SNAP;
            if (nt_pcap_writer_open(&w, outfile, pc.nano, snap) != 0) {
                nt_pcap_close(&pc);
                free(buf);
                return 1;
            }
            writing = 1;
        }
        size_t caplen = 0, origlen = 0;
        uint32_t sec = 0, frac = 0;
        while ((rc = nt_pcap_next(&pc, buf, NT_SNAP, &caplen, &origlen, &sec, &frac)) == 1) {
            num++;
            if (writing &&
                nt_pcap_writer_write(&w, buf, caplen, origlen, sec, frac) != 0) {
                rc = -1;
                break;
            }
            nt_packet pkt;
            nt_status s = nt_decode_frame(buf, caplen, &pkt);
            stats[(unsigned)s < 4u ? (unsigned)s : 0u]++;
            emit(&pkt, buf, caplen, num, origlen, tsv, hex);
            emitted++;
            if (count > 0 && emitted >= count) {
                break;
            }
        }
        if (writing) {
            nt_pcap_writer_close(&w);
        }
        nt_pcap_close(&pc);
    } else {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_signal;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);

        nt_live lv;
        if (nt_live_open(&lv, iface) != 0) {
            free(buf);
            return 1;
        }
        nt_pcap_writer w;
        int writing = 0;
        if (outfile != NULL) {
            if (nt_pcap_writer_open(&w, outfile, 0, NT_SNAP) != 0) {
                nt_live_close(&lv);
                free(buf);
                return 1;
            }
            writing = 1;
        }
        fprintf(stderr, "sniff: capturing on %s (Ctrl-C to stop)\n", iface);
        while (!g_stop) {
            size_t caplen = 0;
            uint64_t ts_us = 0;
            rc = nt_live_next(&lv, buf, NT_SNAP, &caplen, &ts_us);
            if (rc < 0) {
                break;
            }
            if (rc == 0) {
                continue;
            }
            num++;
            uint32_t sec = (uint32_t)(ts_us / 1000000ULL);
            uint32_t frac = (uint32_t)(ts_us % 1000000ULL);
            if (writing &&
                nt_pcap_writer_write(&w, buf, caplen, caplen, sec, frac) != 0) {
                rc = -1;
                break;
            }
            nt_packet pkt;
            nt_status s = nt_decode_frame(buf, caplen, &pkt);
            stats[(unsigned)s < 4u ? (unsigned)s : 0u]++;
            emit(&pkt, buf, caplen, num, caplen, tsv, hex);
            emitted++;
            if (count > 0 && emitted >= count) {
                break;
            }
        }
        if (writing) {
            nt_pcap_writer_close(&w);
        }
        incoming = lv.incoming;
        outgoing = lv.outgoing;
        nt_live_close(&lv);
        rc = 0;
    }

    free(buf);

    if (rc < 0) {
        return 1;
    }
    fprintf(stderr, "packets=%llu  truncated=%lu malformed=%lu unsupported=%lu",
            num, stats[NT_ERR_TRUNCATED], stats[NT_ERR_MALFORMED], stats[NT_ERR_UNSUPPORTED]);
    if (iface != NULL) {
        fprintf(stderr, "  incoming=%lu outgoing=%lu", incoming, outgoing);
    }
    fputc('\n', stderr);
    return 0;
}
