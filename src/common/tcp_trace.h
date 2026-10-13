/*
 * TCP trace formatting helpers (Phase 4, M3).
 *
 * Pure functions with no I/O and no globals; owned by src/common because both
 * `sniff --tcp-trace` and the unit tests use them. Kept out of src/lib because
 * they format for humans rather than decode the wire.
 */
#ifndef NT_TCP_TRACE_H
#define NT_TCP_TRACE_H

#include <stddef.h>
#include <stdint.h>

#include "nettk.h"

/* Render the TCP flag bits as tcpdump-style letters, in tcpdump's order
 * (F S R P A U E C N); a clear bit is '.'. out must hold >= 10 bytes. */
const char *nt_tcp_flags_str(uint16_t flags, char out[10]);

/* Relative sequence/ack: wrapping subtraction, correct across the 32-bit roll-over. */
uint32_t nt_seq_rel(uint32_t seq, uint32_t base);

/* One-line option summary ("mss=1460 sack ts=... wscale=7"), or "-" when none. */
void nt_tcp_opts_str(const nt_tcp *t, char *out, size_t cap);

#endif /* NT_TCP_TRACE_H */
