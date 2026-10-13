/*
 * nettk guard: refuse active network sends outside the lab.
 *
 * The guard is a seatbelt against typos, not a security boundary. Sending tools
 * call nt_guard_ipv4()/nt_guard_ipv6() before the first send, and ARP/NDP tools
 * additionally call nt_guard_iface_veth(). Everything refuses unless NT_LAB=1
 * (set by lab/ex) and the address is inside a lab range.
 *
 * Socket tools (Phase 4+) use the *_peer/_bind variants: the allowed peer set
 * adds loopback (127.0.0.0/8, ::1), and a server may bind the wildcard address,
 * a lab address or loopback. Servers must also pass nt_guard_server_port().
 */
#ifndef NT_GUARD_H
#define NT_GUARD_H

#include <stdint.h>

/* Pure range predicates, no I/O; unit-testable on their own. */
int nt_in_lab_v4(uint32_t addr);            /* host order */
int nt_in_lab_v6(const uint8_t addr[16]);
int nt_in_lab_ip(const char *text);         /* parse as v4 or v6, then range-check */
int nt_in_loopback_v4(uint32_t addr);       /* 127.0.0.0/8, host order */
int nt_in_loopback_v6(const uint8_t addr[16]); /* ::1 */

/* 0 when allowed, -1 when refused (reason printed to stderr). */
int nt_guard_lab(void);                     /* only check NT_LAB */
int nt_guard_ipv4(uint32_t dst);
int nt_guard_ipv6(const uint8_t dst[16]);
int nt_guard_iface_veth(const char *ifname);/* NIC driver must be veth */

/* Socket peers: lab ranges plus namespace loopback. */
int nt_guard_peer_v4(uint32_t dst);
int nt_guard_peer_v6(const uint8_t dst[16]);

/* Bind addresses: wildcard, lab range or loopback. */
int nt_guard_bind_v4(uint32_t addr);
int nt_guard_bind_v6(const uint8_t addr[16]);

/* Server port policy: refuse well-known ports (below 1024). */
int nt_guard_server_port(uint16_t port);

#endif /* NT_GUARD_H */
