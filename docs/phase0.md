# Phase 0: Lab Harness

Goal: a reproducible, disposable network you can capture on, break, and rebuild in seconds,
plus a C toolchain whose sanitizers are proven to work. Time-box: 2-3 days.

## Theory minimum (read once, 20 minutes)

- **Network namespace**: an independent network stack (interfaces, routes, ARP/neighbour table,
  netfilter rules, sockets). `ip netns exec` runs a process inside one. Containers are namespaces
  plus cgroups plus a filesystem.
- **veth pair**: a virtual cable. Frames sent into one end come out the other. One end per namespace
  makes a "wire" between two hosts.
- **Bridge**: a software L2 switch. It learns source MACs per port and forwards by destination MAC.
- **Router namespace**: just a namespace with `net.ipv4.ip_forward=1` and two interfaces.
- **Offloads** (checksum, TSO/GSO/GRO): the kernel defers work to the NIC, so captured packets can
  carry unfinished checksums or be larger than the MTU. This lab disables them by default.
- **Sanitizers**: ASan catches memory errors at the access; UBSan catches undefined behaviour.
  A sanitizer you have never seen fire is a sanitizer you cannot trust, hence `make san-test`.

## Acceptance

```
make deps         # tools present
make phase0       # sanitizers trip, fixtures generate, lab comes up, lab checks pass
```

## Experiments (do each, capture the evidence)

1. **TTL byte by hand.** `sudo lab/up.sh basic`. In one shell run `sudo lab/cap.sh rtr r1 icmp`; in
   another `sudo lab/ex h1 ping -c1 10.0.2.2`. Print the captured packet with
   `tcpdump -nXX -r captures/<file>` and find the TTL byte (offset 14 + 8 = 22). Repeat on `r2` and
   confirm it dropped by one. Write down the offsets of: dst MAC, src MAC, EtherType, IP protocol,
   src/dst IP.
2. **ARP life cycle.** `sudo lab/ex h1 ip neigh flush all`, capture on `h1 eth0`, ping the router.
   Identify the request (broadcast dst `ff:ff:ff:ff:ff:ff`), the reply (unicast), and the neighbour
   entry states with `ip neigh` (`REACHABLE`, then `STALE`). Note why the first MAC octet `02` marks
   the lab MACs as locally administered.
3. **Broadcast domain.** `sudo lab/up.sh bridge3 --force`. Capture on `h3 eth0`, then ping h1 to h2.
   h3 sees the ARP broadcast but not the unicast ICMP. Confirm with
   `sudo lab/ex sw bridge fdb show br br0` which port each MAC lives on.
4. **Offload artifact.** `NT_OFFLOAD=1 sudo -E lab/up.sh basic --force`. Run
   `sudo lab/ex h2 python3 -m http.server 8000 &` and `sudo lab/ex h1 curl -s http://10.0.2.2:8000/`
   while capturing on `h1 eth0` with `tcpdump -nvv`. Find the "incorrect" checksums. Compare with
   `ethtool -k eth0` inside h1, then rebuild with offloads off and watch them disappear. Record which
   features were responsible.
5. **Sanitizers.** Read `src/smoke/smoke.c`. Run both trips by hand and read the ASan report: which
   line, which allocation, how many bytes past the end. Then build `BUILD=release` and observe that
   the overflow goes unnoticed.

## Break and debug (write up at least two)

| Break | Symptom to predict first | How to find it |
|---|---|---|
| `sudo lab/ex rtr sysctl -w net.ipv4.ip_forward=0` | h1 reaches the router but not h2 | capture on `r1` and `r2`: request arrives, nothing leaves |
| `sudo lab/ex h1 ip route del default` | `Network is unreachable` immediately, no packets sent | `ip route get 10.0.2.2` |
| `sudo lab/ex h1 ip route replace default via 10.0.1.99` | ARP requests for .99 go unanswered | `ip neigh` shows `FAILED`/`INCOMPLETE`; capture shows repeated ARP |
| `sudo lab/ex h2 ip addr flush dev eth0` | h2 stops answering; h1 sees ARP failures for 10.0.2.2 at the router | `lab/status.sh`, capture on `r2` |

## Security note (write 5 lines)

- Opening `AF_PACKET` needs `CAP_NET_RAW`; inside a namespace it exposes every frame of that
  namespace. State which capability you will keep after opening the socket, and which you drop.
- Namespaces isolate network state, not privilege: root inside one is still root.
- `lab/down.sh` kills every process in `nt-*` namespaces. Say why it must never match anything else.

## Done when

- [ ] `make phase0` passes on your machine
- [ ] experiments 1-5 have evidence (captures or command output) in `docs/phase0-evidence/`
- [ ] two break-and-debug write-ups using `docs/phase-template.md`
- [ ] security note written
- [ ] you can bring the lab up from nothing in under a minute without notes
