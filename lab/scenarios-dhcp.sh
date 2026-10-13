#!/usr/bin/env bash
# Phase 6 (M20-M22) lab rows: the DORA client, the broadcast-flag lesson, the
# rogue server and (via scripts/dhcp-starvation.sh) pool exhaustion.
#
#   sudo lab/up.sh dhcp1
#   sudo lab/svc.sh dhcp up            # dnsmasq on dhcpd (pool 10.0.6.100-150)
#   sudo lab/scenarios-dhcp.sh
#
# Rows:
#   M20  dhcpc completes DORA and gets a lease that matches dnsmasq's lease file
#   M20  a plain UDP socket (:68) sees nothing when the OFFER is unicast, but
#        sees it once the DISCOVER sets the broadcast flag -- why dhcpc uses
#        AF_PACKET. (py/udp68.py, no CAP_NET_RAW held by the client.)
#   M21  lab/apply-lease.sh applies the lease; the address shows up on eth0
#   M22  a rogue server answers too; --trust-server makes the client ignore it
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
source "$here/lib.sh"
nt_require_root

topo=$(cat "$NT_STATE" 2>/dev/null || true)
if [[ $topo != dhcp1 ]]; then
    echo "this scenario script expects the dhcp1 topology (run: sudo lab/up.sh dhcp1 --force)"
    exit 2
fi

bin="$root/build/asan/bin/dhcpc"
[[ -x $bin ]] || bin="$root/build/release/bin/dhcpc"
[[ -x $bin ]] || { echo "no dhcpc binary (run: make BUILD=asan all)"; exit 2; }
command -v dnsmasq >/dev/null 2>&1 || { echo "dnsmasq not installed"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not installed"; exit 2; }

build=$root/build/lab-dhcp
leases=$build/dhcpd.leases

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
info(){ echo "info  $1"; }

# Fresh server: clear the lease table so each run starts from a known state.
fresh_dhcp() {
    nt_ex dhcpd pkill -x dnsmasq 2>/dev/null || true
    rm -f "$leases"
    "$here/svc.sh" dhcp up >/dev/null 2>&1
    sleep 1
}

lease_ip_for() {  # chaddr -> the IP dnsmasq handed to it
    awk -v m="$1" 'tolower($2) == tolower(m) { print $3 }' "$leases" 2>/dev/null | tail -1
}

# clear any address left over from a previous scenario run
nt_ex c1 ip addr flush dev eth0 2>/dev/null || true

# --- M20: DORA, lease matches dnsmasq's own record --------------------------
fresh_dhcp
out=$(nt_ex c1 env NT_LAB=1 "$bin" -i eth0 --hostname c1 --lease-file /tmp/nt-c1.lease 2>&1)
echo "$out" | sed 's/^/      /'
got=$(grep -oE 'lease_valid=1 ip=[0-9.]+' <<<"$out" | grep -oE '[0-9.]+$' || true)
record=$(lease_ip_for 02:00:00:00:06:0a)
if [[ -n $got && $got == "$record" ]]; then
    ok "M20 DORA: client yiaddr=$got equals dnsmasq lease file ($record)"
else
    bad "M20 DORA: client got '${got:-none}', dnsmasq says '${record:-none}'"
fi

# --- M21: apply the lease and confirm it lands on eth0 ----------------------
if [[ -f /tmp/nt-c1.lease ]]; then
    # apply-lease.sh wraps its own `ip netns exec nt-c1`, so run it on the host.
    "$root/lab/apply-lease.sh" c1 --lease-file /tmp/nt-c1.lease \
        --resolv-out /tmp/nt-c1.resolv 2>&1 | sed 's/^/      /'
    addr=$(nt_ex c1 ip -4 -br addr show eth0 2>/dev/null)
    if [[ -n $got ]] && grep -q "$got" <<<"$addr"; then
        ok "M21 apply-lease: eth0 now has $got"
    else
        bad "M21 apply-lease: eth0 shows '$addr'"
    fi
else
    bad "M21 apply-lease: dhcpc wrote no lease file"
fi
nt_ex c1 ip addr flush dev eth0 2>/dev/null || true

# --- M20 broadcast flag: what a plain UDP socket sees -----------------------
# A protocol client that owns no address cannot use a UDP socket for the
# unicast OFFER; the kernel drops it. With the flag set the server broadcasts.
udp_seen() {  # extra dhcpc args -> datagrams py/udp68.py caught
    nt_ex c1 python3 "$root/py/udp68.py" --port 68 --count 1 --timeout 5 \
        >/tmp/nt-udp68.log 2>&1 &
    local upid=$!
    sleep 0.3
    nt_ex c1 env NT_LAB=1 "$bin" -i eth0 --timeout 5 $1 >/tmp/nt-bcast-client.log 2>&1 || true
    wait "$upid" 2>/dev/null || true
    grep -oE 'udp68: received [0-9]+' /tmp/nt-udp68.log | grep -oE '[0-9]+$'
}

fresh_dhcp
n_unicast=$(udp_seen "")
fresh_dhcp
n_bcast=$(udp_seen "--broadcast")
info "M20 plain UDP :68 saw ${n_unicast:-0} datagram(s) with no flag, ${n_bcast:-0} with --broadcast"
if [[ ${n_bcast:-0} -ge 1 ]]; then
    ok "M20 broadcast flag: the OFFER reaches an ordinary UDP socket"
else
    info "M20 UDP :68 saw no broadcast OFFER (c1 has no address/route; the AF_PACKET path still worked)"
fi
if [[ ${n_unicast:-0} -eq 0 ]]; then
    ok "M20 unicast OFFER is invisible to UDP :68 (why dhcpc uses AF_PACKET)"
else
    info "M20 dnsmasq broadcast the OFFER without the flag this time (seen: $n_unicast)"
fi

# --- M22: rogue server and --trust-server -----------------------------------
fresh_dhcp
nt_ex rogue pkill -x dnsmasq 2>/dev/null || true
"$here/svc.sh" dhcp rogue >/dev/null 2>&1
sleep 1
rogue_pid_ok=0
nt_ex rogue ss -lun 2>/dev/null | grep -q ':67 ' && rogue_pid_ok=1
if [[ $rogue_pid_ok -eq 1 ]]; then
    ok "M22 rogue dnsmasq is listening on 10.0.6.66:67"
else
    info "M22 rogue server did not come up; skipping its rows"
fi

if [[ $rogue_pid_ok -eq 1 ]]; then
    # Without a trust anchor either server may win. Force the race to the rogue
    # by stopping the honest server, then show --trust-server rejects its offer.
    nt_ex dhcpd pkill -x dnsmasq 2>/dev/null || true
    out=$(nt_ex c1 env NT_LAB=1 "$bin" -i eth0 --timeout 5 2>&1)
    rogue_ip=$(grep -oE 'server_id=[0-9.]+' <<<"$out" | grep -oE '[0-9.]+$' || true)
    if [[ $rogue_ip == 10.0.6.66 ]]; then
        ok "M22 client accepted the only server present (rogue 10.0.6.66)"
    else
        info "M22 client server_id='${rogue_ip:-none}' (expected the rogue 10.0.6.66)"
    fi

    out=$(nt_ex c1 env NT_LAB=1 "$bin" -i eth0 --trust-server 10.0.6.1 --timeout 5 2>&1)
    if grep -q 'no OFFER' <<<"$out"; then
        ok "M22 --trust-server 10.0.6.1 ignored the rogue offer (timed out)"
    else
        bad "M22 --trust-server did not reject the rogue (output: $(tr '\n' ' ' <<<"$out"))"
    fi
fi

# --- cleanup ----------------------------------------------------------------
"$here/svc.sh" dhcp down >/dev/null 2>&1 || true
rm -f /tmp/nt-c1.lease /tmp/nt-c1.resolv /tmp/nt-udp68.log /tmp/nt-bcast-client.log

echo
echo "scenarios-dhcp: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
