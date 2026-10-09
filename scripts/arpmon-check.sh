#!/usr/bin/env bash
# M10 checks: every arpmon rule fires on fixtures/arp-spoof.pcap, and the binding
# table stays bounded on the 20k-packet flood fixture.
#
# usage: scripts/arpmon-check.sh [arpmon-binary]
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)

bin=${1:-$root/build/asan/bin/arpmon}
[[ -x $bin ]] || bin=$root/build/release/bin/arpmon
[[ -x $bin ]] || { echo "no arpmon binary (run: make BUILD=asan all)" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || { echo "python3 not installed" >&2; exit 2; }
python3 "$root/py/gen_fixtures.py" "$root/fixtures" >/dev/null

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }

spoof=$("$bin" -r "$root/fixtures/arp-spoof.pcap" 2>/dev/null)
for rule in mac-mismatch binding-change flip-flop gratuitous unsolicited-reply duplicate-ip; do
    if grep -q "ALERT $rule " <<<"$spoof"; then ok "rule fires: $rule"
    else bad "rule fires: $rule"; fi
done

# Run the flood under measurement; the table is fixed at BIND_CAP so RSS stays flat.
rss=$(python3 - "$bin" "$root/fixtures/arp-flood.pcap" <<'PY'
import resource, subprocess, sys
subprocess.run([sys.argv[1], "-r", sys.argv[2]], stdout=subprocess.DEVNULL, check=True)
print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
PY
)
echo "flood max RSS: ${rss} KiB"
if [[ -n $rss && $rss -lt 65536 ]]; then ok "bounded memory on 20k-packet flood"
else bad "bounded memory on 20k-packet flood (${rss} KiB)"; fi

echo; echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
