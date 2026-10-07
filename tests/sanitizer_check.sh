#!/usr/bin/env bash
# Verify the ASan/UBSan build actually catches bugs (a silent sanitizer is worse than none).
set -uo pipefail
bin=${1:-build/asan/bin/smoke}
[[ -x $bin ]] || { echo "missing $bin (run: make BUILD=asan)"; exit 1; }
rc=0
check() { # check <flag> <expected-pattern>
  local out
  if out=$("$bin" "$1" 2>&1); then
    echo "FAIL: $1 exited 0, sanitizer did not trip"; rc=1; return
  fi
  if grep -q "$2" <<<"$out"; then echo "ok: $1 tripped ($2)"
  else echo "FAIL: $1 failed but without '$2'"; echo "$out" | head -5; rc=1; fi
}
check --asan-test  "AddressSanitizer"
check --ubsan-test "runtime error"
exit "$rc"
