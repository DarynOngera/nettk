# Step engine for lab/wizard.sh. Source this file; do not execute it.
#
# A lesson script (lab/learn/<topo>.sh) is an ordered series of steps built
# from these helpers. Everything a step *explains* also goes to LEARN_LOG so a
# full guided transcript survives after the interactive run.
#
#   lesson_start <topo> <title>
#   step <title>                      begin a step (shows a heading)
#   why     <<EOF ... EOF             rationale, printed before any command
#   cmd     <verbatim command line>   the exact command being demonstrated
#   run     <host> <args...>          execute inside nt-<host>, print output
#   t_run   <host> <tool> <args...>   run one of our NT_LAB-gated tools
#   run_fail <host> <args...>         run that is expected to fail
#   expect  <pattern> <yes> [no]      annotate LAST_OUT against a pattern
#   note    <<EOF ... EOF             read-the-output guidance after a run
#   cap     <host> <if> <count> <probe host> <args...>  capture + decode via sniff
#   predict <<EOF ... EOF             multiple-choice, scored against the answer
#   report                             scores, patterns to review, where the log went
#
# Modes: with LEARN_TEXT=1 the wizard prints the whole tour including the
# expected results but runs nothing (root not needed). With WIZARD_YES=1 it
# runs without pausing for Enter.

# shellcheck shell=bash
LEARN_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck disable=SC2034
root=$(cd "$LEARN_DIR/../.." && pwd)
# shellcheck source=./lab/lib.sh
source "$root/lab/lib.sh"

LEARN_LOG="${LEARN_LOG:-/tmp/nt-wizard.log}"
LEARN_TEXT=${LEARN_TEXT:-0}
STEP_N=0
QUIZ_OK=0
QUIZ_TOTAL=0
LAST_RC=0
RUN_TOTAL=0
RUN_UNEXP=0
MISSES=()
LAST_OUT=""
BIN="$root/build/asan/bin"
[[ -x $BIN/ping ]] || BIN="$root/build/release/bin"

say() { printf '%s\n' "$*"; }

pause() {
  if [[ $LEARN_TEXT == 1 || ${WIZARD_YES:-0} == 1 ]]; then return 0; fi
  printf '  [Enter] continue, [q] quit > '
  local k
  read -r k || { printf '\n'; exit 0; }
  if [[ $k == q || $k == Q ]]; then say "wizard stopped. transcript kept in $LEARN_LOG"; exit 0; fi
}

_tangle() {
  local line
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line ]] && { say; echo >> "$LEARN_LOG"; continue; }
    printf '%s\n' "$line"
    echo "$line" >> "$LEARN_LOG"
  done
}

lesson_start() {
  local topo=$1 title=$2
  : > "$LEARN_LOG"
  echo "# $title (topology $topo, $(date --iso-8601=seconds))" > "$LEARN_LOG"
  say "==============================================================================="
  say "  LAB WIZARD :: $title   (topology: $topo)"
  if [[ $LEARN_TEXT == 1 ]]; then say "  --text mode: tour only, nothing is executed"; fi
  say "==============================================================================="
  say
}

step() {
  STEP_N=$((STEP_N + 1))
  say
  say "-------------------------------------------------------------------------------"
  say "  STEP $STEP_N   $*"
  say "-------------------------------------------------------------------------------"
  say
  echo >> "$LEARN_LOG"
  echo "== STEP $STEP_N  $* ==" >> "$LEARN_LOG"
  pause
}

# why: heredoc of rationale lines; shown with a "|" margin, then a pause.
why() {
  say "  why"
  _tangle | sed 's/^/    | /'
  say
  pause
}

# cmd: the verbatim command line, for reference. Not executed by the wizard.
cmd() {
  say "  \$ $*"
  echo "\$ $*" >> "$LEARN_LOG"
  pause
}

# run <host> <args...>: execute in nt-<host>, echo the real output (feedback).
run() {
  local host=$1; shift
  local out rc
  RUN_TOTAL=$((RUN_TOTAL + 1))
  say "  [$(nt_ns "$host")] \$ $*"
  echo "[$(nt_ns "$host")] \$ $*" >> "$LEARN_LOG"
  if [[ $LEARN_TEXT == 1 ]]; then
    say "  (text mode: not executed)"
    LAST_OUT=""
    return 0
  fi
  out=$(nt_ex "$host" "$@" 2>&1)
  rc=$?
  LAST_OUT=$out
  if [[ -n $out ]]; then
    printf '  %s\n' "$out" | sed 's/^/      /'
    echo "-- output --" >> "$LEARN_LOG"
    printf '%s\n' "$out" >> "$LEARN_LOG"
  else
    say "      (no output)"
    echo "-- output -- (empty)" >> "$LEARN_LOG"
  fi
  if [[ $rc -eq 0 ]]; then
    say "      [ok]"
  else
    say "      [exit $rc]"
  fi
  LAST_RC=$rc
  return "$rc"
}

# run_ok: a run that must succeed; a failure is flagged as unexpected.
run_ok() {
  local rc
  run "$@"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    RUN_UNEXP=$((RUN_UNEXP + 1))
    say "  !! unexpected failure (review the output above)"
  fi
  return "$rc"
}

# t_run <host> <tool> <args...>: our tools need NT_LAB=1 (guard).
t_run() {
  local host=$1 tool=$2; shift 2
  if [[ ! -x $BIN/$tool ]]; then
    say "  !! $tool not built ($BIN/$tool); make BUILD=asan all"
    return 1
  fi
  run "$host" env NT_LAB=1 "$BIN/$tool" "$@"
}

# run_fail: a deliberate break-and-debug step; non-zero exit is the point.
run_fail() {
  local rc
  run "$@"
  rc=$?
  if [[ $rc -eq 0 ]]; then
    RUN_UNEXP=$((RUN_UNEXP + 1))
    say "  !! that command unexpectedly succeeded (expected failure)"
    return 1
  fi
  return 0
}

# expect <pattern> <yes-text> [no-text]: annotate the last run's output.
expect() {
  local pat=$1 yes=${2:-} no=${3:-}
  if [[ -n $LAST_OUT && $LAST_OUT == *"$pat"* ]]; then
    say "  [check] output contains \`$pat\`  ->  $yes"
    echo "  [check-ok] $pat -> $yes" >> "$LEARN_LOG"
  else
    say "  [check] output does NOT contain \`$pat\`"
    [[ -n $no ]] && say "         $no"
    echo "  [check-miss] $pat $no" >> "$LEARN_LOG"
    MISSES+=("$pat")
  fi
}

# expect_none <yes-text> [no-text]: annotate that the last run produced no reply.
expect_none() {
  local yes=${1:-} no=${2:-}
  if [[ -z $LAST_OUT ]]; then
    say "  [check] no reply in output  ->  $yes"
    echo "  [check-ok] no-reply -> $yes" >> "$LEARN_LOG"
  else
    say "  [check] expected NO reply but saw output"
    [[ -n $no ]] && say "         $no"
    echo "  [check-miss] expected-none $no" >> "$LEARN_LOG"
    MISSES+=("expected-none")
  fi
}

# expect_absent <pattern> <yes-text> [no-text]: the pattern must NOT be present.
expect_absent() {
  local pat=$1 yes=${2:-} no=${3:-}
  if [[ -n $LAST_OUT && $LAST_OUT != *"$pat"* ]]; then
    say "  [check] output has no \`$pat\`  ->  $yes"
    echo "  [check-ok] absent $pat -> $yes" >> "$LEARN_LOG"
  else
    say "  [check] \`$pat\` should have been ABSENT"
    [[ -n $no ]] && say "         $no"
    echo "  [check-miss] wanted-absent $pat $no" >> "$LEARN_LOG"
    MISSES+=("absent-$pat")
  fi
}

# note: heredoc of read-the-output guidance.
note() {
  say "  note"
  _tangle | sed 's/^/      * /'
  say
  pause
}

# cap <caphost> <capif> <count> <probehost> <args...>
# Capture up to <count> frames on the interface while <probehost> runs the
# probe, then decode the pcap with our own `sniff -x` (offset annotations).
cap() {
  local caphost=$1 capif=$2 count=$3 probehost=$4; shift 4
  local f=/tmp/nt-wizard-cap.pcap sbin=$BIN/sniff
  if [[ ! -x $sbin ]]; then say "  !! sniff not built; make BUILD=asan all"; return 1; fi
  if ! command -v tcpdump >/dev/null 2>&1; then say "  !! tcpdump not installed"; return 1; fi
  say "  capture: up to $count frames on $(nt_ns "$caphost")/$capif while probing from $(nt_ns "$probehost")"
  echo "-- capture ns=$(nt_ns "$caphost") if=$capif count=$count probe=$(nt_ns "$probehost") $* --" >> "$LEARN_LOG"
  if [[ $LEARN_TEXT == 1 ]]; then
    LAST_OUT=""
    return 0
  fi
  rm -f "$f"
  nt_ex "$caphost" timeout "$((count + 4))" tcpdump -ni "$capif" -c "$count" -w "$f" >/dev/null 2>&1 &
  local pid=$!
  sleep 0.7
  nt_ex "$probehost" "$@" >/dev/null 2>&1 || true
  wait "$pid" 2>/dev/null || true
  if [[ ! -s $f ]]; then
    say "      (captured nothing)"
    LAST_OUT=""
    return 1
  fi
  say "      decoded with our sniffer (-x, offsets are byte positions in the frame):"
  LAST_OUT=$("$sbin" -r "$f" -x 2>&1)
  printf '%s\n' "$LAST_OUT" | sed 's/^/      /'
  echo "$LAST_OUT" >> "$LEARN_LOG"
  return 0
}

# predict: heredoc with
#   <question>
#   a) choice  b) choice ...
#   answer <letter>
#   because <the systems-level reason>      (printed after the result)
predict() {
  local line answer="" reason="" q=""
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == answer\ * ]]; then answer=${line#answer }
    elif [[ $line == because\ * ]]; then reason=${line#because }
    else q+="$line"$'\n'; fi
  done
  q=${q%$'\n'}
  say
  say "  PREDICT"
  printf '%s\n' "$q" | sed 's/^/      /'
  echo "-- predict --" >> "$LEARN_LOG"
  echo "$q" >> "$LEARN_LOG"
  local got=""
  if [[ $LEARN_TEXT == 1 ]]; then
    say "      (answer: ${answer})"
    return 0
  fi
  QUIZ_TOTAL=$((QUIZ_TOTAL + 1))
  while :; do
    printf '  your answer [a-z]> '
    read -r got || { printf '\n'; return 0; }
    if [[ $got =~ ^[a-z]$ ]]; then break; fi
  done
    if [[ $got == "$answer" ]]; then
      QUIZ_OK=$((QUIZ_OK + 1))
      say "  [predict] correct."
      echo "  [predict-ok] $got" >> "$LEARN_LOG"
    else
      say "  [predict] not quite. Correct answer: ${answer}."
      MISSES+=("predict-$answer")
      echo "  [predict-miss] got=$got want=$answer" >> "$LEARN_LOG"
    fi
  [[ -n $reason ]] && { say "      because $reason"; echo "  [because] $reason" >> "$LEARN_LOG"; }
  say
  pause
}

report() {
  say
  say "==============================================================================="
  say "  WIZARD COMPLETE ($STEP_N steps)"
  if [[ $QUIZ_TOTAL -gt 0 ]]; then
    say "  predictions correct: $QUIZ_OK / $QUIZ_TOTAL"
  fi
  say "  commands run: $RUN_TOTAL; failures the lesson did not ask for: $RUN_UNEXP"
  if [[ ${#MISSES[@]} -gt 0 ]]; then
    say "  review these patterns: ${MISSES[*]}"
  fi
  say "  full transcript: $LEARN_LOG"
  say "==============================================================================="
  say
}