#!/usr/bin/env bash
# Guided, annotated walkthrough of a lab topology or a lesson.
# usage: sudo lab/wizard.sh <lesson> [--text|--yes]
#        lab/wizard.sh --list                 list lessons and their topology
#   <lesson> is a file in lab/learn/ (basic, line4, bridge3, sockets, ...).
#   A lesson may set LESSON_TOPO to the topology it needs; the default is its
#   own name. That keeps each sub-phase's tour out of the topology list.
#   --text   print the whole tour without running anything (no root needed)
#   --yes    run without pausing between steps
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/learn/lib.sh"

usage() { echo "usage: sudo lab/wizard.sh <lesson> [--text|--yes]   (--list to list lessons)" >&2; }

list_lessons() {
  local f name
  for f in "$here"/learn/*.sh; do
    name=$(basename "$f" .sh)
    [[ $name == lib ]] && continue
    # Sourcing runs nothing: a lesson only assigns TOPIC/LESSON_TOPO and defines
    # lesson_main(). Do it in a subshell so the parent stays clean.
    ( unset LESSON_TOPO
      # shellcheck disable=SC1090
      source "$f" >/dev/null 2>&1
      printf '  %-10s topology=%s\n' "$name" "${LESSON_TOPO:-$name}" )
  done
}

lesson=""
LEARN_TEXT=0
export WIZARD_YES=0
for a in "$@"; do
  case $a in
    --list|-l) list_lessons; exit 0 ;;
    --text) LEARN_TEXT=1 ;;
    --yes)  WIZARD_YES=1 ;;
    -*) echo "unknown option '$a'" >&2; usage; exit 2 ;;
    *) [[ -n $lesson ]] && { echo "only one lesson at a time" >&2; usage; exit 2; }
       lesson=$a ;;
  esac
done
[[ -n $lesson ]] || { usage; exit 2; }

lesson_file="$here/learn/$lesson.sh"
[[ -f $lesson_file ]] || {
  echo "unknown lesson '$lesson'. available:" >&2
  list_lessons >&2
  exit 2
}

# The lesson declares its topology; default is its own name (basic/line4/bridge3).
unset LESSON_TOPO
# shellcheck source=/dev/null
source "$lesson_file"
topo=${LESSON_TOPO:-$lesson}
[[ -f "$here/topo/$topo.sh" ]] || {
  echo "lesson '$lesson' needs topology '$topo' (lab/topo/$topo.sh missing)" >&2
  exit 2
}

if [[ $LEARN_TEXT != 1 ]]; then
  nt_require_root || exit 1
  nt_need ip tcpdump || exit 1
  current=$(cat "$NT_STATE" 2>/dev/null || true)
  if [[ -z $current ]]; then
    if [[ ${WIZARD_YES:-0} == 1 || ! -t 0 ]]; then
      echo "lab is down. bringing up '$topo'..."
      "$here/up.sh" "$topo" --force || exit 1
    else
      echo "lab is down. bring up '$topo' now? [y/N] "
      read -r k || { echo "aborting"; exit 0; }
      [[ $k =~ ^[yY]$ ]] || { echo "aborting"; exit 0; }
      "$here/up.sh" "$topo" --force || exit 1
    fi
  elif [[ $current != "$topo" ]]; then
    if [[ ${WIZARD_YES:-0} == 1 || ! -t 0 ]]; then
      echo "topology '$current' is up, switching to '$topo'..."
      "$here/up.sh" "$topo" --force || exit 1
    else
      echo "topology '$current' is up, this tour wants '$topo'. switch now? [y/N] "
      read -r k || { echo "aborting"; exit 0; }
      [[ $k =~ ^[yY]$ ]] || { echo "aborting"; exit 0; }
      "$here/up.sh" "$topo" --force || exit 1
    fi
  fi
fi

lesson_main

true
