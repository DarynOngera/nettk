#!/usr/bin/env bash
# Guided, annotated walkthrough of a lab topology.
# usage: sudo lab/wizard.sh <basic|bridge3|line4> [--text|--yes]
#   --text   print the whole tour without running anything (no root needed)
#   --yes    run without pausing between steps
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/learn/lib.sh"

topo=""
LEARN_TEXT=0
export WIZARD_YES=0
for a in "$@"; do
  case $a in
    --text) LEARN_TEXT=1 ;;
    --yes)  WIZARD_YES=1 ;;
    basic|bridge3|line4) topo=$a ;;
    *) echo "usage: sudo lab/wizard.sh <basic|bridge3|line4> [--text|--yes]" >&2; exit 2 ;;
  esac
done
[[ -n $topo ]] || { echo "usage: sudo lab/wizard.sh <basic|bridge3|line4> [--text|--yes]" >&2; exit 2; }
lesson="$here/learn/$topo.sh"
[[ -f $lesson ]] || { echo "no lessons for '$topo'" >&2; exit 2; }

if [[ $LEARN_TEXT != 1 ]]; then
  nt_require_root || exit 1
  nt_need ip tcpdump || exit 1
  current=$(cat "$NT_STATE" 2>/dev/null || true)
  if [[ -z $current ]]; then
    echo "lab is down. bring up '$topo' now? [y/N] "
    read -r k || exit 0
    [[ $k =~ ^[yY]$ ]] || { echo "aborting"; exit 0; }
    "$here/up.sh" "$topo" --force || exit 1
  elif [[ $current != "$topo" ]]; then
    echo "topology '$current' is up, this tour wants '$topo'. switch now? [y/N] "
    read -r k || exit 0
    [[ $k =~ ^[yY]$ ]] || { echo "aborting"; exit 0; }
    "$here/up.sh" "$topo" --force || exit 1
  fi
fi

# shellcheck source=./lab/learn/basic.sh
source "$lesson"
lesson_main

true