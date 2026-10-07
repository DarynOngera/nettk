#!/usr/bin/env bash
# Check (default) or install (--install, Debian/Ubuntu) the lab toolchain.
set -euo pipefail
tools=(ip ping tcpdump tshark ethtool nft nmap hping3 dnsmasq python3 gcc make)
missing=()
for t in "${tools[@]}"; do
  command -v "$t" >/dev/null 2>&1 || missing+=("$t")
done
python3 -c 'import scapy' 2>/dev/null || missing+=("scapy(python3-scapy)")
command -v clang >/dev/null 2>&1 || echo "note: clang not found (only needed for 'make fuzz')"
if [[ ${#missing[@]} -eq 0 ]]; then echo "all required tools present"; exit 0; fi
echo "missing: ${missing[*]}"
if [[ ${1:-} == --install ]]; then
  sudo apt update
  sudo apt install -y iproute2 iputils-ping tcpdump tshark ethtool nftables nmap hping3 \
       dnsmasq python3 python3-scapy build-essential clang
else
  echo "run: lab/deps.sh --install   (apt-based systems)"
  exit 1
fi
