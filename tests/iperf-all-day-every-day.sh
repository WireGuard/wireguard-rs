#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
#
# This script tests the below topology:
#
# ┌─────────────────────┐   ┌──────────────────────────────────────────┐   ┌─────────────────────┐
# │   $ns1 namespace    │   │              $ns0 namespace              │   │   $ns2 namespace    │
# │                     │   │                                          │   │                     │
# │┌────────┐           │   │                ┌────────┐                │   │           ┌────────┐│
# ││  wg1   │───────────┼───┼────────────────│   lo   │────────────────┼───┼───────────│  wg2   ││
# │├────────┴──────────┐│   │    ┌───────────┴────────┴────────────┐   │   │┌──────────┴────────┤│
# ││192.168.241.1/24   ││   │    │(ns1)             (ns2)          │   │   ││192.168.241.2/24   ││
# ││fd00::1/24         ││   │    │127.0.0.1:10000   127.0.0.1:20000│   │   ││fd00::2/24         ││
# │└───────────────────┘│   │    │[::]:10000        [::]:20000     │   │   │└───────────────────┘│
# └─────────────────────┘   │    └─────────────────────────────────┘   │   └─────────────────────┘
#                           └──────────────────────────────────────────┘
#
# After the topology is prepared we run a series of TCP/UDP iperf3 tests between the
# wireguard peers in $ns1 and $ns2. Note that $ns0 is the endpoint for the wg1
# interfaces in $ns1 and $ns2. See https://www.wireguard.com/netns/ for further
# details on how this is accomplished.

# This code is ported for wireguard-rs from wireguard-go, which was in turn directly
# from the kernel project.
#
# Please ensure that you have installed the newest version of the WireGuard
# tools from the WireGuard project and before running these tests as:
#
# ./netns.sh <path to wireguard-rs>

set -e

exec 3>&1
export WG_HIDE_KEYS=never
netns0="wg-test-0"
netns1="wg-test-1"
netns2="wg-test-2"

pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
info() { echo -e "\x1b[32m[~] "$@" \x1b[0m" >&3; }
warn() { echo -e "\x1b[31m\x1b[1m[!] "$@" \x1b[0m" >&3; }
section() { echo -e "\x1b[1m[*] SECTION: "$@" \x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
maybe_exec() { if [[ $BASHPID -eq $$ ]]; then "$@"; else exec "$@"; fi; }
n0() { pretty 0 "$*"; maybe_exec ip netns exec $netns0 "$@"; }
n1() { pretty 1 "$*"; maybe_exec ip netns exec $netns1 "$@"; }
n2() { pretty 2 "$*"; maybe_exec ip netns exec $netns2 "$@"; }
ip0() { pretty 0 "ip $*"; ip -n $netns0 "$@"; }
ip1() { pretty 1 "ip $*"; ip -n $netns1 "$@"; }
ip2() { pretty 2 "ip $*"; ip -n $netns2 "$@"; }
sleep() { read -t "$1" -N 0 || true; }
waitiperf() { pretty "${1//*-}" "wait for iperf:5201"; while [[ $(ss -N "$1" -tlp 'sport = 5201') != *iperf3* ]]; do sleep 0.1; done; }
waitncatudp() { pretty "${1//*-}" "wait for udp:1111"; while [[ $(ss -N "$1" -ulp 'sport = 1111') != *ncat* ]]; do sleep 0.1; done; }
waitncattcp() { pretty "${1//*-}" "wait for tcp:1111"; while [[ $(ss -N "$1" -tlp 'sport = 1111') != *ncat* ]]; do sleep 0.1; done; }
waitiface() { pretty "${1//*-}" "wait for $2 to come up"; ip netns exec "$1" bash -c "while [[ \$(< \"/sys/class/net/$2/operstate\") != up ]]; do read -t .1 -N 0 || true; done;"; }

for arg in "$@"; do
  shift
  case "$arg" in
    "--iperf"|"--iperf3") use_iperf=1 ;;
    *)        program="$arg"
  esac
done

if [ $program ]; then
    info "using $program as userspace wireguard."
fi

if [ $use_iperf ]; then
    info "including iperf tests."
else
    info "skipping iperf tests."
fi

create() {
    if [ $program ]; then
        echo "$program $1"
    else
        echo "ip link add dev $1 type wireguard"
    fi
}

cleanup() {
    set +e
    exec 2>/dev/null
    printf "$orig_message_cost" > /proc/sys/net/core/message_cost
    ip0 link del dev wg0
    ip1 link del dev wg1
    ip2 link del dev wg2
    local to_kill="$(ip netns pids $netns0) $(ip netns pids $netns1) $(ip netns pids $netns2)"
    [[ -n $to_kill ]] && kill $to_kill
    pp ip netns del $netns1
    pp ip netns del $netns2
    pp ip netns del $netns0
    exit
}

error() {
    local code="${3:-1}"
    warn "Test failed at line $1."
    exit "${code}"
}

orig_message_cost="$(< /proc/sys/net/core/message_cost)"
trap 'error ${LINENO}' ERR
trap cleanup EXIT
printf 0 > /proc/sys/net/core/message_cost

ip netns del $netns0 2>/dev/null || true
ip netns del $netns1 2>/dev/null || true
ip netns del $netns2 2>/dev/null || true
pp ip netns add $netns0
pp ip netns add $netns1
pp ip netns add $netns2
ip0 link set up dev lo

n0 $(create wg1)
sleep 0.5
ip0 link set wg1 netns $netns1

n0 $(create wg2)
sleep 0.5
ip0 link set wg2 netns $netns2

key1="$(pp wg genkey)"
key2="$(pp wg genkey)"
pub1="$(pp wg pubkey <<<"$key1")"
pub2="$(pp wg pubkey <<<"$key2")"
psk="$(pp wg genpsk)"
[[ -n $key1 && -n $key2 && -n $psk ]]

configure_peers() {
    ip1 addr add 192.168.241.1/24 dev wg1
    ip1 addr add fd00::1/24 dev wg1

    ip2 addr add 192.168.241.2/24 dev wg2
    ip2 addr add fd00::2/24 dev wg2

    n1 wg set wg1 \
        private-key <(echo "$key1") \
        listen-port 10000 \
        peer "$pub2" \
            preshared-key <(echo "$psk") \
            allowed-ips 192.168.241.2/32,fd00::2/128
    n2 wg set wg2 \
        private-key <(echo "$key2") \
        listen-port 20000 \
        peer "$pub1" \
            preshared-key <(echo "$psk") \
            allowed-ips 192.168.241.1/32,fd00::1/128

    ip1 link set up dev wg1
    ip2 link set up dev wg2
    sleep 1
}
configure_peers

tests() {
    # TCP over IPv4
    n2 iperf3 -s -1 -B 192.168.241.2 &
    waitiperf $netns2
    n1 iperf3 -Z -t 3 -c 192.168.241.2
}

[[ $(ip1 link show dev wg1) =~ mtu\ ([0-9]+) ]] && orig_mtu="${BASH_REMATCH[1]}"
big_mtu=$(( 34816 - 1500 + $orig_mtu ))

# Test using IPv4 as outer transport
section "IPv4 as outer transport"
n1 wg set wg1 peer "$pub2" endpoint 127.0.0.1:20000
n2 wg set wg2 peer "$pub1" endpoint 127.0.0.1:10000

while [[ true ]]
do
	tests
done

