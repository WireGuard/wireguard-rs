#!/bin/bash

killall rabbittun

cargo run -- wg0 -v debug || exit -1
sleep 0.1
ps -A | grep rabbittun || exit -1

wg genkey > /tmp/wg0.sk
wg genkey > /tmp/peer.sk
cat /tmp/peer.sk | wg pubkey > /tmp/peer.pk

echo "Secret Key"
cat /tmp/wg0.sk

echo "Peer Secret Key"
cat /tmp/peer.sk

echo "Peer Public Key"
cat /tmp/peer.pk

sudo wg set wg0 listen-port 8888 private-key /tmp/wg0.sk
sudo wg

sudo wg set wg0 peer $(cat /tmp/peer.pk) allowed-ips 192.168.88.0/24 endpoint 127.0.0.1:7777
sudo wg

echo "Shutting Down"

killall rabbittun

sleep 0.1

cat /tmp/rabbittun.err
cat /tmp/rabbittun.out
