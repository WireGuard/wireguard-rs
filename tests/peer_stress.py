#!/usr/bin/env python3

import base64
import subprocess
import ipaddress
import os
import nacl.utils
import sys
from nacl.public import PrivateKey
from tqdm import tqdm
from timeit import default_timer as timer

NETWORK=ipaddress.ip_network('10.99.0.0/16')

def shell(cmd, input=''):
    return subprocess.run(cmd.split(' '), input=input.encode('utf-8'), stdout=subprocess.PIPE)

class Peer:
    def __init__(self, ip):
        privkey = PrivateKey.generate()
        self.privkey = base64.b64encode(bytes(privkey)).decode('utf-8')
        self.pubkey = base64.b64encode(bytes(privkey.public_key)).decode('utf-8')
        self.ip = ip

if os.geteuid() != 0:
    print("must be root.")
    exit()

peers = []
hosts = list(NETWORK.hosts())

print("generating {} peers".format(len(hosts)))

gen_start = timer()
for ip in tqdm(hosts):
    peers.append(Peer(ip))
gen_end = timer()

print("finished generating in {:.2f}".format(gen_end - gen_start))

if len(sys.argv) > 1:
    print("using " + sys.argv[1])
    print(shell(sys.argv[1] + " utun8").stdout.decode('utf-8').strip())
else:
    print("using kernel wireguard")
    shell("ip link add dev utun8 type wireguard").check_returncode()

add_start = timer()
print("adding peers to device")
cmds = []
for peer in tqdm(peers):
    cmds.append("peer {} allowed-ips {}/32".format(peer.pubkey, peer.ip))
    if len(cmds) > 1000:
        ret = shell("wg set utun8 " + ' '.join(cmds))
        if ret.returncode != 0:
            print("ERROR " + ret.stdout.decode('utf-8').strip())
            exit()
        cmds = []
if len(cmds) > 0:
    shell("wg set utun8 " + ' '.join(cmds))
add_end = timer()

print("finished adding in {:.2f}".format(add_end - add_start))

# print("destroying interface")
# os.remove("/var/run/wireguard/utun8.sock")
