#!/usr/bin/env python

# pip install python-pcapng
# pip install scapy

import sys
import os
import broadlink
import json
from pprint import pprint
import pcapng
from scapy.all import *
#import scapy

# The offset here are from the decrypted payload (from 0x38)
blcmds0x6a = [
    {
        'name' : 'set_name ',
        'decrypt': True,
        'ofs' : 0x0,
        'data': [ 0x00 ],
        'sub': [
            {
                'name': 'name:',
                'decrypt': True,
                'ofs': 4,
                'len': 32,
                'type': 'str'
            }
        ]
    },
    {
        'name' : 'get_power ',
        'decrypt': True,
        'ofs' : 0x0,
        'data': [ 0x01 ],
        'sub': [
            {
                'name': 'powerstate:',
                'decrypt': True,
                'ofs': 4,
                'len': 1,
                'type': 'int'
            }
        ]
    },

    {
        'name' : 'set_power ',
        'decrypt': True,
        'ofs' : 0x0,
        'data': [ 0x02 ],
        'sub': [
            {
                'name': 'powerstate:',
                'decrypt': True,
                'ofs': 4,
                'len': 1,
                'type': 'int'
            }
        ]

    },
    ]

pkginfo = [
    {
        'name' : 'broadlink header ',
        'ofs' : 0,
        'data': [ 0x5a, 0xa5, 0xaa, 0x55, 0x5a, 0xa5, 0xaa, 0x55],
        'sub': [ {
            'name': 'cmd 0x6a ',
            'ofs' : 0x26,
            'data': [0x6a],
            'sub': blcmds0x6a
        },
        {
            'name': 'cmd 07 (discovery?) ',
            'ofs' : 0x26,
            'data': [0x07],
            'sub': [
                {
                    'name': 'name:',
                    'ofs': 0x40,
                    'len': 32, # Could be up to 62?
                    'type': 'str'
                }
            ]
        }
        ]
    }
]


global devices
devices = []
global conffile
conffile = os.path.dirname(sys.argv[0]) + '/broadlink.json'

filter = {
    'ip': [
        '192.168.1.3',
        '192.168.1.6',
        '192.168.1.4'
    ]
}
mydev = None
devbyip = {}
if os.path.isfile(conffile):
    with open(conffile, 'r') as json_file:
        jsonconfig = json.load(json_file)
        for devinfo in jsonconfig['devices']:
            dev = broadlink.devinfo2dev(devinfo)
            (ip, _port ) = dev.host
            devbyip[ip] = dev
            devices.append(dev)

fname = None

def parse_packet(pkginfo, payload, encrypted):
    info = ''
    for pkg in pkginfo:
        if len(pkg.get('data', [])):
            if pkg.get('decrypt', False):
                if encrypted[pkg['ofs']:pkg['ofs']+len(pkg['data'])] == "".join(map(chr,pkg['data'])):
                    info = pkg['name']
                    info += parse_packet(pkg.get('sub', []), payload, encrypted)
            else:
                if payload[pkg['ofs']:pkg['ofs']+len(pkg['data'])] == "".join(map(chr,pkg['data'])):
                    info = pkg['name']
                    info += parse_packet(pkg.get('sub', []), payload, encrypted)
        elif pkg.get('type'):
            if pkg.get('decrypt', False):
                value = encrypted[pkg['ofs']:pkg['ofs']+pkg['len']]
            else:
                value = payload[pkg['ofs']:pkg['ofs']+pkg['len']]
            if pkg.get('type') == 'str':
                info += "%s %s" % (pkg['name'], broadlink.data2str(value))
            elif pkg.get('type') == 'int':
                info += "%s %i" % (pkg['name'], int(broadlink.byteval(value)))
            else:
                print "Unhandled type: %s" % pkg.get('type')
                exit(1)
    #print "info so far: %s" % info
    return info


def decrypt_packet(dev, packet):
    aes = AES.new(bytes(dev.key), AES.MODE_CBC, bytes(dev.iv))
    encrypted = bytes(packet[0x38:])
    #print type(encrypted)
    #print encrypted
    if len(encrypted) % 16 != 0:
        pad = bytearray(len(encrypted) % 16)
        encrypted = encrypted + bytes(pad)
    payload = aes.decrypt(encrypted)
    return payload

def usage():
    print "-f pcapfile"


if len(sys.argv) > 1:
    arg = 1
    while arg < len(sys.argv):
        if sys.argv[arg] == '-h':
            usage()
            exit(0)
        elif sys.argv[arg] == '-f':
            arg = arg + 1
            fname = sys.argv[arg]
        else:
            print "Unknown argument: %s" % (sys.argv[arg])
        arg = arg + 1            

with open(fname) as fp:
        scanner = pcapng.FileScanner(fp)
        for block in scanner:
            if isinstance(block, pcapng.blocks.SectionHeader):
                pass
            elif isinstance(block, pcapng.blocks.InterfaceDescription):
                print("Options: %s" % block.options)
            elif isinstance(block, pcapng.blocks.EnhancedPacket):
                (clen, plen, data ) = block.packet_payload_info
                p=scapy.all.Ether(data)
                if IP in p:
                    pIP = p[IP]
                    #pprint(p)
                    #print(pIP.src)
                    if str(pIP.src) in filter['ip'] or str(pIP.dst) in filter['ip']:
                        mydev = devbyip.get(str(pIP.src), devbyip.get(str(pIP.dst), None))
                        sport='?'
                        dport='?'
                        if UDP in pIP:
                            prot='UDP'
                            sport=str(pIP[UDP].sport)
                            dport=str(pIP[UDP].dport)
                        elif TCP in pIP:
                            prot='TCP'
                            sport=str(pIP[TCP].sport)
                            dport=str(pIP[TCP].dport)
                        elif ICMP in pIP:
                            prot='ICMP'
                        else:
                            prot='Unknown'
                            pprint(p)
                        print("TS:%d.%lu len %i" % (block.timestamp_high, block.timestamp_low, plen))
                        print("Ether: %s -> %s %s: %s:%s -> %s:%s" % (p.src, p.dst, prot, pIP.src, sport, pIP.dst, dport))
                        if UDP in pIP:
                            #pprint(pIP)
                            udp=pIP[UDP]
                            if Raw in udp:
                                raw=udp[Raw]
                                payload=raw.load
                                broadlink.dump_payload(payload, "raw")
                                decrypted = None
                                if mydev and len(payload) > 0x38 and broadlink.byteval(payload[0x26]) != 0x07:
                                    decrypted = decrypt_packet(mydev, payload)
                                    broadlink.dump_payload(decrypted, "decrypted")
                                print parse_packet(pkginfo, payload, decrypted)

            else:
                print("Unhandled type: %s" % type(block))
                pprint(block)
