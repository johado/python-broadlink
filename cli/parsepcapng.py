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

global devices
devices = []
global conffile
conffile = os.path.dirname(sys.argv[0]) + '/broadlink.json'

filter = {
    'ip': '192.168.1.3'
#    'ip': '192.168.1.6'    
}
mydev = None

if os.path.isfile(conffile):
    with open(conffile, 'r') as json_file:
        jsonconfig = json.load(json_file)
        for devinfo in jsonconfig['devices']:
            dev = broadlink.devinfo2dev(devinfo)
            if dev.host == ( filter['ip'], 80 ):
                mydev = dev
            devices.append(dev)

fname = None


def decrypt_packet(dev, packet):
    aes = AES.new(bytes(dev.key), AES.MODE_CBC, bytes(dev.iv))
    encrypted = bytes(packet[0x38:])
    #print type(encrypted)
    #print encrypted
    if len(encrypted) % 16 != 0:
        pad = bytearray(len(encrypted) % 16)
        print "pad: %i" % len(pad)
        encrypted = encrypted + bytes(pad)
    payload = aes.decrypt(encrypted)
    return payload

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
                    #pprint(pIP)
                    #print(pIP.src)
                    if str(pIP.src) == filter['ip'] or str(pIP.dst) == filter['ip']:
                        print("TS:%d.%lu len %i" % (block.timestamp_high, block.timestamp_low, plen))
                        print("IP: %s -> %s" % (pIP.src, pIP.dst))
                        if UDP in pIP:
                            #pprint(pIP)
                            udp=pIP[UDP]
                            if Raw in udp:
                                raw=udp[Raw]
                                payload=raw.load
                                broadlink.dump_payload(payload, "raw")
                                if len(payload) > 0x38 and len(payload) - 0x38 > 16:
                                    decrypted = decrypt_packet(mydev, payload)
                                    broadlink.dump_payload(decrypted, "decrypted")

            else:
                print("Unhandled type: %s" % type(block))
                pprint(block)
