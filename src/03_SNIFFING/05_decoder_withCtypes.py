#!/usr/bin/python3

import os
import socket
import struct
import sys
import ipaddress
from ctypes import *

class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong)
    ]
    
    # Override to create a new instance of the IP class and initialize the buffer
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer) #  creates a new instance and copies the contents of the buffer into it. 
    
    # Perform additional initialization on the newly created instance
    def __init__(self, socket_buffer=None):
                
        # convert the raw binary IP src and dst addresses from the buffer into human-readable string format
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        
        # extract the protocol
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

# same test as 05_decoder_withStruct.py

encoded_pkt = b'\x45\x00\x00\x14\x00\x00\x40\x00\x40\x01\xc0\xa8\x00\xbb\xc0\xa8\x00\x01\x01\x01\x45\x00\x00\x14\x00\x00\x40\x00\x40\x01\xc0\xa8\x00\xbb\xc0\xa8\x00\x01\x01\x01'
decoded_pkt = IP(encoded_pkt)

print("Version: ", decoded_pkt.version)
print("IHL: ", decoded_pkt.ihl)
print("TOS: ", decoded_pkt.tos)
print("Length: ", decoded_pkt.len)
print("Offset: ", decoded_pkt.offset)
print("TTL: ", decoded_pkt.ttl)
print("Protocol: ", decoded_pkt.protocol_num)
print("Checksum: ", decoded_pkt.sum)
print("Source IP: ", ipaddress.IPv4Address(decoded_pkt.src))
print("Destination IP: ", ipaddress.IPv4Address(decoded_pkt.dst))