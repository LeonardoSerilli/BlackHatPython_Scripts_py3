#!/usr/bin/python3
import struct
import ipaddress


''' The information is packed into binary form, and as shown above, is quite difficult to understand. 
We are now going to work on decoding the IP portion of a packet so that we
can pull useful information out such as the protocol type (TCP, UDP, ICMP), and the source and
destination IP addresses. This will be the foundation for you to start creating further protocol parsing
later on
'''

class IP:
    
    # buff contains the sniffed binary data
    def __init__(self, buff=None):
        
        ''' <BBHHHBBH4s4s', which means the data should be interpreted as:
            <: little-endian byte order
            B: an unsigned char (1 byte)
            H: an unsigned short (2 bytes)
            4s: a string of 4 bytes '''
        
        header = struct.unpack('<BBHHHBBH4s4s', buff) # returns a tuple containing the unpacked data
        
        self.ver = header[0] >> 4 # Take the 4 less significant bit of the first byte
        self.ihl = header[0] & 0xF #  Take the 4 most significant bit of the first byte
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]
        
        # human readable addresses 
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)
        
        # extract the protocol
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            # if no protocol found 
            self.protocol = str(self.protocol_num)


# same test as 05_decoder_withCtypes.py

encoded_pkt = b'\x45\x00\x00\x14\x00\x00\x40\x00\x40\x01\xc0\xa8\x00\xbb\xc0\xa8\x00\x01\x01\x01'

decoded_pkt = IP(encoded_pkt)

print("Version: ", decoded_pkt.ver)
print("IHL: ", decoded_pkt.ihl)
print("TOS: ", decoded_pkt.tos)
print("Length: ", decoded_pkt.len)
print("ID: ", decoded_pkt.id)
print("Offset: ", decoded_pkt.offset)
print("TTL: ", decoded_pkt.ttl)
print("Protocol: ", decoded_pkt.protocol_num)
print("Checksum: ", decoded_pkt.sum)
print("Source IP: ", ipaddress.IPv4Address(decoded_pkt.src))
print("Destination IP: ", ipaddress.IPv4Address(decoded_pkt.dst))




