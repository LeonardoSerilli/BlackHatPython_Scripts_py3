#!/usr/bin/python3
import struct
import ipaddress
import socket
import time 
import os 
import sys 
import threading

SUBNET = "192.168.1.0/24"
MESSAGE = "Wabbalubba dub dub!"

# IP packet decoder class using the Struct lib
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

# ICMP packet decoder class using the Struct lib
class ICMP:
    # buff contains the sniffed binary data
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHH', buff) # returns a tuple containing the unpacked data
        
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]
        
        
def udp_sender(ports_to_scan):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
                for port in ports_to_scan:
                    time.sleep(1)
                    sender.sendto(bytes(MESSAGE, 'utf-8'), (str(ip), port))
class Scanner():
    def __init__(self, host):
        
        # create the scanner as a socket binded to the network interface 
        self.host = host
        
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP # IPv4 on Windows 
        else: 
            socket_protocol = socket.IPPROTO_ICMP # ICMP on Linux 
            
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0)) # 0 bind the socket to all port
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # include the IP headers in packets 
        
        # on windows ->  ioctl (Input/Output Control) is used to enable promiscuous mode... 
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        
    def sniff(self):
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                raw_buffer = self.socket.recvfrom(65565)[0]
                ip_header = IP(raw_buffer[0:20]) # decode the first 20 bytes of the raw ip packet
                
                # The Internet Control Message Protocol (ICMP) message is typically encapsulated in an IP packet.
                    # ICMP is used to send error and control messages between IP-enabled devices, such as routers and computers.
                    # When a device sends an ICMP message, it is sent as data within an IP packet, with the IP header indicating
                    # that the payload of the packet is an ICMP message. 
                    # This allows ICMP messages to be transmitted over a network and to be processed by IP-enabled devices.
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    buff = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buff)

                    # check if the packet has a 'destination unreachable' code and type (why? boh)
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        # check if the packet comes from the scanned subnet 
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            # check if the define message is contained in the reply
                            if(raw_buffer[len(raw_buffer) - len(MESSAGE): ] == bytes(MESSAGE, "utf-8")):
                                hosts_up.add(str(ip_header.src_address))
                                print(f'Host up: {(str(ip_header.src_address))}')
    
        except KeyboardInterrupt:
            # ...on windows -> turn off the promiscouos mode 
            if os.name == 'nt':
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                
            print("\nuser interrupted.")
            if hosts_up:
                print("Hosts up discovered on {SUBNET}")  
            for host in sorted(hosts_up):
                print(f'{host}')    
            print('')
            sys.exit()      
        
        
if __name__ == '__main__':
    
    ports_to_scan = [65212, 4523]

    if len(sys.argv) == 2:
        host = sys.argv[2]
    else:
        host = '192.168.1.93'
    
    s = Scanner(host)    
    time.sleep(10)
    t = threading.Thread(target = udp_sender, args=([ports_to_scan]))
    t.start()
    s.sniff()
        