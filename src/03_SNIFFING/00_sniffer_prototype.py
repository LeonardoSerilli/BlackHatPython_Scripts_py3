#!/usr/bin/python3
import socket
import os

#### [!!!] The following script works on both linux and windows, 
        # it capture IPv4 packets on windows
        # and ICMP packets on Linux.
        # it require admin privileges !

# --------------------------------------------------------------#

# some Theory:
    # [1] PROMISCOUS MODE -> 
        # is a feature of some network interfaces that allows 
        # them to receive all packets on the network, rather than just those 
        # packets intended for the host's IP address. 
        # This can be useful for network monitoring and troubleshooting.
    # [2] CAPTURE IP (windows)->
        # On Windows, the ability to capture ICMP packets using raw sockets is restricted by
        # the operating system for security reasons.
        # Windows uses a different mechanism to handle ICMP packets, 
        # known as ICMP Sockets, which provides a more secure way of handling ICMP
        # packets, and does not allow capturing of all ICMP packets using raw sockets.
    # [3] CAPTURE ICMP (Linux/Unix) -> 
        # if you want to capture ICMP packets on Linux 
        # and Unix-like systems, you should use the socket.IPPROTO_ICMP protocol,
        # if you want to capture all IP packets, regardless of their upper-layer protocol,
        # you should use the socket.IPPROTO_RAW protocol.

HOST = '192.168.1.93' # sniffed interface 

def main():
    
    # create a socket binding to the network interface 
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP # IPv4 on Windows [2]
    else: 
        socket_protocol = socket.IPPROTO_ICMP # ICMP on Linux [3]
        
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0)) # 0 bind the socket to all port
    
    # include the IP headers in packets 
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # on windows ->  ioctl (Input/Output Control) is used to enable promiscuous mode... [1]
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    # sniff a single packet 
    print(sniffer.recvfrom(65565)[0])

    # ...on windows -> turn off the promiscouos mode [1]
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
if __name__ == '__main__':
    main()