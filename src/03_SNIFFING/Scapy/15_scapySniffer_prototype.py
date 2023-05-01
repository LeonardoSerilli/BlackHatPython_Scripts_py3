#!/usr/bin/python3

from scapy.all import sniff #https://scapy.net/

def packetCallback(packet):
    print(packet.show())
    
def main():
    sniff(prn=packetCallback, count=1)

if __name__ == "__main__":
    main()