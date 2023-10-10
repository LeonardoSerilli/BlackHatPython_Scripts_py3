#!/usr/bin/python3

from scapy.all import sniff  # https://scapy.net/


def packetCallback(packet):
    print(packet.show())


def main():
    # Simply sniff one packet, and send it to the callback function
    sniff(prn=packetCallback, count=1)


if __name__ == "__main__":
    main()
