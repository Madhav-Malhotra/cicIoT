#!/usr/bin/env python3

import os
import time
from scapy.all import sniff, wrpcap

def packet_callback(packet):
    packets.append(packet)

def save_packets():
    filename = f"./network_traffic/{time.strftime('%Y%m%d%H%M%S')}.pcap"
    wrpcap(filename, packets)
    print(f"Captured data saved to {filename}")
    del packets[:]

def monitor():
    while True:
        try:
            sniff(prn=packet_callback, store=False, timeout=10)
        except KeyboardInterrupt:
            break
        save_packets()

if __name__ == "__main__":
    packets = []
    print("Starting packet monitoring")

    # If ./network_traffic doesn't exist, create it
    os.makedirs("./network_traffic", exist_ok=True)

    try:
        monitor()
    except KeyboardInterrupt:
        print("Stopping packet monitoring.")