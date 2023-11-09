#!/usr/bin/env python3

import time
from scapy.all import sniff, wrpcap

def packet_callback(packet):
    packets.append(packet)

def save_packets():
    filename = f"network_traffic_{time.strftime('%Y%m%d%H%M%S')}.pcap"
    wrpcap(filename, packets)
    print(f"Captured data saved to {filename}")
    del packets[:]

if __name__ == "__main__":
    packets = []

    try:
        while True:
            sniff(prn=packet_callback, store=False, timeout=10)
            save_packets()

    except KeyboardInterrupt:
        print("Sending kill signal, script will stop within 10s.")
        save_packets()
        exit(0)
