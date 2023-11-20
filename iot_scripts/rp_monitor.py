#!/usr/bin/env python3

import os
import time
import signal
from scapy.all import sniff, wrpcap

def save_packets():
    filename = f"./network_traffic/{time.strftime('%Y%m%d%H%M%S')}.pcap"
    wrpcap(filename, packets)
    del packets[:]

    print(f"Captured data saved to {filename}")

def monitor():
    while True:
        sniff(prn=lambda x: packets.append(x), store=False, timeout=10)
        save_packets()

def on_exit(sig, frame):
    save_packets()
    print("Stopped packet monitoring")
    exit(0)

if __name__ == "__main__":
    # Setup data
    packets = []
    os.makedirs("./network_traffic", exist_ok=True)

    # Setup exit signal handler
    signal.signal(signal.SIGINT, on_exit)

    print("Starting packet monitoring")
    monitor()