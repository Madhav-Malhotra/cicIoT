import os
import time
import RPi.GPIO as GPIO
from feat_extract.Feature_extraction import Feature_extraction
from rp_analyse import check_benign

# Setup output pins
GPIO.setmode(GPIO.BCM)
ben_pin = 22
mal_pin = 23
mon_pin = 24
GPIO.setup(ben_pin, GPIO.OUT)
GPIO.setup(mal_pin, GPIO.OUT)
GPIO.setup(mon_pin, GPIO.OUT)


def analyze_pcap_file(file_path):
    '''
    Converts pcap to CSV and runs negative selection algorithm
    '''
    
    # Create CSV
    print(f"Analyzing {file_path}")
    fe.pcap_evaluation(file_path, file_path[:-5])

    # Run negative selection, show results
    benign = check_benign(file_path[:-5] + ".csv")
    for b in list(benign):
        GPIO.output(ben_pin if b else mal_pin, GPIO.HIGH)
        time.sleep(0.1)
        GPIO.output(ben_pin if b else mal_pin, GPIO.LOW)

def monitor_directory(directory):
    '''
    Monitors directory for new pcap files
    '''

    while True:

        GPIO.output(mon_pin, GPIO.LOW)
        # Check for new files
        for filename in os.listdir(directory):
            if filename.endswith(".pcap"):
                file_path = os.path.join(directory, filename)

                if file_path not in processed_files:
                    analyze_pcap_file(file_path)
                    processed_files.add(file_path)

        GPIO.output(mon_pin, GPIO.HIGH)
        time.sleep(10)

if __name__ == "__main__":
    # Setup objects
    directory_to_monitor = "./network_traffic/"
    processed_files = set()
    fe = Feature_extraction()

    # Start continuous monitoring
    print("Starting packet processing")
    try:
        monitor_directory(directory_to_monitor)
    except KeyboardInterrupt:
        print("Stopping packet processing")