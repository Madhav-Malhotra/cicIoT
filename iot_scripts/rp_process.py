import os
import time
import RPi.GPIO as GPIO
from feat_extract.Feature_extraction import Feature_extraction
from rp_analyse import check_benign

# Setup output pins
BEN_PIN = 22
MAL_PIN = 23
MON_PIN = 24
WAIT = 1.0

GPIO.setmode(GPIO.BOARD)
GPIO.setup(BEN_PIN, GPIO.OUT)
GPIO.setup(MAL_PIN, GPIO.OUT)
GPIO.setup(MON_PIN, GPIO.OUT)


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
        GPIO.output(BEN_PIN if b else MAL_PIN, GPIO.HIGH)
        time.sleep(WAIT)
        GPIO.output(BEN_PIN if b else MAL_PIN, GPIO.LOW)
        time.sleep(WAIT)

def monitor_directory(directory):
    '''
    Monitors directory for new pcap files
    '''

    while True:
        GPIO.output(MON_PIN, GPIO.LOW)
        
        # Check for new files
        for filename in os.listdir(directory):
            if filename.endswith(".pcap"):
                file_path = os.path.join(directory, filename)

                if file_path not in processed_files:
                    analyze_pcap_file(file_path)
                    processed_files.add(file_path)

        GPIO.output(MON_PIN, GPIO.HIGH)
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

    # Fail gracefully
    except KeyboardInterrupt:
        print("Stopping packet processing")
        GPIO.output(BEN_PIN, GPIO.LOW)
        GPIO.output(MAL_PIN, GPIO.LOW)
        GPIO.output(MON_PIN, GPIO.LOW)
        GPIO.cleanup()