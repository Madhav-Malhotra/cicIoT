import os
import time
from feat_extract.Feature_extraction import Feature_extraction

def analyze_pcap_file(file_path):
    print(f"Analyzing {file_path}")
    fe.pcap_evaluation(file_path, file_path[:-5] + ".csv")
    

def monitor_directory(directory):
    while True:
        for filename in os.listdir(directory):
            if filename.endswith(".pcap"):
                file_path = os.path.join(directory, filename)
                if file_path not in processed_files:
                    analyze_pcap_file(file_path)
                    processed_files.add(file_path)

        time.sleep(10)

if __name__ == "__main__":
    directory_to_monitor = "./network_traffic/"
    processed_files = set()
    fe = Feature_extraction()

    print("Starting packet processing")
    try:
        monitor_directory(directory_to_monitor)
    except KeyboardInterrupt:
        print("Stopping packet processing")