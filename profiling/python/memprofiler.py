""" Memory Profiler
Records RAM and hard disk usage of script over time.
Dependancies: `time`, `psutil`, `argparse`, "pid.txt" file with process ID to profile.
Send kill signal (Ctrl+C) to stop profiling.
"""

# Library Imports
import time
import psutil
import argparse


def profiler(outfile : str, pid : int, interval : int) -> None:
    """ 
    Records process stats to `outfile`.csv every `interval` seconds 
    
    Parameters
    ------------------
    outfile (output CSV filepath)
    pid (process ID of process to profile)
    interval (time between stat recordings in seconds)
    """

    # Setup process
    process = psutil.Process(pid)
    ram_info = process.memory_full_info()
    disk_info = process.io_counters()

    # Setup CSV
    f = open(outfile, 'w')
    f.write(",".join(ram_info._fields + disk_info._fields) + "\n")

    # Append CSV data
    while True:
        ram_info = tuple(process.memory_full_info())
        disk_info = tuple(process.io_counters())

        f.write(",".join(
            [str(x) for x in ram_info + disk_info]
        ) + "\n")

        time.sleep(interval)

def main(outfile : str, pid : int, interval : int):
    """
    Fixes PID if none specified, then starts profiling.

    Parameters
    ------------------
    outfile (output CSV filepath)
    pid (process ID of process to profile)
    interval (time between stat recordings in seconds)
    """

    # Get the PID of the main script
    if pid == None:
        with open("pid.txt", 'r') as f:
            pid = int(f.readline())

    profiler(outfile, pid, interval)

if __name__ == "__main__":
    # Setup script arguments
    parser = argparse.ArgumentParser(description=__doc__)
    
    parser.add_argument(
        '-o',
        '--output',
        type=str,
        help="CSV filename to store stats to (default memstats.csv)",
        default="memstats.csv",
        required=False
    )

    parser.add_argument(
        '-p',
        '--pid',
        type=int,
        help="Process ID of script to profile",
        required=False
    )

    parser.add_argument(
        '-i',
        '--interval',
        type=int,
        help="Number of seconds to pause between each stat collection (default 1)",
        default=1,
        required=False
    )

    # Run profiler
    args = parser.parse_args()
    main(args.output, args.pid, args.interval)