from os import getpid     # IMPORT THESE TWO FUNCTIONS
from time import sleep    #

def main():
    # SAVE PID TO TEXT FILE
    pid = getpid()
    open("pid.txt", 'w').write(str(pid))

    # Run your code
    while True:
        pid = getpid()
        sleep(3)

main()