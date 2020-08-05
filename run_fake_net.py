import os
import sys
from signal import SIGINT, signal

W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red

def stop(signal, frame):
    sys.exit('\n['+R+'!'+W+'] Closing')

signal(SIGINT, stop)

os.system('hostapd /root/fap/hostapd.conf')

