import os
import sys
import time

fake_AP_BSSID = "18:A6:F7:8A:9A:9F"
monitor_interface = "wlan1"
fake_AP_name = "tsadok_up"
os.popen("python3 my_deauth.py " + fake_AP_BSSID + " " + monitor_interface + " " + fake_AP_name)

while True:
    time.sleep(5)