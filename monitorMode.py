import os

def change2monitor(interface):
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode monitor')
    os.system('ifconfig ' + interface + ' up')

print("----------------------------------------------------------")
change2monitor("wlan2")
os.system('iwconfig')
