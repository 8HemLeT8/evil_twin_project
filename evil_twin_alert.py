#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
import os
import sys
import time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl


# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan



def parse_args():
	#Create the arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--interface", help="Choose monitor mode interface. By default script will find the most powerful interface and starts monitor mode on it. Example: -i mon5")
    parser.add_argument("-c", "--channel", help="Listen on and deauth only clients on the specified channel. Example: -c 6")
    parser.add_argument("-m", "--maximum", help="Choose the maximum number of clients to deauth. List of clients will be emptied and repopulated after hitting the limit. Example: -m 5")
    parser.add_argument("-n", "--noupdate", help="Do not clear the deauth list when the maximum (-m) number of client/AP combos is reached. Must be used in conjunction with -m. Example: -m 10 -n", action='store_true')
    parser.add_argument("-t", "--timeinterval", help="Choose the time interval between packets being sent. Default is as fast as possible. If you see scapy errors like 'no buffer space' try: -t .00001")
    parser.add_argument("-p", "--packets", help="Choose the number of packets to send in each deauth burst. Default value is 1; 1 packet to the client and 1 packet to the AP. Send 2 deauth packets to the client and 2 deauth packets to the AP: -p 2")
    parser.add_argument("-d", "--directedonly", help="Skip the deauthentication packets to the broadcast address of the access points and only send them to client/AP pairs", action='store_true')
    parser.add_argument("-a", "--accesspoint", help="Enter the MAC address of a specific access point to target")
    parser.add_argument("--world", help="N. American standard is 11 channels but the rest of the world it's 13 so this options enables the scanning of 13 channels", action="store_true")

    return parser.parse_args()


########################################
# Begin interface settings

def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print '['+G+'*'+W+'] Monitor mode: '+G+mon_iface+W+' - '+O+mac+W
    return mac

########################################
# End interface settings
########################################





########################################
# Set channel hop behavior
########################################


def channel_hop(mon_iface, args):
    '''
    First time through, scan each channel for 5 seconds.
    Then skip through all channels quickly.
    '''

    global monchannel, first_pass

    channelNum = 0
    maxChan = 11 if not args.world else 13
    err = None

    while 1:
        if args.channel:
            with lock:
                monchannel = args.channel
        else:
            channelNum +=1
            if channelNum > maxChan:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = str(channelNum)

            try:
                proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel], stdout=DN, stderr=PIPE)
            except OSError:
                print '['+R+'-'+W+'] Could not execute "iw"'
                os.kill(os.getpid(),SIGINT)
                sys.exit(1)
            for line in proc.communicate()[1].split('\n'):
                if len(line) > 2: # iw dev shouldnt display output unless there's an error
                    err = '['+R+'-'+W+'] Channel hopping failed: '+R+line+W

        output(err, monchannel)
        if args.channel:
            time.sleep(.05)
        else:
            # For the first channel hop thru, do not deauth
            if first_pass == 1:
                time.sleep(1)
                continue


########################################
# End channel hop behavior
########################################




########################################
# Set output filtering
########################################

def output(err, monchannel):
    os.system('clear')
    ETIdentifier()

    if err:
        print err


def noise_filter(addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:', mon_MAC]

    for i in ignore:
        if i in addr1 or i in addr2:
            return True

########################################
# End output filtering
########################################


########################################
# evil twin identifier
########################################

def ETIdentifier():
    setOfaps = set()
    for ap in APs:
        if ap[2] in setOfaps:
            print "\n\n\n\n\n\n"
            print R + "             CAUTION!!! " + ap[2] + " might be an EVIl TWIN  :("
            print R + "             CAUTION!!! " + ap[2] + " might be an EVIl TWIN  :("
            print R + "             CAUTION!!! " + ap[2] + " might be an EVIl TWIN  :("
            return
        else:
            setOfaps.add(ap[2])
    print "\n\n\n\n\n\n"
    print G + "             This area is safe  :)"
    setOfaps.clear()

########################################
# End evil twin identifier
########################################

########################################
# Set packet handling
########################################

def cb(pkt):
    '''
    Look for dot11 packets that aren't to or from broadcast address,
    are type 1 or 2 (control, data), and append the addr1 and addr2
    to the list of clients
    '''
    global clients_APs, APs

    # return these if's keeping clients_APs the same or just reset clients_APs?
    # I like the idea of the tool repopulating the variable more
    if args.maximum:
        if args.noupdate:
            if len(clients_APs) > int(args.maximum):
                return
        else:
            if len(clients_APs) > int(args.maximum):
                with lock:
                    clients_APs = []
                    APs = []

    # We're adding the AP and channel to the clients list at time of creation rather
    # than updating on the fly in order to avoid costly for loops that require a lock
    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:
            pkt.addr1 = pkt.addr1.lower()
            pkt.addr2 = pkt.addr2.lower()

            # Filter out all other APs and clients if asked
            if args.accesspoint:
                if args.accesspoint not in [pkt.addr1, pkt.addr2]:
                    return

            # Check if it's added to our AP list
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel, args.world)

            # Ignore all the noisy packets like spanning tree

            if noise_filter(pkt.addr1, pkt.addr2):
                return

            # Management = 1, data = 2
            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)

def APs_add(clients_APs, APs, pkt, chan_arg, world_arg):
    ssid       = pkt[Dot11Elt].info
    bssid      = pkt[Dot11].addr3.lower()
    try:
        # Thanks to airoscapy for below
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'] if not args.world else ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13']
        if ap_channel not in chans:
            return

        if chan_arg:
            if ap_channel != chan_arg:
                return

    except Exception as e:
        return

    if len(APs) == 0:
        with lock:
            return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            return APs.append([bssid, ap_channel, ssid])

def clients_APs_add(clients_APs, addr1, addr2):
    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])
        else:
            AP_check(addr1, addr2)

    # Append new clients/APs if they're not in the list
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def stop(signal, frame):
    sys.exit('\n['+R+'!'+W+'] Closing')


########################################
# End packet handling
########################################






########################################
# Now get busy!
########################################


if __name__ == "__main__":
    if os.geteuid():
        sys.exit('['+R+'-'+W+'] Please run as root')
    clients_APs = []
    APs = []
    DN = open(os.devnull, 'w')
    lock = Lock()
    args = parse_args()
    monitor_on = None
    # mon_iface = get_mon_iface(args)
    mon_iface = "wlan1"
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1

    # Start channel hopping
    hop = Thread(target=channel_hop, args=(mon_iface, args))
    hop.daemon = True
    hop.start()

    signal(SIGINT, stop)

    print "sniffing"
    sniff(iface=mon_iface, store=0, prn=cb)