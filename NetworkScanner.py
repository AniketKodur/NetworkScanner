#!/bin/bash

import scapy.all as sc
import argparse
import os

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    if os.geteuid() != 0:
        print("Access Denied. Need root privileges to run this script.")
        exit()
    arpReq = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpReqBroadcast = broadcast / arpReq
    answered, unanswered = sc.srp(arpReqBroadcast, timeout=1, verbose=False)
    clients_list = []
    for x in answered:
        clients_dic = {"ip": x[1].psrc, "MAC": x[1].hwsrc}
        clients_list.append(clients_dic)
    return clients_list

def printing(x):
    print("\tIP\t\t\tMAC Address\n------------------------------------------------")
    for client in x:
        print(client["ip"], "\t\t", client["MAC"])

options = get_arguments()
a = scan("192.168.0.1/24")
printing(a)