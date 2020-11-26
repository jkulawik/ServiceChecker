#!/usr/bin/env python3
"""scapy-dhcp-listener.py
Listen for DHCP packets using scapy to learn when LAN 
hosts request IP addresses from DHCP Servers.
Copyright (C) 2018 Jonathan Cutrer
https://jcutrer.com/python/scapy-dhcp-listener
License Dual MIT, 0BSD

Extended by jkulawik, 2020
"""

from __future__ import print_function
from scapy.all import *

from scapy.layers.dhcp import DHCP
from scapy.layers.dhcp import Ether
from scapy.layers.dhcp import BOOTP
from scapy.layers.dhcp import IP

# Logging
from datetime import date
from inspect import getsourcefile
import mac_vendor

__version__ = "0.0.3"


def print_and_log(message):
    print(message)
    log(message)

def log(message):
    dir = 'logs'
    if not os.path.exists(dir):
        # The folder gets created in the run directory automatically...
        os.makedirs(dir)

    # ...but for file writing a full path is needed
    current_dir = os.path.dirname(getsourcefile(lambda:0))
    path = os.path.join(current_dir, 'logs')

    file_name = str(date.today()) + '-log.txt'
    file_path = os.path.join(path, file_name)

    file = open(file_path, "a")
    file.write(message + '\n')
    file.close()


# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):

    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass


def handle_dhcp_packet(packet):

    # Match DHCP discover
    # TODO this message is suspicious
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print('---')
        print('New DHCP Discover')
        #print(packet.summary())
        #print(ls(packet))
        hostname = get_option(packet[DHCP].options, 'hostname')
        mac = packet[Ether].src
        print_and_log(f"Unknown host {hostname} asked for an IP.")
        print_and_log(f'Host vendor: {mac_vendor.get_str(mac)}')
        print_and_log(f'Host MAC: {mac}')

    # Match DHCP ack
    elif DHCP in packet and packet[DHCP].options[0][1] == 5\
            and packet[BOOTP].yiaddr != '0.0.0.0':
        print('---')
        print('New DHCP Ack')
        #print(packet.summary())
        #print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"acked {packet[BOOTP].yiaddr}")

        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}")

    # Match DHCP inform
    elif DHCP in packet and packet[DHCP].options[0][1] == 8:
        print('---')
        print('New DHCP Inform')
        #print(packet.summary())
        #print(ls(packet))

        hostname = get_option(packet[DHCP].options, 'hostname')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')

        print(f"DHCP Inform from {packet[IP].src} ({packet[Ether].src}) "
              f"hostname: {hostname}, vendor_class_id: {vendor_class_id}")

    else:
        print('---')
        print('Some Other DHCP Packet')
        print(packet.summary())
        print(ls(packet))

    return


# This is just to use this script as a dependency
def start_sniffing():
    print('Sniffing DHCP broadcasts...')
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)


if __name__ == "__main__":
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)