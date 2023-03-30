
import scapy.all as scapy


#1) ARP request
#2) Broadcast
#3) Response



arp_request_packet = scapy.ARP()
scapy.ls(scapy.ARP())