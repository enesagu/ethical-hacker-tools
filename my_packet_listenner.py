

import scapy.all as scapy
from scapy_http import http



def listen_packets(interface):

	scapy.sniff(iface=interface, store=False, prn=analyze_packets)     
	##prn = callback function

	





def analyze_packets(packet): ## Bilgileri alacağımız bağlantının detaylarına göre analiz kısmın özelleştirilir
	#packet.show()
	
	if packet.haslayer(http.HTTPRequest):
		if packet.haslayer(scapy.Raw):
			print(packet[scapy.Raw].load)
	
	

	



listen_packets("eth0")




