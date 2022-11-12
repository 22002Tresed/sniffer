import scapy.all as scapy

def sniff(inteface):
    scapy.sniff(iface = inteface,count = 5, store = False, prn = process_sniffed_packet, filter = 'tcp')

def process_sniffed_packet(packet):
    print(packet.show())

sniff(None)
