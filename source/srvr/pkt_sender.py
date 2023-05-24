#code to craft some packets using Scapy
#Use scapy to craft and send level 2 packets
#Send stuff in the udp payload

#Use server code to receive data from client
#(result of the commands executed for example)

import sys
from scapy.all import *

victim_addr = "192.168.1.75"
victim_mac_addr = "aa:bb:cc:dd:ee"

#preset destination IP
#destination port 5000 for TCP packet
sample_tcp_pkt = Ether()/IP(dst=victim_addr)/TCP(dport=5000)

#sample udp preset
sample_udp_pkt = Ether()/IP(dst=victim_addr)/UDP(dport=5555)

#send at layer 2 (Data Link Layer) 
sent = 0
while sent != 10: #while sent is not 10 (starts at 0)
    sendp(sample_udp_pkt) 
    sent = sent + 1 #increment by 1
#sent a udp packet at layer 2, 10 times 
