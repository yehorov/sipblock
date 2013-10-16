#!/usr/bin/env python

import argparse
import socket
import struct
from datetime import datetime, timedelta
import re
import subprocess
import os
import pcap
from daemon import DaemonContext
from daemon.pidlockfile import PIDLockFile


class SIPReg:
    def __init__(self, host, lastdt, period = timedelta(seconds = 10), \
            reglimit = 100, exceedtimeout = timedelta(hours = 1)):
        self.host = host
        self.lastdt = lastdt
        self.prevdt = lastdt
        self.count = 1
        self.period = period
        self.reglimit = reglimit
        self.exceedtimeout = exceedtimeout
        self.exceeded = False

    def addReg(self, lastdt):
        result = 0
        delta = lastdt - self.lastdt
        if self.exceeded:
            if delta >= self.exceedtimeout:
                self.exceeded = False
            else:
                self.count = self.count + 1
                return 0
        if delta >= self.period:
            self.prevdt = self.lastdt
            self.lastdt = lastdt
            self.count = 1
        else:
            self.count = self.count + 1
        if self.count >= self.reglimit:
            result = self.count
            self.exceeded = True
        return result


class SIPBlock:

    sipfilter = 'udp and port 5060'
    rereg = re.compile('^REGISTER\s');
    reua = re.compile('^User-Agent:\s(.*)$');

    def __init__(self, args):
        self.args = args
        self.regs = dict()
        self.UAset = set(['friendly-scanner'])

    def main(self):
        def handle_packet(pktlen, data, timestamp):
            if not data:
                return

            if data[12:14] != '\x08\x00':
                return

            decoded = decode_ip_packet(data[14:])
            if not 'udp_data' in decoded:
                return

            data = decoded['udp_data']
            if block.args.debug > 15:
                print "%r" % data

            host = decoded['source_address']
            port = decoded['source_port']

            m = self.rereg.search(data)
            if m == None:
                return

            check = False
            for line in data.split('\r\n'):
                m = self.reua.search(line)
                if m != None:
                    check = True
                    if len(self.UAset) > 0 and not m.group(1) in self.UAset:
                        return
            if not check:
                return

            now = datetime.now()
            if not host in self.regs:
                reg = SIPReg(host, now,
                        reglimit = args.reglimit,
                        exceedtimeout = timedelta(days = 1))
                self.regs[host] = reg
            else:
                reg = self.regs[host]
                over = reg.addReg(now)
                if over > 0:
                    if block.args.debug > 5:
                        print "%s: SIP flood from %s (%i in %s)" \
                                  % (now, host, over, now - reg.lastdt)
                        p = subprocess.Popen([block.args.action, host],
                                  stdout=open(os.devnull),
                                  stderr=open(os.devnull))
                        p.communicate()[0]

            if block.args.debug > 10:
                print "SIPReg(%s, %s, %i, %s)" \
                      % (reg.host, reg.lastdt, reg.count, reg.exceeded)
            if block.args.debug > 15:
                print "received %r from %s:%d" % (data, host, port)

        p = pcap.pcapObject()
        net, mask = pcap.lookupnet(self.args.interface)
        p.open_live(self.args.interface, 1600, 0, 100)
        p.setfilter(self.sipfilter, 0, 0)

        try:
            while True:
                p.dispatch(1, handle_packet)
        except KeyboardInterrupt:
            print 'shutting down'
            print '%d packets received, %d packets dropped, ' \
                  '%d packets dropped by interface' % p.stats()


def decode_ip_packet(s):
    d = {}
    d['version'] = (ord(s[0]) & 0xf0) >> 4
    d['header_len'] = ord(s[0]) & 0x0f
    d['tos'] = ord(s[1])
    d['total_len'] = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id'] = socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags'] = (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset'] = socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl'] = ord(s[8])
    d['protocol'] = ord(s[9])
    d['checksum'] = socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address'] = pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address'] = pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len'] > 5:
        d['options'] = s[20:4*(d['header_len']-5)]
    else:
        d['options'] = None
    payload_offset = 4 * d['header_len']
    d['data'] = s[payload_offset:]
    if d['protocol'] == 17:
        d['source_port'] = socket.ntohs(struct.unpack('H', d['data'][0:2])[0])
        d['destination_port'] = socket.ntohs(struct.unpack('H', d['data'][2:4])[0])
        d['udp_length'] = socket.ntohs(struct.unpack('H', d['data'][4:6])[0])
        d['udp_checksum'] = socket.ntohs(struct.unpack('H', d['data'][6:8])[0])
        d['udp_data'] = d['data'][8:]
    return d


if __name__=='__main__':

    parser = argparse.ArgumentParser(description = 'SIPBlocker')
    parser.add_argument('-d', '--debug', type = int, default = 0,
            help = 'debug level')
    parser.add_argument('-f', '--foreground', action = 'store_true',
            help = 'run in foreground')
    parser.add_argument('-i', '--interface', required = True,
            help = 'capture interface')
    parser.add_argument('-a', '--action', required = True,
            help = 'action script')
    parser.add_argument('--pid', default = '/var/run/sipblock.{0}.pid',
            help = 'pid file')
    parser.add_argument('--reglimit', type = int, default = 500,
            help = 'registration limit per ip adress for period')
    args = parser.parse_args()

    block = SIPBlock(args)
    if args.foreground == True:
        block.main()
    else:
        pidfilename = args.pid.format(args.interface)
        with DaemonContext(pidfile = PIDLockFile(pidfilename), umask = 022):
            block.main()
