#!/usr/bin/env python

from core.compatible import version

"""
    A pure python ping implementation using raw socket.


    Note that ICMP messages can only be sent from processes running as root.


    Derived from ping.c distributed in Linux's netkit. That code is
    copyright (c) 1989 by The Regents of the University of California.
    That code is in turn derived from code written by Mike Muuss of the
    US Army Ballistic Research Laboratory in December, 1983 and
    placed in the public domain. They have my thanks.

    Bugs are naturally mine. I'd be glad to hear about them. There are
    certainly word - size dependenceies here.

    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.

    Original Version from Matthew Dixon Cowles:
      -> ftp://ftp.visi.com/users/mdc/ping.py

    Rewrite by Jens Diemer:
      -> http://www.python-forum.de/post-69122.html#69122

    Rewrite by George Notaras:
      -> http://www.g-loaded.eu/2009/10/30/python-ping/

    Fork by Pierre Bourdon:
      -> http://bitbucket.org/delroth/python-ping/

    Revision history
    ~~~~~~~~~~~~~~~~

    November 22, 1997
    -----------------
    Initial hack. Doesn't do much, but rather than try to guess
    what features I (or others) will want in the future, I've only
    put in what I need now.

    December 16, 1997
    -----------------
    For some reason, the checksum bytes are in the wrong order when
    this is run under Solaris 2.X for SPARC but it works right under
    Linux x86. Since I don't know just what's wrong, I'll swap the
    bytes always and then do an htons().

    December 4, 2000
    ----------------
    Changed the struct.pack() calls to pack the checksum and ID as
    unsigned. My thanks to Jerome Poincheval for the fix.

    May 30, 2007
    ------------
    little rewrite by Jens Diemer:
     -  change socket asterisk import to a normal import
     -  replace time.time() with time.clock()
     -  delete "return None" (or change to "return" only)
     -  in checksum() rename "str" to "source_string"

    November 8, 2009
    ----------------
    Improved compatibility with GNU/Linux systems.

    Fixes by:
     * George Notaras -- http://www.g-loaded.eu
    Reported by:
     * Chris Hallman -- http://cdhallman.blogspot.com

    Changes in this release:
     - Re-use time.time() instead of time.clock(). The 2007 implementation
       worked only under Microsoft Windows. Failed on GNU/Linux.
       time.clock() behaves differently under the two OSes[1].

    [1] http://docs.python.org/library/time.html#time.clock

    September 25, 2010
    ------------------
    Little modifications by Georgi Kolev:
     -  Added quiet_ping function.
     -  returns percent lost packages, max round trip time, avrg round trip
        time
     -  Added packet size to verbose_ping & quiet_ping functions.
     -  Bump up version to 0.2

"""

__version__ = "0.2"

import os
import select
import socket
import struct
import sys
import time

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 8  # Seems to be the same on Solaris.


def checksum_py3(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum = 0
    countTo = (len(source_string) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = source_string[count + 1] * 256 + source_string[count]
        sum = sum + thisVal
        sum = sum & 0xffffffff  # Necessary?
        count = count + 2

    if countTo < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff  # Necessary?

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def checksum_py2(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum = 0
    count_to = (len(source_string) / 2) * 2
    for count in range(0, int(count_to), 2):
        this = ord(str(source_string[count + 1])) * \
            256 + ord(str(source_string[count]))
        sum = sum + this
        sum = sum & 0xffffffff  # Necessary?
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff  # Necessary?

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receive_one_ping(my_socket, id, timeout):
    """
    Receive the ping from the socket.
    """
    time_left = timeout
    while True:
        started_select = time.time()
        what_ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = (time.time() - started_select)
        if what_ready[0] == []:  # Timeout
            return

        time_received = time.time()
        received_packet, addr = my_socket.recvfrom(1024)
        icmpHeader = received_packet[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )
        if packet_id == id:
            bytes = struct.calcsize("d")
            time_sent = struct.unpack("d", received_packet[28:28 + bytes])[0]
            return time_received - time_sent

        time_left = time_left - how_long_in_select
        if time_left <= 0:
            return


def send_one_ping(my_socket, dest_addr, id, psize):
    """
    Send one ping to the given >dest_addr<.
    """
    try:
        dest_addr = socket.gethostbyname(dest_addr)
    except:
        return None
    # Remove header size from packet size
    psize = psize - 8

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    my_checksum = 0

    # Make a dummy heder with a 0 checksum.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, id, 1)
    bytes = struct.calcsize("d")
    data = (psize - bytes) * "Q"
    data = struct.pack("d", time.time(
    )) + data if version() is 2 else struct.pack("d", time.time()) + data.encode()

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum_py2(
        header + data) if version() is 2 else checksum_py3(header + data)

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1
    )
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1))  # Don't know about the 1


def do_one(dest_addr, timeout, psize):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error:
        return None

    my_id = os.getpid() & 0xFFFF

    send_one_ping(my_socket, dest_addr, my_id, psize)
    delay = receive_one_ping(my_socket, my_id, timeout)

    my_socket.close()
    return delay

    # def verbose_ping(dest_addr, timeout = 2, count = 4, psize = 64):
    #     """
    #     Send `count' ping with `psize' size to `dest_addr' with
    #     the given `timeout' and display the result.
    #     """
    #     for i in xrange(count):
    #         print "ping %s with ..." % dest_addr,
    #         try:
    #             delay  =  do_one(dest_addr, timeout, psize)
    #         except socket.gaierror, e:
    #             print "failed. (socket error: '%s')" % e[1]
    #             break
    #
    #         if delay  ==  None:
    #             print "failed. (timeout within %ssec.)" % timeout
    #         else:
    #             delay  =  delay * 1000
    #             print "get ping in %0.4fms" % delay
    #     print
    #
    #
    # def quiet_ping(dest_addr, timeout = 2, count = 4, psize = 64):
    #     """
    #     Send `count' ping with `psize' size to `dest_addr' with
    #     the given `timeout' and display the result.
    #     Returns `percent' lost packages, `max' round trip time
    #     and `avrg' round trip time.
    #     """
    #     mrtt = None
    #     artt = None
    #     lost = 0
    #     plist = []
    #
    #     for i in xrange(count):
    #         try:
    #             delay = do_one(dest_addr, timeout, psize)
    #         except socket.gaierror, e:
    #             print "failed. (socket error: '%s')" % e[1]
    #             break
    #
    #         if delay != None:
    #             delay = delay * 1000
    #             plist.append(delay)
    #
    #     # Find lost package percent
    #     percent_lost = 100 - (len(plist) * 100 / count)
    #
    #     # Find max and avg round trip time
    #     if plist:
    #         mrtt = max(plist)
    #         artt = sum(plist) / len(plist)
    #
    #     return percent_lost, mrtt, artt
    #
    # if __name__ == '__main__':
    #     verbose_ping("heise.de")
    #     verbose_ping("google.com")
    #     verbose_ping("a-test-url-taht-is-not-available.com")
    #     verbose_ping("192.168.1.1")
