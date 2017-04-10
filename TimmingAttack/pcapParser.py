#!/usr/bin/env python
"""
This example expands on the print_packets example. It checks for HTTP request headers and displays their contents.
NOTE: We are not reconstructing 'flows' so the request (and response if you tried to parse it) will only
      parse correctly if they fit within a single packet. Requests can often fit in a single packet but
      Responses almost never will. For proper reconstruction of flows you may want to look at other projects
      that use DPKT (http://chains.readthedocs.io and others)
"""
import datetime
import glob
import os.path
import socket
from io import BytesIO

import dpkt
from dpkt.compat import compat_ord


def connection_id_to_str(cid, v=4):
    """This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port, destination_ip_address,
destination_tcp_port) to a string.  v is either 4 for IPv4 or 6 for IPv6"""
    if v == 4:
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + ":" + str(cid[1]) + "=>" + dst_ip_addr_str + ":" + str(cid[3])
    elif v == 6:
        src_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(socket.AF_INET6, cid[2])
        return src_ip_addr_str + "." + str(cid[1]) + "=>" + dst_ip_addr_str + "." + str(cid[3])
    else:
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)


def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def print_http_requests(pcap, password):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    count = 0
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        if count == 0:
            previous_packet = dpkt.ethernet.Ethernet(buf).data.data
            count+=1
        else:
            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(buf)

            # Make sure the Ethernet data contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
                continue

            # Now grab the data within the Ethernet frame (the IP packet)
            ip = eth.data

            # Check for TCP in the transport layer
            if isinstance(ip.data, dpkt.tcp.TCP):

                # Set the TCP data
                tcpData = ip.data


                # Now see if we can parse the contents as a HTTP request
                f = BytesIO(tcpData.data)
                line = f.readline().decode("ascii", "ignore")
                l = line.strip().split()

                if len(l) > 0 and ('HTTP' in l[0]):  # 'POST' in l[0] or

                    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
                    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
                    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
                    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

                    # Print out the info
                    print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
                    print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
                    print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' %
                          (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments,
                           fragment_offset))


                    # Get and calculate time elapse between request and server response


                    actualOptions = fetchOptions(tcpData)
                    previous_options = fetchOptions(previous_packet)


                    try:
                        elapse = actualOptions.get('tsval') - previous_options.get('tsval')
                    except Exception as e:
                        pass

                    previous_packet = dpkt.ethernet.Ethernet(buf).data.data
                    # write info into txt

                    if os.path.isfile('wireData/' + password + '.txt'):
                        file = open('wireData/' + password + '.txt', 'a')
                    else:
                        file = open('wireData/' + password + '.txt', 'w+')
                    file.write(password + ':' + str(elapse) + '\n')
                    file.close()

                    # Check for Header spanning acrossed TCP segments
                    if not tcpData.data.endswith(b'\r\n'):
                        print('\nHEADER TRUNCATED! Reassemble TCP segments!\n')


def fetchOptions(tcpData):
    options = {}
    for opt in dpkt.tcp.parse_opts(tcpData.opts):
        try:
            o, d = opt
            if len(d) > 32: raise TypeError
        except TypeError:
            break
        if o == dpkt.tcp.TCP_OPT_MSS:
            options['mss'] = dpkt.struct.unpack('>H', d)[0]
        elif o == dpkt.tcp.TCP_OPT_WSCALE:
            options['wsc'] = ord(d)
        elif o == dpkt.tcp.TCP_OPT_SACKOK:
            options['sackok'] = True
        elif o == dpkt.tcp.TCP_OPT_TIMESTAMP:
            (options['tsval'], options['tsecr']) = dpkt.struct.unpack('>II', d)
    return options


def parser():
    files = glob.glob("pcaps/*.pcap")
    files.sort()
    """Open up a test pcap file and print out the packets"""
    for file in files:
        password = file.split('/')[1].split('.')[0]
        with open(str(file), 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            print_http_requests(pcap,password)
parser()



