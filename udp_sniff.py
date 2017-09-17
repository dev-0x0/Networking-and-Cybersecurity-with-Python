#!/usr/bin/env python

import socket
import sys
import os

# host to listen on
host = '0.0.0.0'

# create raw socket and bind to public iface
if os.name == 'nt':
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# want the IP headers included in capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're using Windows we need to send an IOCTL to set up
# promiscuous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Read a single packet capture
print(sniffer.recvfrom(65565))

# If we're using Windows, turn off promiscuous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

