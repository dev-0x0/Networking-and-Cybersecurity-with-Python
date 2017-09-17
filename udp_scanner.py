#!/usr/bin/env python

import threading
import time
import socket
import os
import struct
from ctypes import *
from netaddr import IPNetwork, IPAddress

# host to listen on
host = '0.0.0.0'

# subnet to target
subnet = '192.168.245.0/24'

# Magic string to check ICMP responses for
magic_string = "PYTHONRULES!"

# fUNCTION that sprays the UDPs
def spray_upd(subnet, magic_string):
	time.sleep(5)
	spray = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# send datagram to every ip in the subnet
	for ip in IPNetwork(subnet):
		try:
			spray.sendto(magic_string, ("{}".format(ip), 65212))
		except:
			pass


# Our IP header
class IP(Structure):

	_fields_ = [
		("ihl", c_ubyte, 4),
		("version", c_ubyte, 4),
		("tos", c_ubyte),
		("len", c_ushort),
		("id", c_ushort),
		("offset", c_ushort),
		("ttl", c_ubyte),
		("protocol_num", c_ubyte),
		("sum", c_ushort),
		("src", c_uint32),
		("dst",	c_uint32)]

	# builds the ip header struct from _fields_
	# called BEFORE __init__
	def __new__(self, socket_buffer=None):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer=None):

		# map protocol constants to their names
		self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

		# human readable IP addresses
		self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
		self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

		# human readable protocol
		try:
			self.protocol = self.protocol_map[self.protocol_num]
		except:
			self.protocol = str(self.protocol_num)


class ICMP(Structure):

	_fields_ = [
		("type", c_ubyte),
		("code", c_ubyte),
		("checksum", c_ushort),
		("unused", c_ushort),
		("next_hop_mtu", c_ushort)]

	def __new__(self, socket_buffer):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer):
		pass


if os.name == 'nt'		:
	sock_protocol = socket.IPPROTO_IP
else:
	sock_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_protocol)

sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Turn on promiscuous mode for Windows
if os.name == 'nt':
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
	# Release the datagrams!
	t = threading.Thread(target=spray_upd, args=(subnet, magic_string))
	t.start()

	# Main sniffer loop
	while True:
		# read in a packet
		raw_buffer = sniffer.recvfrom(65565)[0]

		# create IP header from first 20 bytes of the buffer
		ip_header = IP(raw_buffer[:20])

		# print out the protocol that was detected and the hosts
		#print("Protocol: {} {} -> {}".format(
		#	ip_header.protocol, ip_header.src_address, ip_header.dst_address))

		#print("IP header size: {}".format(ip_header.ihl))

		# If it's an ICMP packet, we want it
		if ip_header.protocol == "ICMP":
			# calculate where the packet starts
			# ihl is the number of 32-bit words(4-byte chunks) in the header
			# so an ihl of 5 would give us a total of 20 bytes, which is 160 bits
			# where the ICMP header would begin
			offset = ip_header.ihl * 4
			buf = raw_buffer[offset: offset + sizeof(ICMP)]

			# create our ICMP struct
			icmp_header = ICMP(buf)

			# if it's the right type of ICMP
			# type = 3 = Destination unreachable
			# code = 3 = Port unreachable
			if icmp_header.type == 3 and icmp_header.code == 3:
				# make sure host is within target subnet
				if IPAddress(ip_header.src_address) in IPNetwork(subnet):
					# make sure it contains the magic string
					string_offset = len(raw_buffer) - len(magic_string)
					if raw_buffer[string_offset:] == magic_string:
						print("[+] Host is UP: {}".format(ip_header.src_address))


# handle CTRL-C
except KeyboardInterrupt:
	# if Windows, turn off promiscuous mode
	if os.name == 'nt':
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)










