#!/usr/bin/env python

import sys
import socket
import threading


def request_handler(local_buffer):
	# Perform modifications etc.
	return local_buffer

def response_handler(remote_buffer):
	# Perform modifications 
	return remote_buffer

def hexdump(src, length=16):
	# this is a pretty hex dumping function directly taken from
	# the comments here:
	# http://code.activestate.com/recipes/142812-hex-dumper/
	result = []
	digits = 4 if isinstance(src, unicode) else 2

	for i in xrange(0, len(src), length):
		s = src[i:i + length]
		hexa = b' '.join("{:0{digits}x}".format(ord(c), digits=digits) for c in s)
		text = b''.join([x if 0x20 <= ord(x) < 0x7f else b'.' for x in s])

		result.append( b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text) )

		print(b'\n'.join(result))


def receive_from(connection):
	
	data_buffer = ""

	# Setting a 2 second timeout. Depending on the target
	# This may need to be adjusted
	connection.settimeout(10)

	try:
		# keep reading into the buffer until
		# there's no more data
		# or we time out
		while True:
			data = connection.recv(4096)

			if not data:
				break

			data_buffer += data

	except:
		pass

	return data_buffer

def proxy_handler(client, remote_host, remote_port, receive_first):

	# Connect to remote host
	remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	try:
		remote_socket.connect((remote_host, remote_port))

	except socket.error as e:
		print("[!] Exception: could not connect to {}:{}".format(remote_host, remote_port))
		print("socket error:\n{}".format(e))
		sys.exit(0)

	# Receive data from remote host first if set
	if receive_first:

		remote_buffer = receive_from(remote_socket)
		hexdump(remote_buffer)

		# Send response through response handler
		remote_buffer = response_handler(remote_buffer)		

		# If we received a response, send it back to local client
		if len(remote_buffer):
			print("[<==] Sending {} byte to localhost...".format(len(remote_buffer)))
			client.send(remote_buffer)

	# Now let's loop: Read from local, Send to remote, Send response back to local
	# Local, Remote, back to Local

	while True:

		# Read from Local
		local_buffer = receive_from(client)

		if len(local_buffer):
			print("[==>] Received {} bytes from localhost...".format(len(local_buffer)))
			hexdump(local_buffer)

			# Process outgoing request through request handler
			local_buffer = request_handler(local_buffer)

			# Pass it on to the remote host
			remote_socket.send(local_buffer)
			print("[==>] Sent to remote.")


		# Receive response back from remote host
		remote_buffer = receive_from(remote_socket)

		if len(remote_buffer):

			print("[<==] Received {} bytes from remote host...".format(len(remote_buffer)))

			# Process the response
			hexdump(remote_buffer)
			remote_buffer = response_handler(remote_buffer)


			# Relay response to Local
			client.send(remote_buffer)
			print("[<==] Sent to Localhost.")


		# If no more data on either side, close connections down

		if not len(local_buffer) or not len(remote_buffer):
			client.close()
			remote_socket.close()

			print("[*] No more data.. closing connections..")

			break

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
	
	# create socket and bind to local
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	try:
		server.bind((local_host, local_port))
		server.listen(5)
		print("[*] Listening on {}:{}".format(local_host, local_port))

	except:
		print("[!] Exception: could not bind server")
		sys.exit(0)

	while True:

		client, addr = server.accept()
		print("[<==] Incoming connection: {}:{}".format(addr[0], addr[1]))

		proxy_thread = threading.Thread(target=proxy_handler,
			args=(client, remote_host, remote_port, receive_first))

		proxy_thread.start()

def main():

	# quick and dirty cmd line parsing
	if len(sys.argv[1:]) != 5:
		print("\nUsage: ./tcp_proxy.py [localhost] [localport] [remotehost] [remoteport] [receivefirst]\n")
		print("Example: ./tcp_proxy.py 127.0.0.1 9999 192.12.15.13 3456 False\n")
		sys.exit(0)

	# set up local listening params
	local_host = sys.argv[1]
	local_port = int(sys.argv[2])

	# set up remote host params
	remote_host = sys.argv[3]
	remote_port = int(sys.argv[4])

	# this determines whether to first receive data or not
	# upon connecting with remote host
	receive_first = "True" in sys.argv[5]

	# Spin up the server loop
	server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == "__main__":
	main()