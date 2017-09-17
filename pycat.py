#!/usr/bin/env python

# PyCat is a very basic netcat type tool

import socket
import sys
import argparse
import threading
import subprocess

options = {
	"listen": False,
	"command": False,
	"upload": False,
	"execute": "",
	"target":  "",
	"upload": "",
	"port": 0}

def client_handler(client_socket):

	# Check for file upload
	if len(options['upload']):
		
		# read in the file as a byte stream
		file_buffer = ""

		# read data until there is none
		while True:
			data = client_socket.recv(1024)
			if len(data):
				file_buffer += data
			else:
				break

		# write data to a file
		try:
			with open(options['upload'], "wb") as f:
				f.write(file_buffer)

			client_socket.send("Successfully saved file to {}\r\n".format(options['upload']))

		except:
			client_socket.send("Failed to save file {}\r\n".format(options['upload']))

	# Check for command execution
	if len(options['execute']):

		# Run the command
		output = exe_command(options['execute'])
		client_socket.send(output)

	# Now go into another loop if a command shell was requested
	if options['command']:

		while True:

			# Show a simple prompt
			client_socket.send("#~ ")

			# Receive until we see a linefeed
			cmd_buffer = ""

			while '\n' not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)

			# Send back the cmd output
			response = exe_command(cmd_buffer)

			# Send back the response
			client_socket.send(response)

def exe_command(cmd):

	cmd = cmd.strip()

	# Run command and check output for errors
	try:
		output = subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)
	except:
		output = "[!] Error executing command"

	# Return output to client
	return output

def server_loop():

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# bind server
	server.bind((options['target'], options['port']))
	server.listen(5)
	print("[*] Server listening on {}:{}".format(options['target'], options['port']))

	# Accept new clients and spin them off into their own threads
	while True:
		client_socket, addr = server.accept()
		print("[*] {}:{} connected".format(addr[0], addr[1]))
		client_thread = threading.Thread(target=client_handler, args=(client_socket,))
		client_thread.start()

def client_send_recv(data):

    # open a socket to the target host
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	try:
		client.connect((options['target'], options['port']))

        # Send our data
		if len(data):
			client.send(data)

		while True:

			# Wait for response data
			recv_len = 1
			response = ""

            # recv data and append to response string until 
            # it stops coming in
			while recv_len:
				remote_data = client.recv(4096)
				recv_len = len(remote_data)
				response += remote_data

				if recv_len < 4096:
					break

			print(response),

			# Wait for more input
			data = raw_input("") + "\n"

			# Send it off
			client.send(data)

	except:
		print("[!] Exception: connection error")
		# close socket
		client.close()

def main():
    
    # read in the buffer from the commandline
    # this will block, so send CTRL-D if not sending input
    # to stdin
	if options["listen"] is False:
		data = sys.stdin.read()
		client_send_recv(data)

    # we are going to listen and potentially
    # upload files, execute commands, and drop into a shell
    # depending on our command line options above
	else:
		server_loop()

def parse_arguments():
	parser = argparse.ArgumentParser(usage=usage())
	parser.add_argument("-t", "--target", type=str, help="the target host", default="0.0.0.0")
	parser.add_argument("-p", "--port", type=int, help="the target port", default=8888)
	parser.add_argument("-l", "--listen", help="listen on [host]:[port] for incoming connections",
		action="store_true")
	parser.add_argument("-e", "--execute", type=str, 
		help="execute the given file upon receiving a connection", default="")
	parser.add_argument("-c", "--command", help="initialize a command shell",
		action="store_true")
	parser.add_argument("-u", "--upload", type=str, 
		help="upon receiving connection, upload file and write to [destination]", default="")
	args = parser.parse_args()

	# store user options in global dict
	for arg in vars(args):
		if arg is not False and arg is not None:
			options[arg] = getattr(args, arg)
			
			### DEBUG ###
			print(''.join([arg, ': ', str(getattr(args, arg))]))

def usage():

      return """

      PyCat Net Tool

      Usage: pycat.py -t target_host -p port

      -l --listen              - listen on [host]:[port] for incoming connections
      -e --execute=file_to_run - execute the given file upon receiving a connection     
      -c --command             - initialize a command shell"
      -u --upload=destination  - upon receiving connection upload file and write to [destination]

      Examples:

      pycat.py -t 192.168.0.1 -p 5555 -l -c
      pycat.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe
      pycat.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"
      echo 'ABCDEFGHI' | ./pycat.py -t 192.168.11.12 -p 135

      """

if __name__ == "__main__":

	parse_arguments()
	main()
