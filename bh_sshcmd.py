#!/usr/bin/env python

import sys
import threading
import paramiko
import subprocess

def ssh_command(ip, user, pwd, cmd):

	client = paramiko.SSHClient()
	#client.load_host_keys('/root/.ssh/known_hosts')
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(ip, username=user, password=pwd)
	print("[*] Connected to {}:{}".format(ip, 22))

	ssh_session = client.get_transport().open_session()

	if ssh_session.active:
		print("[*] Logged in as: {}@{}\n".format(user, ip))
		ssh_session.exec_command(cmd)
		print(ssh_session.recv(1024))

	return

ssh_command('192.168.245.129', 'user', 'pass', 'id')