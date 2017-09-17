#!/usr/bin/env python
# web_app_scanner.py

import urllib2
import Queue
import threading
import os

threads = 10

target = "http://www.blackhatpython.com"
