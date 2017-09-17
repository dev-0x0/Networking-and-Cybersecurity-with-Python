#!/usr/bin/env python
# pic_carver.py

import re
import zlib
import cv2

from scapy.all import *


pictures_dir = "/root/books/bhp/pic_carver/pictures"
faces_dir = "/root/books/bhp/pic_carver/faces"
pcap_file = "/root/books/bhp/arper/arper.pcap"


def face_detect(path, file_name):

	img = cv2.imread(path)
	cascade = cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
	rects = cascade.detectMultiScale(img, 1.005, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20, 20))

	if len(rects) == 0:
		return False

	rects[:, 2:] += rects[:, :2]

	# highlight the faces in the image
	for x1, y1, x2, y2 in rects:
		cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)

	cv2.imwrite("{}/{}-{}".format(faces_dir, pcap_file, file_name), img)

	return True


def extract_image(headers, http_payload):

	image = None
	image_type = None

	try:
		if "image" in headers['Content-Type']:
			# grap the image-type and image body
			image_type = headers['Content-Type'].split('/')[1]

			image = http_payload[:http_payload.index("\r\n\r\n") + 4]

			# if we detect compression, decompress the image
			try:
				if "Content-Encoding" in headers:
					if headers['Content-Encoding'] == "gzip":
						image = zlib.decompress(image, 16 + zlib.MAX_WBITS)
					elif headers['Content-Encoding'] == "deflate":
						image = zlib.decompress(image)

			except:
				pass

	except:
		return None, None

	return image, image_type


def get_http_headers(http_payload):

	try:
		# split the HTTP headers off if it is HTTP traffic
		headers_raw = http_payload[:http_payload.index("\r\n\r\n") + 2]

		# break out the headers
		headers = dict(
			re.findall(r"(?P<name>).*?): (?P<value>.*?)\r\n", headers_raw))

	except:
		return None

	if "Content-Type" not in headers:
		return None

	return headers


def http_assembler(pcap_file):

	carved_images = 0
	faces_detected = 0

	a = rdpcap(pcap_file)

	sessions = a.sessions()

	for session in sessions:
		http_payload = ""

		for packet in sessions[session]:
			try:
				http_payload += str(packet[TCP].payload)

			except:
				pass

		print("[*] HTTP PAYLOAD\n{}".format(http_payload))

		headers = get_http_headers(http_payload)

		if headers is None:
			continue

		image, image_type = extract_image(headers, http_payload)

		if image is not None and image_type is not None:
			# store the image
			file_name = "{}-pic_carver_{}.{}".format(pcap_file, carved_images, image_type)

			with open("{}/{}".format(picutres_dir, file_name), "wb") as f:
				f.write(image)

			carved_images += 1

			# now attempt face detection
			try:
				result = face_detect("{}/{}".format(pictures_dir, file_name), file_name)

				if result:
					faces_detected += 1
			except:
				pass

	return carved_images, faces_detected


carved_images, faces_detected = http_assembler(pcap_file)

print("[*] Extracted {} images".format(carved_images))
print("[*] Detected {} faces".format(faces_detected))








