#!/usr/bin/python
"""
Script to send messages to XS17 EVE visualization tool.
"""

import sys, getopt
import requests
import json
import socket


def main(argv):
	eveurl='http://1.2.3.4:7777/eve/newEvent'
	headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Accept-Encoding': 'gzip, deflate'}
	ttypes = ['host', 'network']
	probes = ['syslogs', 'snoopy', 'apache', 'honeystuff', 'ids', 'pcap', 'netflow', 'influx', 'other']
	reltypes = ['honeystuff', 'other']

	s = ''
	s4 = ''
	s6 = ''
	t = ''
	t4 = ''
	t6 = ''
	ttype = 'host'
	tname = ''
	attack = ''
	probe = 'other'
	evidence = ''
	url = ''
	reltype = 'other'
	rel4 = ''
	rel6 = ''
	reldesc = ''

	data = {}
	source = {}
	target = {}
	payload = {}
	related = {}


	try:
		opts, args = getopt.getopt(argv,"hs:t:a:p:e:u:r:",["help","source=","s4","source4=","source6=","target=","target4=","target6","ttype=","tname=","attack=","probe=","evidence=","url=","reltype=","rel=","rel4=","rel6=","reldesc="])
	except getopt.GetoptError:
		printhelp()
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-h", "--help"):
			printhelp()
			sys.exit()
		elif opt in ("-s", "--source"):
			#Really simplistic verification, FIXME later
			if ":" in arg:
				s6 = normalizeIP6(arg)
			else:
				s4 = arg
		elif opt in ("--source4"):
			s4 = arg
		elif opt in ("--source6"):
			s6 = arg
		elif opt in ("-t", "--target"):
			#Really simplistic verification, FIXME later
			if ":" in arg:
				t6 = normalizeIP6(arg)
			else:
				t4 = arg
		elif opt in ("--target4"):
			t4 = arg
		elif opt in ("--target6"):
			t6 = arg
		elif opt in ("--ttype"):
			if arg.lower() in ttypes:
				ttype = arg.lower()
			else:
				print 'Bad target type'
				sys.exit(2)
		elif opt in ("--tname"):
			tname = arg
		elif opt in ("-a", "--attack"):
			attack = arg
		elif opt in ("-p", "--probe"):
			if arg.lower() in probes:
				probe = arg.lower()
			else:
				print 'Bad probe type'
				sys.exit(2)
		elif opt in ("-e", "--evidence"):
			evidence = arg
		elif opt in ("-u", "--url"):
			url = arg
		elif opt in ("--reltype"):
			if arg.lower() in reltypes:
				reltype = arg.lower()
			else:
				print 'Bad relation type'
				sys.exit(2)
		elif opt in ("--rel"):
			#Really simplistic verification, FIXME later
			if ":" in arg:
				rel6 = normalizeIP6(arg)
			else:
				rel4 = arg
		elif opt in ("--rel4"):
			rel4 = arg
		elif opt in ("--rel6"):
			rel6 = arg
		elif opt in ("--reldesc"):
			rdesc = arg


	#Some basic sanity checks
	# Commented to allow unknown source attacks.
	# if (s4 == '') and (s6 == ''):
	# 	print 'Source information is required'
	# 	sys.exit(2)
	#if (t4 == '') and (t6 == '') and (tname == ''):
	# 	print 'Some target information is required'
	# 	sys.exit(2)
	# if (pname == '') or (pprobe == '') or (pevidence == ''):
	# 	print 'Payload information is missing'
	# 	sys.exit(2)

	# Build the JSON data
	source['IPV4'] = s4
	source['IPV6'] = s6

	target['type'] = ttype
	target['IPV4'] = t4
	target['IPV6'] = t6
	target['name'] = tname

	payload['name'] = attack
	payload['probe'] = probe
	payload['evidence'] = evidence
	payload['url'] = url

	related['type'] = reltype
	related['IPV4'] = rel4
	related['IPV6'] = rel6
	related['description'] = reldesc

	data['source'] = source
	data['target'] = target
	data['payload'] = payload
	data['related'] = related


	json_data = json.dumps(data)
	#print json_data #debug print

	r = requests.post(eveurl, json_data, headers=headers)



def printhelp():
	print "Sends information to XS17 EVE visualization. Either one source or target address (or name) is mandatory. Attack name is required. Other fields are optional, however, providing more information is highly suggested. The entire related section is optional.\n"

	print "Possible arguments:\n\
	-s, --source  \t source address (auto-detects IPv4 or IPv6)\n\
	    --source4 \t source IPv4 address\n\
	    --source6 \t source IPv6 address\n\
	-t, --target  \t target address (auto-detects IPv4 or IPv6)\n\
	    --target4 \t target IPv4 address\n\
	    --target6 \t target IPv6 address\n\
	    --ttype   \t target type: 'host', 'network'\n\
	    --tname   \t target name\n\
	-a, --attack  \t attack name\n\
	-p, --probe   \t probe type: 'syslogs', 'snoopy', 'apache', 'honeystuff', 'ids', 'pcap', 'netflow', 'influx', 'other'\n\
	-e, --evidence\t attack evidence description\n\
	-u, --url     \t provide URL to more information\n\
	    --reltype \t relation type\n\
	    --rel4    \t related IPv4 address\n\
	    --rel6    \t related IPv6 address\n\
	    --reldesc \t relation description\n"

	#print "./send_to_eve.py [--s4 src_IP4_adr] [--s6 src_IP6_adr] [--tt host|network] [--t4 target_IP4_adr] [--t6 target_IP6_adr] [--tn target_name] --pn 'Attack name/type' --pp 'Probe type' --pe 'Attack description'"

def normalizeIP6(addr):
	try:
		internal = socket.inet_pton(socket.AF_INET6, addr)
		return socket.inet_ntop(socket.AF_INET6, internal)

	except socket.error:
		print "Invalid IPv6 address " + addr
		sys.exit(3)

if __name__ == "__main__":
   main(sys.argv[1:])
