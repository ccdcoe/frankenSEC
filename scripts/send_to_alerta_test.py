#!/usr/bin/python
"""
Script to to Alerta
"""

import sys, getopt
import requests
import json
import socket


def main(argv):
	eveurl='http://1.2.3.4:8080/alert'
	headers = {'Content-type': 'application/json; charset=UTF-8'}
	ttypes = ['host', 'network']
	probes = ['syslogs', 'snoopy', 'apache', 'honeystuff', 'ids', 'pcap', 'netflow', 'influx', 'other']
	reltypes = ['honeystuff', 'other']
	status = 'open'
	environment = 'Production'
	severity = 'Major'
	group = 'Misc'
	id = '[sec] '

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
	rel = ''
	rel4 = ''
	rel6 = ''
	reldesc = ''

	data = {}
	service = []
	correlate = []
	tags = []
	attributes = {}


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
                        if ":" in arg:
                                s = normalizeIP6(arg)
                        else:
                                s = arg
		elif opt in ("-t", "--target"):
                        if ":" in arg:
                                t = normalizeIP6(arg)
                        else:
                                t = arg
		elif opt in ("--ttype"):
			if arg.lower() in ttypes:
				ttype = arg.lower()
			else:
				print 'Bad target type'
				sys.exit(2)
		elif opt in ("--tname"):
			if t == '':
				t = arg
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
                        if ":" in arg:
                                rel = normalizeIP6(arg)
                        else:
                                rel = arg
		elif opt in ("--reldesc"):
			rdesc = arg


	# Severity determination
	if 'snoopy' in probe:
		severity = 'Warning'


	# Build the JSON data
	data['type'] = ttype
	data['value'] = t
	data['resource'] = s
	data['event'] = id + attack
	data['origin'] = probe
	data['text'] = id + evidence
	data['status'] = status
	data['environment'] = environment
	data['severity'] = severity
	data['group'] = group

	data['tags'] = tags
	data['service'] = [probe]
	data['correlate'] = correlate
	data['attributes'] = attributes


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
