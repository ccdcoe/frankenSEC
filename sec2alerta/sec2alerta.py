#!/usr/bin/python3

import argparse
import json
import requests
import time
import logging
import socket
import sys
import re
import os
import errno

#pip3 install iso8601
import iso8601

# from alertaclient.api import Client
LOG = logging.getLogger("sec2alerta")
logging.basicConfig(format="%(asctime)s - %(name)s: %(levelname)s - %(message)s", level=logging.DEBUG)

header = {"Content-type": "application/json"}
if "ALERTA_ENDPOINT" in os.environ:
    alerta_srv = os.environ["ALERTA_ENDPOINT"]
    LOG.debug("Using alerta endpoint {} from environment".format(alerta_srv))
else:
    alerta_srv = "http://localhost:8080/api/alert"
    LOG.debug("Using default alerta endpoint {}".format(alerta_srv))

TS_KEYS = ["timestamp", '@timestamp']
metakey = "gamemeta"
sender = metakey + "!Host" # Flattened JSON
senderIP = metakey + "!IP"
srckey = metakey + "!Src"
destkey = metakey + "!Dest"
srcAlias = srckey + "!Host"
destAlias = destkey + "!Host"
srcIP = srckey + "!IP"
destIP = destkey + "!IP"

strip_keywords = [
    "Potential ",
    "Potentially ",
    "Suspicious ",
    "Behavioral ",
    "ET SCAN ",
    "ETPRO ",
    "ET POLICY ",
    "GPL ",
    "^ET ",
]
mod_keyw = r'{}'.format('|'.join(strip_keywords))

# Toned down for XS, should differ for production environments
SURICATA_SEVERITY_MAP = {
    1: "major",
    2: "minor",
    3: "warning",
    4: "informational",
}
SYSLOG_SEVERITY_MAP = {
    "emerg":   "critical",
    "alert":   "critical",
    "crit":    "major",
    "err":     "minor",
    "warning": "warning",
    "notice":  "normal",
    "info":    "informational",
    "debug":   "debug",
}
WINLOGON_TYPE_MAP = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteracive",
    11: "CachedInteractive",
}

def suricata_severity_to_code(level):
    return SURICATA_SEVERITY_MAP.get(level, "unknown")

def syslog_severity_to_code(level):
    return SYSLOG_SEVERITY_MAP.get(level, "unknown")

def winlogon_decode(level):
    return WINLOGON_TYPE_MAP.get(level, "Unknown")

# == Prepare POST data main
def prepare_data(data):
    post_data = dict()

    post_data['createTime'] = int(get_timestamp(data))
    post_data['timeout'] = get_timeout(data)
    post_data['environment'] = (data['environment'] if "environment" in data else args.env)
    post_data['severity'] = get_severity(data)
    #post_data['type'] = data['kafka.key']
    post_data['resource'] = genResource(data)
    post_data['correlate'], post_data['event'] = genEvent(data)
    #post_data['correlate'] = genCorrelate(data[srcAlias], data[destAlias])
    post_data['value'] = genValue(data)
    #post_data['attributes'] = genAttributes(data)
    post_data['text'] = genText(data)
    post_data['service'] = genService(data)
    return post_data


def get_timestamp(data):
    if args.overridets:
        return currentTs()
    elif "createTime" in data:
        return parseTs(data['createTime'])
    else:
        for key in TS_KEYS:
            if key in data:
                return parseTs(data[key])
            #else:
            #    LOG.warning("No known timestamp field in message: " + str(data))
    return currentTs()


def currentTs():
    return str(time.time()).split(".")[0]


def parseTs(ts):
    ts = str(ts)
    isnum = False
    try:
        if ts.isnumeric():
            isnum = True
    except:
        isnum = False

    if isnum:
        try:
            assert int(ts) > 0, "Expecting timestamp to be a positive integer"
            return ts
        except Exception as err:
            LOG.warning("Could not parse numeric ts: " + str(ts) + ", because: " + str(err))
    else: # Perhaps just do .egex matching to avoid try:except blocks
        try: # iso8601
            pTs = iso8601.parse_date(ts).timestamp()
            return str(pTs).split(".")[0]
        except Exception as err:
            LOG.debug("Could not parse ts as iso8601 string: " + str(ts) + ", because: " + str(err))

        if ts.count(".") == 1 or ts.count(",") == 1:
            try: # maybe it's just a float...
                f1, f2 = re.split('\.|,', ts) # has to have 2 fields
                int(f2) # test
                return int(f1)
            except Exception as err:
                LOG.debug("Could not parse ts as float: " + str(ts) + ", because: " + str(err))
    LOG.warning("Parsing " + str(ts) + " as a valid timestamp failed")


### Timeout handling ###
def get_timeout(data):
    if args.overrideto:
        return args.timeout
    elif "timeout" in data:
        try:
            return int(data['timeout'])
        except Exception as err:
            LOG.warning("Could not use existing timeout: " + str(data['timeout']) + ", because: " + str(err))
    else:
        return args.timeout


### Severity handling ###
def get_severity(data):
    severity = "informational"
    if "alert!severity" in data:
        return suricata_severity_to_code(data['alert!severity'])
    elif "syslog_severity" in data:
        return syslog_severity_to_code(data['syslog_severity'])
    return severity


### Resource field generating from two girls name
def genResource(data):
    names = list()

    if "resource" in data and data["resource"] is not "null":
        return data['resource']
    else:
        if destAlias in data:
            names.append(data[destAlias])
        if srcAlias in data:
            names.append(data[srcAlias])
        if len(names) == 0:
            if sender in data:
                names.append(data[sender])
    sorted_name = ', '.join(sorted(names))
    return sorted_name


### Event string creation ###
def genEvent(data):
    event = "-"
    correlate = list()
    src = ""
    dst = ""
    sep = " -> "

    if "event" in data and data["event"] is not "-":
        event = data['event']
    else:
        if destkey in data: #means "Dest": None
            dst = ""
            sep = ""
        elif destAlias in data:
            dst = data[destAlias]
    
        if srckey in data: #means "Src": None
            src = ""
            sep = ""
        elif srcAlias in data:
            src = data[srcAlias]
    
        event = src + sep + dst
        c1 = dst + sep + src

        if c1 in event:
            correlate = [event]
        else:
            correlate = [event, dst + sep + src]
        
        if len(event) == 0:
            if sender in data:
                event = data[sender]
                correlate = [event]

    return correlate, event


### Event string creation ###
def genCorrelate(src, dst):
    corr = [genEvent(src, dst), genEvent(dst, src)]
    return corr


### Event string creation ###
def genValue(data):
    values = list()
    value = ""
    if "value" in data and data["value"] is not "-":
        if "GetLogonType" in data["value"] and "LogonType" in data:
            return (winlogon_decode(int(data['LogonType'])) + " logon")
        else:
            return data['value']
    else:
        if srcIP in data:
            values.append(normalizeIP(data[srcIP]))
        if destIP in data:
            values.append(normalizeIP(data[destIP]))
        if len(values) == 0:
            if senderIP in data:
                value = normalizeIP(data[sender])

    if len(values) > 1:
        sep = " -> "
        value = sep.join(values)
        if "p" in data:
            data["dest_port"] = data["p"]
        if "dest_port" in data and "proto" in data:
            value = value + " " + str(data['dest_port']) + "_" + data['proto']
            
    return value
########################


### Attributes generation ###
# Having attributes is highly optional, so add or remove as necessary
def genAttributes(data):
    attr = dict()
    if "alert!signature_id" in data:
        attr['sid'] = data['alert.signature_id']
    #if "net_info" in data:
    #    attr.update(data["net_info"])
    return attr

#############################


def normalizeIPv6(addr):
    try:
        internal = socket.inet_pton(socket.AF_INET6, addr)
        return socket.inet_ntop(socket.AF_INET6, internal)
    except socket.error:
        LOG.warning("Invalid IPv6 address " + addr)
        return "Invalid IPv6 addr"

def normalizeIP(addr):
    addr = normalizeIPv6(addr) if str(addr).find(":")>=0 else addr
    return addr

### Generating text from alerts
def genText(data):
    if "text" in data:
        # Trim very long output
        return re.sub('\<|\>|;|\$|\!|', "", data["text"])[:150]
    if "alert!signature" in data:
        return re.sub(mod_keyw, "",  data["alert!signature"])
    else:
        return "" #TODO FIXME

def genService(data):
    if "service" in data:
        if data["service"] is not "-":
            return [data["service"]]
    elif "kafka!key" in data:
        return [data["kafka!key"]]
    elif "syslog_program" in data:
        return [data["syslog_program"]]
    else:
        return ["-"]

# == Send POST data to Alerta
def sendPost(line):
    data = dict()
    try:
        data = json.loads(line, encoding="utf-8")
    except Exception as err:
        LOG.info("Decoding JSON error: " + err)
    # Prepeare POST data
    data = prepare_data(data)
    post_data = json.dumps(data)
    #print('"{0}"'.format(data))
    print(post_data)
    try:
        print("Posting")
        resp = requests.post(alerta_srv, data=post_data, headers=header)
        print("{} {}".format(str(resp.status_code), resp.reason))
    except Exception as err:
        print(err)

def main(argv):
    #Sanity checks
    if args.fifo == "":
        print("FIFO path required")
        sys.exit(2)
    while True:
        LOG.debug("Opening FIFO " + args.fifo)
        try:
            with open(args.fifo, encoding='utf8') as fh:
                LOG.info("FIFO opened")
                while True:
                    line = fh.readline()
                    LOG.info(line)
                    if len(line) == 0:
                        LOG.info("Writer closed")
                        break
                    if len(line) < 4:
                        continue

                    sendPost(line)
        except KeyboardInterrupt:
            print("") # Cosmetics for console readability
            LOG.info("Keyboard interrupt (CTRL+C) received. Exiting...")
            sys.exit(3)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=True,
                                     description='Take suricata alerts and send to alerta dashboard')

    parser.add_argument("--environment",
        dest="env",
        default="Production",
        help="Set the alerta environment namespace. NB! These have to be predefined in alerta.")
    parser.add_argument("--fifo",
        dest="fifo",
        required=True,
        help="FIFO/pipe path to read from.")
    parser.add_argument("--overrideto",
        dest="overrideto",
        action="store_true",
        help="Override JSON timeout value (if one exists)")
    parser.add_argument("--overridets",
        dest="overridets",
        action="store_true",
        help="Override JSON timestamp value (if one exists)")
    parser.add_argument("--timeout",
        dest="timeout",
        default=900,
        type=int,
        help="Provide a fixed timeout value") #TODO: implement 0 for no timeout
    args = parser.parse_args()

    main(sys.argv[1:])    
