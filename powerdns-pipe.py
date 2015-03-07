#!/usr/bin/python -u
import time
from phpipam import PHPipam
import iptools
import sys
import logging
import os
import ConfigParser

config = ConfigParser.ConfigParser()
config.read('backend.conf')

dns_server = config.get('dns','server').split(",") 

logging.basicConfig(filename='/var/log/pdns-pyphpipam.log',level=logging.DEBUG)

def responder(line):
    sys.stdout.write("%s\n" % line)
    logging.debug(line)

while 1:
    try:
        line = sys.stdin.readline()
    except KeyboardInterrupt:
        break

    line = line.rstrip('\r\n')
    data = line.split("\t")
    if len(data) < 2:
        continue
    api = PHPipam(config.get('phpipam','url'),config.get('phpipam','app_id'),config.get('phpipam','app_key'))
    logging.debug(line)
    if data[0] == "HELO":
        responder("OK\tpython phpIPAM Backend Module ver 0.1 (PID %s)"%(os.getpid()))
    if data[0] == "PING":
        responder("END")
    if data[0] == "AXFR":
        if not api.lookup(domain) and not api.zone(domain):
            responder("FAIL")
            continue
        responder("DATA\t%s\tIN\tSOA\t3600\t-1\t%s %s %s 1800 3600 604800 3600" % (domain,dns_server[0],config.get('dns','email'),time.strftime('%Y%m%d%H')))

        i = 1 
        for server in dns_server:
            responder("DATA\t%s\tIN\tNS\t3600\t%s\t%s" % (domain,i,server))
            i=i+1

        for host in api.zone(domain):
            if domain.endswith('in-addr.arpa'):
                ip = host['ip'].split('.')
                arpa = "%s.%s.%s.%s.in-addr.arpa" % (ip[3],ip[2],ip[1],ip[0])
                responder("DATA\t%s\tIN\tPTR\t3600\t-1\t%s" % (arpa,host['host']))
            else:
                responder("DATA\t%s\tIN\tPTR\t3600\t-1\t%s" % (host['host'],host['ip']))
        responder("END")
 
    if data[0] == "Q":
        if len(data) < 5:
            responder("FAIL")
            continue
            
        if not api.lookup(data[1]) and not api.zone(data[1]):
            responder("FAIL")
            continue
        domain = data[1]
        if data[3] == "SOA" or data[3] == "ANY":
            responder("DATA\t%s\tIN\tSOA\t3600\t-1\t%s %s %s 1800 3600 604800 3600" % (data[1],dns_server[0],config.get('dns','email'),time.strftime('%Y%m%d%H')))
        if data[3] == "NS" or data[3] == "ANY":
            i=1
            for server in dns_server:
                responder("DATA\t%s\tIN\tNS\t3600\t%s\t%s" % (data[1],i,server))
                i=i+1

        if (data[3] == "A" or data[3] == "ANY") and not data[1].endswith('in-addr.arpa'):
            hosts = api.lookup(data[1])
            if hosts != False:
                for host in hosts:
                    responder("DATA\t%s\tIN\tA\t3600\t-1\t%s" % (data[1],host['ip']))

        if data[3] == "PTR" or data[3] == "ANY" and data[1].endswith('in-addr.arpa'):
            hosts = api.lookup(data[1])
            if hosts != False:
                for host in hosts:
                    ip = host['ip'].split('.')
                    arpa = "%s.%s.%s.%s.in-addr.arpa" % (ip[3],ip[2],ip[1],ip[0])
                    responder("DATA\t%s\tIN\tPTR\t3600\t-1\t%s" % (arpa,host['host']))
        responder("END")
