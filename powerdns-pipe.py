#!/usr/bin/python -u
import time
from phpipam import PHPipam
import iptools
import sys
import logging
import logging.config
import os
import ConfigParser

path = os.path.dirname(os.path.abspath(__file__)) 

config = ConfigParser.ConfigParser()
config.read("%s/backend.conf"%path)

dns_server = config.get('dns', 'server').split(",") 

logging.config.fileConfig("%s/logging.conf" % path)

def responder(qname, qclass, qtype, qttl, qid, qcontent):
    response = "DATA\t%s\t%s\t%s\t%s\t%s\t%s" % (
        qname,
        qclass,
        qtype,
        qttl,
        qid,
        qcontent
    )
    sys.stdout.write("%s\n" % response)
    logging.debug(response)

while 1:
    try:
        line = sys.stdin.readline()
    except KeyboardInterrupt:
        break

    line = line.rstrip("\r\n")
    data = line.split("\t")

    if len(data) < 2:
        continue

    api = PHPipam(
        url=config.get('phpipam', 'url'),
        app_id=config.get('phpipam', 'app_id'),
        app_key=config.get('phpipam', 'app_key')
    )

    logging.debug(line)

    if data[0] == "HELO":
        response = "OK\tpython phpIPAM Backend Module ver 0.1 (PID %s)" % os.getpid()
        sys.stdout.write("%s\n" % response)
        logging.debug(response)

    if data[0] == "PING":
        sys.stdout.write("END\n")

    if data[0] == "AXFR":
        hosts = api.zone(domain)

        if hosts == False:
            sys.stdout.write("FAIL\n")
            continue

        responder(
            qname=domain,
            qclass="IN",
            qtype="SOA",
            qttl=3600,
            qid=-1,
            qcontent="%s %s %s 1800 3600 604800 3600" % (
                dns_server[0],
                config.get('dns', 'email'),
                time.strftime('%Y%m%d%H')
            )
        )

        i = 1 
        for server in dns_server:
            responder(
                qname = domain,
                qclass = "IN",
                qtype = "NS",
                qttl = 3600,
                qid = i,
                qcontent = server
            )

            i+=1

        for host in hosts:
            if domain.endswith('in-addr.arpa'):
                ip = host['ip'].split('.')
                arpa = "%s.%s.%s.%s.in-addr.arpa" % (ip[3], ip[2], ip[1], ip[0])
                responder(
                    qname = arpa,
                    qclass = "IN",
                    qtype = "PTR",
                    qttl = 3600,
                    qid = -1,
                    qcontent = host['host']
                )

            elif domain.endswith('ip6.arpa'):
                responder(
                    qname = host['ip6_rev'],
                    qclass = "IN",
                    qtype = "PTR",
                    qttl = 3600,
                    qid = -1,
                    qcontent = host['host']
                )

            else:
                if 'ip' in host.keys():
                    responder(
                        qname = host['host'],
                        qclass = "IN",
                        qtype = "A",
                        qttl = 3600,
                        qid = -1,
                        qcontent = host['ip']
                    )

                elif 'ip6' in host.keys():
                    responder(
                        qname = host['host'],
                        qclass = "IN",
                        qtype = "AAAA",
                        qttl = 3600,
                        qid = -1,
                        qcontent = host['ip6']
                    )

        sys.stdout.write("END\n")
        logging.debug("END")
 
    if data[0] == "Q":
        if len(data) < 5:
            logging.error("Q failed");
            sys.stdout.write("FAIL\n")
            continue

        hosts = api.lookup(data[1])
        
        if hosts == False:
            if api.zone(data[1]) == False:
                logging.error("No records");
                sys.stdout.write("FAIL\n")
                continue

            else:
                hosts = []

        domain = data[1]

        if data[3] == "SOA" or data[3] == "ANY":
            responder(
                qname = data[1],
                qclass = "IN",
                qtype = "SOA",
                qttl = 3600,
                qid = -1,
                qcontent="%s %s %s 1800 3600 604800 3600" % (
                    dns_server[0],
                    config.get('dns', 'email'),
                    time.strftime('%Y%m%d%H')
                )
            )

        if data[3] == "NS" or data[3] == "ANY":
            i=1

            for server in dns_server:
                responder(
                    qname = data[1],
                    qclass = "IN",
                    qtype = "NS",
                    qttl = 3600,
                    qid = i,
                    qcontent = server
                )

                i+=1

        if (data[3] == "A" or data[3] == "ANY") and not data[1].endswith('in-addr.arpa'):
            for host in hosts:
                if 'ip' in host.keys():
                    responder(
                        qname = data[1],
                        qclass = "IN",
                        qtype = "A",
                        qttl = 3600,
                        qid = i,
                        qcontent = host['ip'] 
                    )

        if (data[3] == "AAAA" or data[3] == "ANY") and not data[1].endswith('in-addr.arpa'):
            for host in hosts:
                if 'ip6' in host.keys():
                    responder(
                        qname = data[1],
                        qclass = "IN",
                        qtype = "A",
                        qttl = 3600,
                        qid = i,
                        qcontent = host['ip6'] 
                    )

        if (data[3] == "PTR" or data[3] == "ANY") and data[1].endswith('in-addr.arpa'):
            for host in hosts:
                ip = host['ip'].split('.')
                arpa = "%s.%s.%s.%s.in-addr.arpa" % (ip[3], ip[2], ip[1], ip[0])
                responder(
                    qname = arpa,
                    qclass = "IN",
                    qtype = "PTR",
                    qttl = 3600,
                    qid = i,
                    qcontent = host['host'] 
                )

        if (data[3] == "PTR" or data[3] == "ANY") and data[1].endswith('ip6.arpa'):
            for host in hosts:
                responder(
                    qname = data[1],
                    qclass = "IN",
                    qtype = "PTR",
                    qttl = 3600,
                    qid = i,
                    qcontent = host['host'] 
                )

        sys.stdout.write("END\n")
        logging.debug("END")
