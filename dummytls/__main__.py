#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

import json
import logging
import os
import sys
import signal
import socket
import argparse
import ipaddress
import threading
from time import sleep
from multiprocessing.connection import Listener

from dnslib.server import DNSServer, DNSLogger

from . import dnsserver
from . import httpserver
from . import confs

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))
logger = logging.getLogger('dummytls')
logger.addHandler(handler)


def get_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = ''
    finally:
        s.close()
    return IP


def get_ipv6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    try:
        s.connect(('2001:0db8:85a3:0000:0000:8a2e:0370:7334', 1))
        IP = s.getsockname()[0]
    except:
        IP = ''
    finally:
        s.close()
    return IP


def handle_sig(signum, frame):
    logger.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)


# this is used to hear for new TXT records from the certbotdns script. We need to get them ASAP to
# validate the certbot request.
def messageListener():
    global TXT_RECORDS
    address = ('localhost', 6000)     # family is deduced to be 'AF_INET'
    listener = Listener(address, authkey=os.getenv('KEY', b'secret'))  # not very secret, but we're bound to localhost.
    while True:
        conn = None
        try:
            conn = listener.accept()
            msg = conn.recv()
            # do something with msg
            msg = json.loads(msg, encoding="utf-8")
            if msg['command'] == "ADDTXT":
                TXT_RECORDS[msg["key"]] = msg["val"]
            elif msg['command'] == "REMOVETXT":
                TXT_RECORDS.pop(msg["key"])
            conn.close()
        except Exception as e:
            logger.error(e)
            if conn:
                conn.close()
            pass
    listener.close()


def main():
    signal.signal(signal.SIGTERM, handle_sig)

    parser = argparse.ArgumentParser(prog='dummytls', description='DummyTLS')
    parser.add_argument(
        '--domain',
        required = True,
        help = "Your domain or subdomain."
    )
    parser.add_argument(
        '--soa-master',
        help = "Primary master name server for SOA record. You should fill this."
    )
    parser.add_argument(
        '--soa-email',
        help = "Email address for administrator for SOA record. You should fill this."
    )
    parser.add_argument(
        '--ns-servers',
        help = "List of ns servers, separated by comma"
    )
    parser.add_argument(
        '--dns-port',
        default=53,
        help = "DNS server port"
    )
    parser.add_argument(
        '--domain-ipv4',
        default='',
        help = "The IPV4 for the naked domain. If empty, use this machine's."
    )
    parser.add_argument(
        '--domain-ipv6',
        default='',
        help = "The IPV6 for the naked domain. If empty, use this machine's."
    )
    parser.add_argument(
        '--only-private-ips',
        action='store_true',
        default=False,
        help = "Resolve only IPs in private ranges."
    )
    parser.add_argument(
        '--no-reserved-ips',
        action='store_true',
        default=False,
        help = "If true ignore ips that are reserved."
    )
    parser.add_argument(
        '--dns-fallback',
        default='1.1.1.1',
        help = "DNS fallback server. Default: 1.1.1.1"
    )
    parser.add_argument(
        '--http-port',
        help = "HTTP server port. If not set, no HTTP server is started"
    )
    parser.add_argument(
        '--http-index-file',
        default = 'index.html',
        help = "HTTP index.html file."
    )
    parser.add_argument(
        '--log-level',
        default = 'ERROR',
        help = "INFO|WARNING|ERROR|DEBUG"
    )
    args = parser.parse_args()

    # The primary addresses
    confs.LOCAL_IPV4 = args.domain_ipv4 if args.domain_ipv4 else get_ipv4()
    confs.LOCAL_IPV6 = args.domain_ipv6 if args.domain_ipv6 else get_ipv6()
    try:
        ipaddress.ip_address(confs.LOCAL_IPV4)
    except:
        logger.critical('Invalid IPV4 %s', confs.LOCAL_IPV4)
        sys.exit(1)
    try:
        if confs.LOCAL_IPV6:
            ipaddress.ip_address(confs.LOCAL_IPV6)
    except:
        logger.critical('Invalid IPV6 %s', confs.LOCAL_IPV6)
        sys.exit(1)
    logger.setLevel(args.log_level)

    confs.ONLY_PRIVATE_IPS = args.only_private_ips
    confs.NO_RESERVED_IPS = args.no_reserved_ips
    confs.BASE_DOMAIN = args.domain
    confs.SOA_MNAME = args.soa_master
    confs.SOA_RNAME = args.soa_email
    if not confs.SOA_MNAME or not confs.SOA_RNAME:
        logger.error('Setting SOA is strongly recommended')

    if args.ns_servers:
        confs.NS_SERVERS = args.ns_servers.split(',')

    # handle local messages to add TXT records
    threadMessage = threading.Thread(target=messageListener)
    threadMessage.start()

    # open the DNS server
    port = int(args.dns_port)
    upstream = args.dns_fallback
    resolver = dnsserver.Resolver(upstream)
    if args.log_level == 'debug':
        logmode = "+request,+reply,+truncated,+error"
    else:
        logmode = "-request,-reply,-truncated,+error"
    dnslogger = DNSLogger(log=logmode, prefix=False)
    udp_server = DNSServer(resolver, port=port, logger=dnslogger)
    tcp_server = DNSServer(resolver, port=port, tcp=True, logger=dnslogger)

    logger.critical('starting DNS server on %s/%s on port %d, upstream DNS server "%s"', confs.LOCAL_IPV4, confs.LOCAL_IPV6, port, upstream)
    udp_server.start_thread()
    tcp_server.start_thread()

    # open the HTTP server
    if args.http_port:
        logger.critical('Starting httpd...')
        threadHTTP = threading.Thread(target=httpserver.run, kwargs={"port": int(args.http_port), "index": args.http_index_file})
        threadHTTP.start()

    try:
        while udp_server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
     main()
