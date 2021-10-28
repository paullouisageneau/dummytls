import os
import sys
import json
import logging
import signal
import socket
import argparse
import ipaddress
import threading
import subprocess
from time import sleep
from multiprocessing.connection import Listener, Client
from dnslib.server import DNSServer, DNSLogger

from . import dnsserver
from . import httpserver
from . import confs

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))
logger = logging.getLogger('dummytls')
logger.addHandler(handler)

BASE_PATH = os.path.realpath(__file__)
LOCAL_ADDRESS = ('localhost', 6000)
SECRET_KEY = os.getenv('SECRET_KEY', b'secret')


def get_ipv4():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1', 9))  # not reachable
            return s.getsockname()[0]
    except Exception:
        return ''


def get_ipv6():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(('2001:db8::1', 9))  # not reachable
            return s.getsockname()[0]
    except Exception:
        return ''


def handle_sig(signum, frame):
    logger.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)


# this is used to hear for new TXT records from user commands
def messageListener():
    global TXT_RECORDS
    listener = Listener(LOCAL_ADDRESS, authkey=SECRET_KEY)
    while True:
        conn = None
        try:
            conn = listener.accept()
            msg = conn.recv()
            # do something with msg
            msg = json.loads(msg)
            if msg['command'] == 'ADDTXT':
                TXT_RECORDS[msg['key']] = msg['val']
            elif msg['command'] == 'REMOVETXT':
                TXT_RECORDS.pop(msg['key'])
            conn.close()
        except Exception as e:
            logger.error(e)
            if conn:
                conn.close()
            pass
    listener.close()


def run(raw_args):
    parser = argparse.ArgumentParser(prog='dummytls run', description='Run DummyTLS server')
    parser.add_argument(
        '--domain',
        required=True,
        help="The domain or subdomain"
    )
    parser.add_argument(
        '--soa-master',
        help="Primary master name server for SOA record (Default: none)"
    )
    parser.add_argument(
        '--soa-email',
        help="Administrator e-mail address for SOA record (Default: none)"
    )
    parser.add_argument(
        '--ns-servers',
        help="List of ns servers, separated by comma (Default: none)"
    )
    parser.add_argument(
        '--dns-port',
        default=53,
        help="DNS server port (Default: 53)"
    )
    parser.add_argument(
        '--domain-ipv4',
        default='',
        help="The IPv4 for the naked domain (Default: local IPv4 address)"
    )
    parser.add_argument(
        '--domain-ipv6',
        default='',
        help="The IPv6 for the naked domain (Default: local IPv6 address)"
    )
    parser.add_argument(
        '--only-private',
        action='store_true',
        default=False,
        help="If true, resolve only private IP addresses"
    )
    parser.add_argument(
        '--no-reserved',
        action='store_true',
        default=False,
        help="If true, ignore reserved IP addresses"
    )
    parser.add_argument(
        '--dns-fallback',
        default='9.9.9.9',
        help="DNS fallback server (Default: 9.9.9.9)"
    )
    parser.add_argument(
        '--http-port',
        help="HTTP server port (Default: disabled)"
    )
    parser.add_argument(
        '--http-index-file',
        default='index.html',
        help="HTTP index.html file."
    )
    parser.add_argument(
        '--log-level',
        default='WARNING',
        help="The log level: DEBUG|INFO|WARNING|ERROR (Default: WARNING)"
    )
    args = parser.parse_args(raw_args)

    signal.signal(signal.SIGTERM, handle_sig)
    logger.setLevel(args.log_level)

    confs.BASE_DOMAIN = args.domain
    if not confs.BASE_DOMAIN:
        logger.critical('Invalid domain: "%s"', confs.BASE_DOMAIN)
        sys.exit(1)

    confs.LOCAL_IPV4 = args.domain_ipv4 if args.domain_ipv4 else get_ipv4()
    confs.LOCAL_IPV6 = args.domain_ipv6 if args.domain_ipv6 else get_ipv6()
    try:
        ipaddress.ip_address(confs.LOCAL_IPV4)
    except Exception:
        logger.critical('Invalid IPv4: "%s"', confs.LOCAL_IPV4)
        sys.exit(1)
    try:
        if confs.LOCAL_IPV6:
            ipaddress.ip_address(confs.LOCAL_IPV6)
    except Exception:
        logger.critical('Invalid IPv6: "%s"', confs.LOCAL_IPV6)
        sys.exit(1)

    confs.SOA_MNAME = args.soa_master
    confs.SOA_RNAME = args.soa_email
    if not confs.SOA_MNAME or not confs.SOA_RNAME:
        logger.error('Setting SOA master and email is strongly recommended to be compliant wth RFC 1035')

    confs.NS_SERVERS = args.ns_servers.split(',') if args.ns_servers else []
    if not confs.NS_SERVERS:
        logger.error('Setting NS servers is strongly recommended to be compliant with RFC 1035')

    confs.ONLY_PRIVATE = args.only_private
    confs.NO_RESERVED = args.no_reserved

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

    logger.critical('Starting DNS server on port %d, upstream DNS server "%s"',
                    port,
                    upstream)
    udp_server.start_thread()
    tcp_server.start_thread()

    # open the HTTP server
    if args.http_port:
        logger.critical('Starting httpd...')
        threadHTTP = threading.Thread(target=httpserver.run, kwargs={
            'port': int(args.http_port),
            'index': args.http_index_file
        })
        threadHTTP.start()

    try:
        while udp_server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        pass


def renew(raw_args):
    parser = argparse.ArgumentParser(prog='dummytls renew', description='Renew certificate')
    parser.add_argument(
        '--domain',
        required=True,
        help="The domain or subdomain"
    )
    parser.add_argument(
        '--email',
        required=True,
        help="Administrator e-mail address"
    )
    args = parser.parse_args(raw_args)

    if not args.domain:
        logger.critical('Invalid domain: "%s"', args.domain)
        sys.exit(1)

    if not args.email and '@' not in args.email:
        logger.critical('Invalid e-mail: "%s"', args.email)
        sys.exit(1)

    naked_domain = args.domain
    wildcard_domain = '*.' + args.domain

    for domain in naked_domain, wildcard_domain:
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certbot.py')
        command = [
            'certbot', 'certonly', '--noninteractive',  # TEST: '--test-cert',
            '--agree-tos', '--email', args.email,
            '--manual', '--preferred-challenges=dns', '--manual-public-ip-logging-ok',
            '--manual-auth-hook', 'python3 {} deploy'.format(script),
            '--manual-cleanup-hook', 'python3 {} cleanup'.format(script),
            '-d', domain
        ]
        output = subprocess.run(command)
        print(output.stdout)
        print(output.stderr)
        output.check_returncode()


def help():
    print("usage: dummytls [run|wildcard|naked] [args...]\n")


def main():
    if len(sys.argv) == 1:
        help()
        sys.exit(1)

    if sys.argv[1] == 'help' or sys.argv[1] == '--help' or sys.argv[1] == '-h':
        help()
        sys.exit(0)

    if sys.argv[1] == 'run':
        run(sys.argv[2:])
    elif sys.argv[1] == 'renew':
        renew(sys.argv[2:])
    else:
        help()
        sys.exit(1)


if __name__ == '__main__':
    main()
