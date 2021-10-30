import os
import json
import logging
import ipaddress
from multiprocessing.connection import Listener

import dnslib
from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib.proxy import ProxyResolver

from . import confs

logger = logging.getLogger('dummytls')

LOCAL_ADDRESS = ('localhost', 6000)
SECRET_KEY = os.getenv('SECRET_KEY', b'secret')

TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
}

TXT_RECORDS = {}


# this is used to hear for new TXT records from user commands
def message_listener():
    global TXT_RECORDS
    with Listener(LOCAL_ADDRESS, authkey=SECRET_KEY) as listener:
        while True:
            try:
                with listener.accept() as conn:
                    data = conn.recv()
                    msg = json.loads(data)
                    if msg['command'] == 'ADDTXT':
                        TXT_RECORDS[msg['key']] = msg['val']
                    elif msg['command'] == 'REMOVETXT':
                        TXT_RECORDS.pop(msg['key'])

            except Exception as e:
                logger.error(e)


class Resolver(ProxyResolver):
    def __init__(self, upstream):
        super().__init__(upstream, 53, 5)
        if confs.SOA_MNAME and confs.SOA_RNAME:
            self.SOA = dnslib.SOA(
                mname=DNSLabel(confs.SOA_MNAME),
                rname=DNSLabel(confs.SOA_RNAME.replace('@', '.')),  # TODO: . before @ should be escaped
                times=(
                    confs.SOA_SERIAL,  # serial number
                    60 * 60 * 1,   # refresh
                    60 * 60 * 2,   # retry
                    60 * 60 * 24,  # expire
                    60 * 60 * 1,   # minimum
                )
            )
        else:
            self.SOA = None

        if confs.NS_SERVERS:
            self.NS = [dnslib.NS(i) for i in confs.NS_SERVERS]
        else:
            self.NS = []

    def match_domain_insensitive(self, request):
        name = request.q.qname
        domain = str(name)[:-1].lower()  # skip the last dot
        return domain == confs.BASE_DOMAIN or domain == '_acme-challenge.' + confs.BASE_DOMAIN

    def match_suffix_insensitive(self, request):
        name = request.q.qname
        suffix = str(name)[-len(confs.BASE_DOMAIN)-1:-1].lower()  # skip the last dot
        return suffix == confs.BASE_DOMAIN

    def resolve(self, request, handler):
        global TXT_RECORDS
        logger.info("Query: %s", request.q.qname)

        reply = request.reply()

        # handle the main domain
        if self.match_domain_insensitive(request):
            r = RR(
                rname=request.q.qname,
                rdata=dns.A(confs.LOCAL_IPV4),
                rtype=QTYPE.A,
                ttl=60 * 60
            )
            reply.add_answer(r)

            if self.SOA:
                r = RR(
                    rname=request.q.qname,
                    rdata=self.SOA,
                    rtype=QTYPE.SOA,
                    ttl=60 * 60
                )
                reply.add_answer(r)

            if len(self.NS):
                for i in self.NS:
                    r = RR(
                        rname=request.q.qname,
                        rdata=i,
                        rtype=QTYPE.NS,
                        ttl=60 * 60
                    )
                    reply.add_answer(r)

            if confs.LOCAL_IPV6:
                r = RR(
                    rname=request.q.qname,
                    rdata=dns.AAAA(confs.LOCAL_IPV6),
                    rtype=QTYPE.AAAA,
                    ttl=60 * 60
                )
                reply.add_answer(r)

            if len(TXT_RECORDS):
                r = RR(
                    rname=request.q.qname,
                    rdata=dns.TXT(['{1}'.format(k, v) for k, v in TXT_RECORDS.items()]),
                    rtype=QTYPE.TXT
                )
                reply.add_answer(r)
            return reply

        # handle subdomains
        elif self.match_suffix_insensitive(request):
            name = str(request.q.qname)
            subdomains = name.split('.')
            if len(subdomains) == 4:  # TODO: dynamic
                ip = None
                try:
                    ip = ipaddress.ip_address(subdomains[0].replace('-', '.'))
                except Exception:
                    pass
                try:
                    if ip is None:
                        ip = ipaddress.ip_address(subdomains[0].replace('-', ':'))
                except Exception:
                    logger.info('Invalid IP address: %s', subdomains[0])
                    return reply

                # check if we only want private ips
                if not ip.is_private and confs.ONLY_PRIVATE:
                    return reply
                if ip.is_reserved and confs.NO_RESERVED:
                    return reply
                # check if it's a valid ip for a machine
                if ip.is_multicast or ip.is_unspecified:
                    return reply

                if type(ip) == ipaddress.IPv4Address:
                    ipv4 = subdomains[0].replace('-', '.')
                    logger.info("IP address is IPv4 %s", ipv4)
                    r = RR(
                        rname=request.q.qname,
                        rdata=dns.A(ipv4),
                        rtype=QTYPE.A,
                        ttl=24 * 60 * 60
                    )
                    reply.add_answer(r)
                elif type(ip) == ipaddress.IPv6Address:
                    ipv6 = subdomains[0].replace('-', ':')
                    logger.info("IP address is IPv6 %s", ipv6)
                    r = RR(
                        rname=request.q.qname,
                        rdata=dns.AAAA(ipv6),
                        rtype=QTYPE.AAAA,
                        ttl=24 * 60 * 60
                    )
                    reply.add_answer(r)
                else:
                    return reply

                logger.info('Found zone for %s, %d replies', request.q.qname, len(reply.rr))
            return reply

        elif self.address == "":
            return reply

        return super().resolve(request, handler)
