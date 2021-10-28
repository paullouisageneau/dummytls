#!/usr/bin/env python

import os
import sys
import json
from multiprocessing.connection import Client

# To simulate certbot DNS hooks:
# CERTBOT_DOMAIN=yourdomain.net CERTBOT_VALIDATION=xxx python3 certbottxt.py deploy
# CERTBOT_DOMAIN=yourdomain.net CERTBOT_VALIDATION=xxx CERTBOT_AUTH_OUTPUT=_acme-challenge.asdf.com python3 certbottxt.py cleanup

BASE_PATH = os.path.realpath(__file__)
CERTBOT_DOMAIN = os.getenv('CERTBOT_DOMAIN')
CERTBOT_VALIDATION = os.getenv('CERTBOT_VALIDATION')
LOCAL_ADDRESS = ('localhost', 6000)
SECRET_KEY = os.getenv('SECRET_KEY', b'secret')


def help():
    print("usage: {} [deploy|cleanup]\n".format(sys.argv[0]))


if len(sys.argv) == 1:
    help()

if sys.argv[1] == 'deploy':
    with Client(LOCAL_ADDRESS, authkey=SECRET_KEY) as conn:
        DOMAIN = "_acme-challenge.{}".format(CERTBOT_DOMAIN)
        conn.send(json.dumps({
            'command': 'ADDTXT',
            'key': DOMAIN,
            'val': CERTBOT_VALIDATION
        }, ensure_ascii=False, indent=4))

elif sys.argv[1] == 'cleanup':
    with Client(LOCAL_ADDRESS, authkey=SECRET_KEY) as conn:
        CERTBOT_AUTH_OUTPUT = os.getenv('CERTBOT_AUTH_OUTPUT', '*')
        conn.send(json.dumps({
            'command': 'REMOVETXT',
            'key': CERTBOT_AUTH_OUTPUT
        }, ensure_ascii=False, indent=4))

else:
    help()
    sys.exit(1)
