import os
import sys
import cherrypy
import subprocess
import logging
import time

from . import confs

INDEX_HTML = '<html><body></body></html>'
CERT_PATH = ''
logger = logging.getLogger('dummytls')


class Root(object):
    @cherrypy.expose
    def index(self):
        return INDEX_HTML

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def keys(self):
        privkey = cert = chain = fullchain = ''
        try:
            if not CERT_PATH:
                raise FileNotFoundError('Missing certificate path')

            with open(os.path.join(CERT_PATH, 'cert.pem')) as f:
                cert = f.read()
            with open(os.path.join(CERT_PATH, 'chain.pem')) as f:
                chain = f.read()
            with open(os.path.join(CERT_PATH, 'fullchain.pem')) as f:
                fullchain = f.read()
            with open(os.path.join(CERT_PATH, 'privkey.pem')) as f:
                privkey = f.read()
        except ValueError as e:
            cherrypy.log(str(e))
        except FileNotFoundError as e:
            cherrypy.log(str(e))
        except Exception:
            cherrypy.log("Unexpected error:", sys.exc_info()[0])
        return {'privkey': privkey, 'cert': cert, 'chain': chain, 'fullchain': fullchain}

    @cherrypy.expose
    def favicon_ico(self):
        raise cherrypy.HTTPError(404)


def listCertificates():
    command = ['certbot', 'certificates']
    output = subprocess.Popen(command,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,
                              bufsize=1,
                              universal_newlines=True)
    current_certificate = ''
    current_domain = ''
    paths = {}
    for line in iter(output.stdout.readline, ''):
        if line.find('Certificate Name') > -1:
            current_certificate = line.split(':')[1].strip()
            continue
        elif line.find('Domains') > -1:
            domains = line.split(':')[1].strip()
            current_domain = domains
        elif line.find('Certificate Path') > -1:
            p = line.split(':')[1].strip()
            paths[domains] = os.path.dirname(p)
    return paths


def force_tls(self=None):
    # check if url is in https and redirect if http
    if cherrypy.request.scheme == "http":
        raise cherrypy.HTTPRedirect(cherrypy.url().replace("http:", "https:"), status=301)


def run(port, index, certpath=''):
    global INDEX_HTML, CERT_PATH
    try:
        with open(index) as f:
            INDEX_HTML = bytes(f.read(), "utf8")
    except Exception:
        pass

    naked_domain = confs.BASE_DOMAIN
    wildcard_domain = '*.' + confs.BASE_DOMAIN

    # get certificates
    try:
        paths = listCertificates()
        if naked_domain not in paths and wildcard_domain not in paths:
            logger.warn("Missing certificates, the HTTP server will only be started after renewal")
            while naked_domain not in paths and wildcard_domain not in paths:
                time.sleep(10)
                paths = listCertificates()

        CERT_PATH = paths[wildcard_domain]

    except Exception:
        logger.critical("Cannot list certificates: {}. Is certbot installed?".format(sys.exc_info()[0]))
        return

    cherrypy.config.update({
        'log.screen': False,
        'log.access_file': '',
        'log.error_file': 'http_error_log',
        'environment': 'production',
        'server.socket_host': '::',
        'server.socket_port': int(port)
    })

    if port == 443 and naked_domain in paths:
        logger.info('Starting TLS server.')
        cert = paths[naked_domain]
        cherrypy.tools.force_tls = cherrypy.Tool("before_handler", force_tls)
        cherrypy.config.update({
            'server.ssl_module': 'builtin',
            'server.ssl_certificate': os.path.join(cert, "cert.pem"),
            'server.ssl_private_key': os.path.join(cert, "privkey.pem"),
            'server.ssl_certificate_chain': os.path.join(cert, "fullchain.pem"),
            'tools.force_tls.on': True
        })

        # extra server instance to dispatch HTTP
        server = cherrypy._cpserver.Server()
        server.socket_host = '::'
        server.socket_port = 80
        server.subscribe()

    logger.info('Starting HTTP server.')
    cherrypy.quickstart(Root(), '/')
