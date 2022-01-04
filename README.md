# dummytls

This is a simple DNS server to provide dummy TLS support for any address. In short, it resolves addresses such as `203-0-113-1.yourdomain.net` to `203.0.113.1` and has a valid TLS certificate for them.

Technically it's a very simple DNS server written in Python, which uses [Let's Encrypt](https://letsencrypt.org/) to generate a wildcard certificate for `*.yourdomain.net` on a real public server. This certificate, both private and public keys, is available for download via a REST call on a simple HTTP server also provided.

dummytls is a fork of [localtls](https://github.com/Corollarium/localtls), originally developed by [Corollarium](https://corollarium.com). It is licensed under MIT license.

## Technical explanation and motivation

Browsers require <a href="https://w3c.github.io/webappsec-secure-contexts/">a secure context</a> (<a href="https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts">MDN</a>) for several Web APIs to work. While this is simple for public websites, it is a difficult issue for intranets and private IPs. When you're deploying applications on networks that you have no control, it's a nightmare.

This software provides:

1. a simple DNS server that resolves to `ADDRESS.yourdomain.net` (for local IP addresses, see below) to `ADDRESS` and should run on a public internet server.
1. an embedded simple HTTP server showing an `index.html` and with a REST endpoint with the certificate keys, including the private key.
1. a one-liner to generate and renew a valid certificate with LetsEncrypt, using DNS authentication. This script should be run once a month.

## What this DNS resolves

* `yourdomain.net` resolves to your server IP address, both A and AAAA (if it exists) records.
* `_acme-challenge.yourdomain.net` also resolves like this, since it's necessary for the certbot authentication.
* `a-b-c-d.yourdomain.net`, where `a.b.c.d` is a valid IPv4, resolves to A record `a.b.c.d`. In other words, replace `.` by `-`.
* `a-b-c-d--xxxx.yourdomain.net`, where `a:b:c:d::xxxx` is a valid IPv6, resolves to AAAA record of `a:b:c:d::xxxx`. In other words, replace any `:` by `-`.
* anything else falls back to another DNS server.

## Security considerations

"But if you provide the public and the private key, someone can do a man-in-the-middle attack!" Yes, that is correct. This is *as safe as a plain HTTP website if you release the private key*.

This service here aims to solve the *requirement of browsers with secure contexts in LANs with a minimum fuss*: when you are developing an app that requires TLS, for example, and want to test it on several devices locally. Or when you want to deploy a web application on customer networks that have no expertise. Hopefully browsers will come up with a solution that makes secure contexts in intranets easier in the future, but it has been a problem for years and it's still unsolved at this time.

In short, you have two possible scenarios. The first: you understand that by using this you may be prone for a MITM attack, but you need a secure context in the browser no matter what, and you do need absolute certainty that your traffic will not be snooped or your application won't be spoofed. This works for most webservices running in a LAN, and is as safe as running them on pure HTTP.

The second: you need not only a secure context for the browser, but actual safety of a private TLS certificate validated by the browser. In this case you can run the DNS server yourself and not publish the private keys, but find someway to distribute them yourself privately to your application. Remember, any application you deploy using TLS will require a private key deployed with it. When distributing web apps that are supposed to run in intranets which you have no access this is hard to do; you'd ideally need to generate a different key for every host, even though they may use the same private IP, you have no accessto a local nameserver and other complications. There is a [nice proposal of how this can be done](https://blog.heckel.io/2018/08/05/issuing-lets-encrypt-certificates-for-65000-internal-servers/) if you need this level of security.

# How to Run

## Overview

1. Get a server. It doesn't need to be big. Ideally you should have at least one slave, too, because NS entries require at least two servers.
1. Point the NS entry of your domain to this server.
1. [Installing](#install).
1. [Running the server](#run-the-server).
1. [Obtaining certificates](#obtain-certificates).

## Installing

### Virtual environment

First, make sure the Let's Encrypt client `certbot` is installed. Then, you should setup a virtual environment:
```
$ virtualenv env
$ source env/bin/activate
$ pip install -r requirements.txt
```

### Docker

Alternatively, a `Dockerfile` is available to build a container:
```
$ docker build .
```

Then you can run dummytls as follows:
```
$ docker run --network host [container] dummytls run --domain yourdomain.net [...]
```

Using network `host` is not mandatory, however if you don't, you must specify the `--domain-ipv4` and `--domain-ipv6` options.

## Testing locally

Run locally like this for a minimal test at port 5300:

```
$ python -m dummytls run --domain=yourdomain.net --dns-port=5300
```

Run dig to test:

```
$ dig @localhost -p 5300 +nocmd 192-168-0-255.yourdomain.net ANY +multiline +noall +answer
```

## Running the server

You probably want to run the server in production like this:

```
$ python -m dummytls run --domain yourdomain.net --soa-master=ns1.yourdomain.net --soa-email=email@yourdomain.net --ns-servers=ns1.yourdomain.net,ns2.yourdomain.net --log-level ERROR --http-port 80 --http-index /somewhere/index.html
```

Run `python -m dummytls run --help` for a list of arguments.

* `--domain`: The domain or subdomain (REQUIRED)
* `--soa-master`: Primary master name server for SOA record (STRONGLY RECOMMENDED)
* `--soa-email`: E-mail address for SOA record (STRONGLY RECOMMENDED)
* `--ns-servers`: Comma-separated list of nameservers for NS records (STRONGLY RECOMMENDED)
* `--dns-port`: DNS server port (default 53, note you need to be root on linux to run this on a port below 1024.)
* `--dns-fallback`: Fallback DNS server
* `--domain-ipv4`: IPv4 address for the naked domain (default local IPV4 address)
* `--domain-ipv6`: IPv6 address for the naked domain (default local IPv6 address)
* `--http-port`: HTTP server port (If not set, no HTTP server is started. It serves an index.html on `/` and the keys on `/keys`.)
* `--http-index-file`: Path to the HTTP index.html file (The file is read on start and cached.)
* `--log-level`: The log level: DEBUG|INFO|WARNING|ERROR
* `--only-private`: Only resolve private IP addresses
* `--no-reserved`: Don't resolve reserved IP addresses

This software uses port 6000 for internal communication. It is bound to 127.0.0.1.

To run a secondary DNS server, do the same without `--http-port`. Remember to set `--domain-ipv4` and `--domain-ipv6` pointing to the master server. You don't need certificates on the secondary server.

## Obtaining the certificates

You should renew keys once a month, according to the recommendation of Let's Encrypt. Run this with the proper domain:

```
$ python -m dummytls wildcard yourdomain.net email@yourdomain.net
```

If you wish to generate a certificate for the naked domain
```
$ python -m dummytls naked yourdomain.net email@yourdomain.net
````

Here's a cron line to run it monthly:

```
0 0 1 * * python -m /path/to/dummytls wildcard yourdomain.net email@yourdomain.net; python -m /path/to/dummytls naked yourdomain.net email@yourdomain.net
```

# Using this in your webservice

You should fetch the keys remotely before you open your webservice. Keys are valid for three months, but renewed every month. If your service runs continuously for longer than that you should either restart the service or make it poll and replace the keys every 24h or so.

First, make sure you run with `--http-port`. Make an HTTP GET request on `yourdomain.net/keys.json` and you'll get a JSON with the following key:

* `privkey`: the private key.
* `cert`: the public certificate.
* `chain`: the chain certificate.
* `fullchain`: the full chain certificate.

This follows the same pattern of files created by Let's Encrypt.

## Node.js code

This code will try to get the keys until a timeout and open a HTTPS server using those keys locally. Remember to replace `yourdomain.net`.

```
function dummytls(dnsserver) {
	const request = require('request');
	return new Promise(function(resolve, reject) {
		request({
			uri: dnsserver + '/keys',
			timeout: 10000,
		}, function (error, response, body) {
			if (error) {
				reject(error);
			}
			else {
				try {
					let d = JSON.parse(body);
					resolve({key: d.privkey, cert: d.cert, ca: d.chain});
				}
				catch (e) {
					reject(e);
				}
			}
		});
	});
}

var app = express(), https;
try {
	let keys = await dummytls('http://yourdomain.net');

	// reload keys every week, see https://github.com/nodejs/node/issues/15115
	let ctx = tls.createSecureContext(keys);
	setInterval(() => {
		lantls().then((k) => { keys = k; }).catch(e => {});
	}, 7*24*60*60*1000);

	https = require('https').createServer({
		SNICallback: (servername, cb) => {
			cb(null, ctx);
		}
	}, app);
}
catch(e) {
	// pass
	console.log("invalid https", e);
}
```


# About and credits

dummytls is a fork of [localtls](https://github.com/Corollarium/localtls), originally developed by [Corollarium](https://corollarium.com) and released under MIT license. The inspiration orginally comes from [nip.io](https://nip.io), [SSLIP](https://sslip.io), and [XIP](http://xip.io/).

