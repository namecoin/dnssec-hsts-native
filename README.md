# DNSSEC-HSTS Native Component

DNSSEC-HSTS is a WebExtension that upgrades HTTP to HTTPS (simulating HSTS) for websites that support DANE (i.e. websites that list a TLSA record for TCP port 443).  This is a reasonably good heuristic for preventing sslstrip-style attacks.

This repository is for the native (Go) component of DNSSEC-HSTS.  The native component is a fork of Miek Gieben's excellent `q` tool.

## Installation

Firefox for GNU/Linux:

~~~
go get github.com/namecoin/dnssec-hsts-native/src/dnssec_hsts
sudo cp $GOPATH/src/github.com/namecoin/dnssec-hsts-native/setup/dnssec_hsts.json /usr/lib64/mozilla/native-messaging-hosts/
sudo cp $GOPATH/bin/dnssec_hsts /usr/bin/
~~~

Then install [the WebExtensions component](https://github.com/namecoin/dnssec-hsts) of DNSSEC-HSTS.

On other OS's, it's probably similar but I haven't tried.  Check the WebExtensions docs or something.

Other browsers might or might not work, I haven't tried.  Check the WebExtensions docs or something.

# Original miekg/exdns README

[![Build Status](https://travis-ci.org/miekg/exdns.svg?branch=master)](https://travis-ci.org/miekg/exdns)
[![BSD 2-clause license](https://img.shields.io/github/license/miekg/exdns.svg?maxAge=2592000)](https://opensource.org/licenses/BSD-2-Clause)

# Examples made with Go DNS

This repository has a bunch of example programs that
are made with the https://github.com/miekg/dns Go package.

Currently they include:

* `as112`: an AS112 black hole server
* `chaos`: show DNS server identity
* `check-soa`: check the SOA record of zones for all nameservers
* `q`: dig-like query tool
* `reflect`: reflection nameserver
