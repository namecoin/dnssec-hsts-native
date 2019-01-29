# DNSSEC-HSTS Native Component

DNSSEC-HSTS is a WebExtension that upgrades HTTP to HTTPS (simulating HSTS) for websites that support DANE (i.e. websites that list a TLSA record for TCP port 443).  This is a reasonably good heuristic for preventing sslstrip-style attacks.

This repository is for the native (Go) component of DNSSEC-HSTS.

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
