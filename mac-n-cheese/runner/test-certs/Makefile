# Based on https://github.com/ctz/rustls/blob/fee894f7e030e7633ec4452c0df3dba57f48ac4a/test-ca/build-a-pki.sh

OPENSSL ?= openssl

all: rootCA.crt galois.macncheese.example.com.pem

clean:
	rm -f *.key *.pem *.crt *.csr *.openssl.cnf

%.key:
	$(OPENSSL) genpkey -algorithm Ed25519 -out $@

rootCA.crt: rootCA.key
	$(OPENSSL) req -nodes \
	    -x509 \
	    -key $< \
	    -out $@ \
	    -sha256 \
	    -batch \
	    -days 3650 \
	    -subj "/CN=mac and cheese CA"

%.csr: %.key
	$(OPENSSL) req -new -sha256 -key $< -batch -subj "/CN=$(patsubst %.key,%,$<)" -out $@

%.fullchain.crt: %.crt rootCA.crt
	cat $^ > $@

%.pem: %.key %.fullchain.crt
	cat $^ > $@

%.openssl.cnf: openssl.base.cnf
	cat $^ > $@
	echo "DNS.1 = $(patsubst %.openssl.cnf,%,$@)" >> $@

%.crt: %.csr %.openssl.cnf rootCA.crt rootCA.key
	$(OPENSSL) x509 -req -in $< -CA rootCA.crt -CAkey rootCA.key -set_serial 123 -out $@ -days 3650 -sha256 -extensions v3_end -extfile $(patsubst %.csr,%.openssl.cnf,$<)

.PRECIOUS: %.key %.crt
.PHONY: all clean
