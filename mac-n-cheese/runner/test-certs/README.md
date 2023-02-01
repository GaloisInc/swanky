# How to use
Run `make`, then pass `-r mac-n-cheese/runner/test-certs/rootCA.crt -k mac-n-cheese/runner/test-certs/galois.macncheese.example.com.pem` to both the prover and the verifier.

NOTE: this Makefile will not work if the openssl command is the default LibreSSL command that comes installed on macOS.

Consider using this on a mac:

```
brew install openssl && make OPENSSL=/opt/homebrew/opt/openssl@1.1/bin/openssl
```

# Security Warning

The certificates contained in this directory are FOR TESTING PURPOSES ONLY!!

DO NOT USE THESE CERTIFICATES (or, indeed, this sketchy certificate-generation Makefile) in production.
