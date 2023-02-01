```
cargo run --bin mac-n-cheese-runner -- --event-log prover.mclog --address 127.0.0.1:8080 --circuit small-f61p -r mac-n-cheese/runner/test-certs/rootCA.crt -k mac-n-cheese/runner/test-certs/galois.macncheese.example.com.pem prove small-f61p.priv


cargo run --bin mac-n-cheese-runner -- --event-log verifier.mclog --address 127.0.0.1:8080 --circuit small-f61p -r mac-n-cheese/runner/test-certs/rootCA.crt -k mac-n-cheese/runner/test-certs/galois.macncheese.example.com.pem verify

```
