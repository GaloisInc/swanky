#!/bin/bash

set -e

echo "PROVER: ${PROVER}"
echo "VERIFIER: ${VERIFIER}"

if [[ ! -z "${VERIFIER}" ]]; then
    tc qdisc add dev eth0 root netem delay 200ms
    cargo run --release --example lan_edabits -- -n 1000000 -b 3 -m 8 --quicksilver --addr verifier:5527
fi

if [[ ! -z "${PROVER}" ]]; then
    sleep 20
    cargo run --release --example lan_edabits -- -n 1000000 -b 3 -m 8 --quicksilver --prover --addr verifier:5527
fi
