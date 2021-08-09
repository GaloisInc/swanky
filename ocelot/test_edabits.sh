#!/bin/bash

set -e

echo "PROVER: ${PROVER}"
echo "VERIFIER: ${VERIFIER}"

if [[ ! -z "${VERIFIER}" ]]; then
    #tc qdisc add dev eth0 root netem delay 200ms
    tc qdisc add dev eth0 root tbf rate 10000kbit latency 1000ms burst 1540
    cargo run --release --example lan_edabits -- -n 1000000 -b 5 -m 8 --quicksilver --addr verifier:5527
fi

if [[ ! -z "${PROVER}" ]]; then
    sleep 20
    tc qdisc add dev eth0 root tbf rate 10000kbit latency 1000ms burst 1540
    cargo run --release --example lan_edabits -- -n 1000000 -b 5 -m 8 --quicksilver --addr verifier:5527 --prover
fi
