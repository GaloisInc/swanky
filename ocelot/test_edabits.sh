#!/bin/bash

set -e

echo "PROVER: ${PROVER}"
echo "VERIFIER: ${VERIFIER}"

if [[ ! -z "${PROVER}" ]]; then
    sleep 20
    cargo run --release --example lan_edabits -- -n 1000000 -b 3 -m 8 --quicksilver --prover
fi

if [[ ! -z "${VERIFIER}" ]]; then
    cargo run --release --example lan_edabits -- -n 1000000 -b 3 -m 8 --quicksilver
fi
