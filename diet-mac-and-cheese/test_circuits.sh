#!/bin/bash

# Integration tests for diet Mac'n'Cheese
# (Run all circuits in test_circuits/)

set -e

for d in test_circuits/*/ ; do
    echo "Running test: $d"
    cargo run --bin dietmc_0p -- --text --lpn small --relation $d/relation* --instance $d/public* --connection-addr 127.0.0.1:7876 prover --witness $d/private* 2> /dev/null &
    pid_prv=$!

    cargo run --bin dietmc_0p -- --text --lpn small --relation $d/relation* --instance $d/public* --connection-addr 127.0.0.1:7876 2> /dev/null &
    pid_vrf=$!

    wait $pid_prv
    wait $pid_vrf
done

echo "All end-to-end tests passed, yay!"
