#!/usr/bin/env bash

set -ex

output=$(cargo run --release -- \
               evaluator sha256.txt $(python -c "print('0' * 768)") | awk '{print $3}')
cargo run --release -- \
      prover sha256.txt $(python -c "print('0' * 768)") \
      ${output} \
      proof
result=$(cargo run --release -- \
               verifier sha256.txt proof \
               ${output})
if [[ ${result} != "Verification succeeded!" ]]; then
   exit 1
fi
result=$(cargo run --release -- \
               verifier sha256.txt proof \
               $(python -c "print('0' * 256)"))
# An error will result in nothing being written to stdout
if [[ ${result} != "" ]]; then
    exit 1
fi
exit 0
