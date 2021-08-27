#!/bin/bash

set -e

echo "PROVER: ${PROVER}"
echo "VERIFIER: ${VERIFIER}"

if [[ ! -z "${VERIFIER}" ]]; then
    WHOAMI=""
else if [[ ! -z "${PROVER}" ]]; then
         sleep 10
         WHOAMI="--prover"
     fi
fi

QUICKSILVER="--quicksilver"
# QUICKSILVER=""

#tc qdisc add dev eth0 root netem delay 200ms

run_command () {
    echo "rate=${RATE}, latency=${LATENCY}, burst=${BURST}, "
    if [[ ! -z "${VERIFIER}" ]]; then
        echo -n "rate=${RATE}, latency=${LATENCY}, burst=${BURST}, n=${NUM_EDABITS}, b=${NUM_BUCKETS}, m=${NUM_BITS}, " >> /tmp/bench_result.txt
    fi
    if [[ ! -z "${PROVER}" ]]; then
        sleep 2
    fi
    cargo run --release --example network_edabits -- -n ${NUM_EDABITS} -b ${NUM_BUCKETS} -m ${NUM_BITS} ${QUICKSILVER} --addr verifier:5527 ${WHOAMI}
}

run_test_b5 () {
    NUM_EDABITS=1024
    NUM_BUCKETS=5
    NUM_BITS=8
    run_command
    NUM_BITS=16
    run_command
    NUM_BITS=32
    run_command
    NUM_BITS=60
    run_command
}

run_test_b4 () {
    NUM_EDABITS=10322
    NUM_BUCKETS=4
    NUM_BITS=8
    run_command
    NUM_BITS=16
    run_command
    NUM_BITS=32
    run_command
    NUM_BITS=60
    run_command
}


run_test_b3 () {
    NUM_EDABITS=1048576
    NUM_BUCKETS=3
    NUM_BITS=8
    run_command
    NUM_BITS=16
    run_command
    NUM_BITS=32
    run_command
    #NUM_BITS=60
    #run_command
}



# From higher to lower bandwidth

RATE=1000000kbit
LATENCY=1ms
BURST=1000kbit
tc qdisc add dev eth0 root tbf rate ${RATE} latency ${LATENCY} burst ${BURST}
run_test_b5
run_test_b4
run_test_b3

# RATE=500000kbit
# LATENCY=1ms
# BURST=500kbit
# tc qdisc delete dev eth0 root
# tc qdisc add dev eth0 root tbf rate ${RATE} latency ${LATENCY} burst ${BURST}
# run_test_b5
# run_test_b4
# run_test_b3

# RATE=100000kbit
# LATENCY=1ms
# BURST=100kbit
# tc qdisc delete dev eth0 root
# tc qdisc add dev eth0 root tbf rate ${RATE} latency ${LATENCY} burst ${BURST}
# run_test_b5
# run_test_b4
# run_test_b3

# RATE=50000kbit
# LATENCY=1ms
# BURST=50kbit
# tc qdisc delete dev eth0 root
# tc qdisc add dev eth0 root tbf rate ${RATE} latency ${LATENCY} burst ${BURST}
# run_test_b5
# run_test_b4
# run_test_b3

# RATE=20000kbit
# LATENCY=1ms
# BURST=20kbit
# tc qdisc delete dev eth0 root
# tc qdisc add dev eth0 root tbf rate ${RATE} latency ${LATENCY} burst ${BURST}
# run_test_b5
# run_test_b4
# run_test_b3
