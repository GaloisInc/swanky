ps aux | grep "target/release/examples/"
pkill -f "target/release/examples/"

echo "Starting Program"

cargo build --release --features="psty_payload" 

cargo run --release --example run_server --features="psty_payload" > sender_log.txt &
sleep 1
cargo run --release --example run_client --features="psty_payload" > receiver_log.txt &
