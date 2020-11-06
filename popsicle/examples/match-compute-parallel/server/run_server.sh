set -e
echo "\n"
echo "*******************Starting Files Preparation*******************"
echo "\n"
cargo run --example prepare_files_server  --features="psty serde1"
wait
echo "\n"
echo "*******************Starting Computation Threads*******************"
echo "\n"
cargo run --example server_thread  --features="psty serde1" 0 &
cargo run --example server_thread  --features="psty serde1" 1 &
wait
echo "*******************Starting Joining Threads Results*******************"
echo "\n"
cargo run --example join_aggregates_server  --features="psty serde1" 2
