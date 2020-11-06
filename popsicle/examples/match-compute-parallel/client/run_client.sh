set -e
echo "*******************Starting Files Preparation*******************"
echo "\n"
cargo run --example prepare_files_client  --features="psty serde1"
wait
sleep 2
echo "\n"
echo "*******************Starting Computation Threads*******************"
echo "\n"
cargo run --example client_thread  --features="psty serde1" 0 &
cargo run --example client_thread  --features="psty serde1" 1 &
wait
sleep 2
echo "*******************Starting Joining Threads Results*******************"
echo "\n"
cargo run --example join_aggregates_client  --features="psty serde1" 2
