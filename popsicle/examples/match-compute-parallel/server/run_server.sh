echo "\n"
echo "*******************Starting Files Preparation*******************"
echo "\n"
cargo run --example prepare_files_server  --features="psty_payload"
wait
echo "\n"
echo "*******************Starting Computation Threads*******************"
echo "\n"
cargo run --example server_thread  --features="psty_payload" 0 &
cargo run --example server_thread  --features="psty_payload" 1 &
cargo run --example server_thread  --features="psty_payload" 2 &
cargo run --example server_thread  --features="psty_payload" 3 &
wait
echo "*******************Starting Joining Threads Results*******************"
echo "\n"
cargo run --example join_aggregates_server  --features="psty_payload" 4
