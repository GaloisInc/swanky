echo on
echo "Starting Program"

cd %UserProfile%\My Documents\swanky-master\popsicle

start cargo run --example run_server --features="psty_payload"
start cargo run --example run_client --features="psty_payload"

echo "Done with Program"

pause
