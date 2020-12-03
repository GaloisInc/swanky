echo "Starting Program"

cd %UserProfile%\My Documents\swanky-master\popsicle

start cmd /c cargo run --release --example run_server --features="psty_payload" ^& pause
start cmd /c cargo run --release --example run_client --features="psty_payload" ^& pause
