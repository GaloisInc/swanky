echo "Starting Program"

cd %UserProfile%\My Documents\swanky-master\popsicle

start cmd /c cargo run --release --example run_server --features="psty_payload" ^& pause
timeout /t 1
start cmd /c cargo run --release --example run_client --features="psty_payload" ^& pause
