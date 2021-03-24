echo "Starting Program"

cd %UserProfile%\My Documents\swanky-master\popsicle

start cmd /c cargo run --release --example run_server --features="psty_payload" ^& pause
<<<<<<< HEAD
timeout /t 2
=======
timeout /t 1
>>>>>>> sum_weights
start cmd /c cargo run --release --example run_client --features="psty_payload" ^& pause
