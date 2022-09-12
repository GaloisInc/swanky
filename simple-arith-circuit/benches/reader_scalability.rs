use simple_arith_circuit::Circuit;
use std::path::PathBuf;

// This benchmark depends upon having created a 2.5GB file
// using the script `make-bench.sh`.
fn bench_reader_scalability() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches");
    let ckt = base.join("bf-gigantic.txt");
    let start = std::time::Instant::now();
    Circuit::read_bristol_fashion(&ckt, None).unwrap();
    let elapsed = start.elapsed();
    println!("Total: {:#?}", elapsed);
    println!("Gates per second: {}", 100_000_000 / elapsed.as_secs());
}

fn main() {
    bench_reader_scalability();
}
