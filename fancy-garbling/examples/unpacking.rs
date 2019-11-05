use criterion::black_box;
use fancy_garbling::Wire;
use rand;
use std::time::SystemTime;

fn main() {
    let start = SystemTime::now();
    for _ in 0..100000 {
        let q = 2 + rand::random::<u16>() % 113;
        let b = rand::random();
        let w = Wire::from_block(b, q);
        black_box(w);
    }
    println!("Time: {} ms", start.elapsed().unwrap().as_millis());
}
