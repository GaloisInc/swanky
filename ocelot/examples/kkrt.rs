use ocelot::oprf::{KkrtReceiver, KkrtSender, Receiver, Sender};
use scuttlebutt::{channel::track_unix_channel_pair, AesRng, Block};
use std::time::SystemTime;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

fn _test_oprf(n: usize) {
    let selections = rand_block_vec(n);
    let (mut sender, mut receiver) = track_unix_channel_pair();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let start = SystemTime::now();
        let mut oprf = KkrtSender::init(&mut sender, &mut rng).unwrap();
        println!(
            "Sender init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let _ = oprf.send(&mut sender, n, &mut rng).unwrap();
        println!(
            "[{}] Send time: {} ms",
            n,
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender communication (read): {:.2} Mb",
            sender.kilobits_read() / 1000.0
        );
        println!(
            "Sender communication (write): {:.2} Mb",
            sender.kilobits_written() / 1000.0
        );
    });
    let mut rng = AesRng::new();
    let start = SystemTime::now();
    let mut oprf = KkrtReceiver::init(&mut receiver, &mut rng).unwrap();
    println!(
        "Receiver init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = oprf.receive(&mut receiver, &selections, &mut rng).unwrap();
    println!(
        "[{}] Receiver time: {} ms",
        n,
        start.elapsed().unwrap().as_millis()
    );
    handle.join().unwrap();
    println!(
        "Receiver communication (read): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receiver communication (write): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    _test_oprf(1 << 20);
}
