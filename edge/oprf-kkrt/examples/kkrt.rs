use std::time::SystemTime;
use swanky_channel::{Channel, local::LocalSocket};
use swanky_channel_tracking::TrackChannel;
use swanky_oprf_kkrt::{Receiver as KkrtReceiver, Sender as KkrtSender};
use swanky_oprf_traits::{Receiver as _, Sender as _};
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

fn rand_u8x16_vec(size: usize) -> Vec<U8x16> {
    (0..size).map(|_| rand::random::<U8x16>()).collect()
}

fn _test_oprf(n: usize) {
    let selections = rand_u8x16_vec(n);
    let (sender, receiver) = LocalSocket::pair().unwrap();

    let total = SystemTime::now();

    let handle = std::thread::spawn(move || {
        let mut sender = TrackChannel::new(sender);
        Channel::with(&mut sender, |c| {
            let mut rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut oprf: KkrtSender = KkrtSender::init(c, &mut rng).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let _ = oprf.send(c, n, &mut rng).unwrap();
            println!(
                "[{}] Send time: {} ms",
                n,
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        })
        .unwrap();

        println!(
            "Sender communication (read): {:.2} Mb",
            sender.kilobits_read() / 1000.0
        );
        println!(
            "Sender communication (write): {:.2} Mb",
            sender.kilobits_written() / 1000.0
        );
    });

    let mut receiver = TrackChannel::new(receiver);
    Channel::with(&mut receiver, |c| {
        let mut rng = SwankyRng::new();
        let start = SystemTime::now();
        let mut oprf: KkrtReceiver = KkrtReceiver::init(c, &mut rng).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let _ = oprf.receive(c, &selections, &mut rng).unwrap();
        println!(
            "[{}] Receiver time: {} ms",
            n,
            start.elapsed().unwrap().as_millis()
        );
        Ok(())
    })
    .unwrap();

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
