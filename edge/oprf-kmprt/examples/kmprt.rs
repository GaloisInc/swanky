use rand::RngExt;
use std::time::SystemTime;
use swanky_block::Block512;
use swanky_channel::{Channel, local::LocalSocket};
use swanky_channel_tracking::TrackChannel;
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

fn rand_u8x16_vec(size: usize) -> Vec<U8x16> {
    (0..size).map(|_| rand::random::<U8x16>()).collect()
}

fn run(ninputs: usize, npoints: usize) {
    println!("npoints = {}, ninputs = {}", npoints, ninputs);
    let inputs = rand_u8x16_vec(ninputs);
    let mut rng = SwankyRng::new();
    let points = (0..npoints)
        .map(|_| (rng.random(), rng.random()))
        .collect::<Vec<(U8x16, Block512)>>();
    let (sender, receiver) = LocalSocket::pair().unwrap();

    let total = SystemTime::now();

    let handle = std::thread::spawn(move || {
        let mut sender = TrackChannel::new(sender);
        Channel::with(&mut sender, |c| {
            let mut rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut oprf: swanky_oprf_kmprt::Sender =
                swanky_oprf_kmprt::Sender::init(c, &mut rng).unwrap();
            println!(
                "Sender init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            oprf.send(c, &points, ninputs, &mut rng).unwrap();
            println!(
                "Sender send time: {} ms",
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
        let mut oprf: swanky_oprf_kmprt::Receiver =
            swanky_oprf_kmprt::Receiver::init(c, &mut rng).unwrap();
        println!(
            "Receiver init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let _ = oprf.receive(c, &inputs, &mut rng).unwrap();
        println!(
            "Receiver send time: {} ms",
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
    run(83231, 196608);
}
