//! Oblivious pseudorandom function benchmarks using `criterion`.

use criterion::{Criterion, criterion_group, criterion_main};
use std::time::Duration;
use swanky_block::Block512;
use swanky_channel::local::local_channel_pair;
use swanky_oprf_traits::{Receiver as OprfReceiver, Sender as OprfSender};
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

type OpprfSender = swanky_oprf_kmprt::Sender;
type OpprfReceiver = swanky_oprf_kmprt::Receiver;

fn rand_block_vec(size: usize) -> Vec<U8x16> {
    (0..size).map(|_| rand::random::<U8x16>()).collect()
}

fn rand_point_vec(size: usize) -> Vec<(U8x16, Block512)> {
    (0..size)
        .map(|_| rand::random::<(U8x16, Block512)>())
        .collect()
}

fn _bench_oprf_init<S: OprfSender, R: OprfReceiver>() {
    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let _ = S::init(c, &mut rng).unwrap();
            Ok(())
        },
        |c| {
            let mut rng = SwankyRng::new();
            let _ = R::init(c, &mut rng).unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn _bench_oprf<S: OprfSender<Input = U8x16>, R: OprfReceiver<Input = U8x16>>(inputs: Vec<U8x16>) {
    let m = inputs.len();

    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let mut oprf = S::init(c, &mut rng).unwrap();
            let _ = oprf.send(c, m, &mut rng).unwrap();
            Ok(())
        },
        |c| {
            let mut rng = SwankyRng::new();
            let mut oprf = R::init(c, &mut rng).unwrap();
            oprf.receive(c, &inputs, &mut rng).unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn bench_oprf(c: &mut Criterion) {
    c.bench_function("oprf::kkrt (initialization)", move |bench| {
        bench.iter(|| {
            _bench_oprf_init::<swanky_oprf_kkrt::Sender, swanky_oprf_kkrt::Receiver>();
            std::hint::black_box(());
        })
    });
    let inputs = rand_block_vec(1 << 12);
    c.bench_function("oprf::kkrt (n = 2^12)", move |bench| {
        bench.iter(|| {
            _bench_oprf::<swanky_oprf_kkrt::Sender, swanky_oprf_kkrt::Receiver>(inputs.clone());
            std::hint::black_box(());
        })
    });
    let inputs = rand_block_vec(1 << 16);
    c.bench_function("oprf::kkrt (n = 2^16)", move |bench| {
        bench.iter(|| {
            _bench_oprf::<swanky_oprf_kkrt::Sender, swanky_oprf_kkrt::Receiver>(inputs.clone());
            std::hint::black_box(());
        })
    });
    let inputs = rand_block_vec(1 << 18);
    c.bench_function("oprf::kkrt (n = 2^18)", move |bench| {
        bench.iter(|| {
            _bench_oprf::<swanky_oprf_kkrt::Sender, swanky_oprf_kkrt::Receiver>(inputs.clone());
            std::hint::black_box(());
        })
    });
}

fn bench_oprf_compute(c: &mut Criterion) {
    c.bench_function("oprf::kkrt (compute)", move |bench| {
        let (_, oprf): (_, swanky_oprf_kkrt::Sender) = local_channel_pair(
            |c| {
                let mut rng = SwankyRng::new();
                let _: swanky_oprf_kmprt::Receiver =
                    swanky_oprf_kmprt::Receiver::init(c, &mut rng).unwrap();
                Ok(())
            },
            |c| {
                let mut rng = SwankyRng::new();
                Ok(swanky_oprf_kkrt::Sender::init(c, &mut rng).unwrap())
            },
        )
        .unwrap();

        let seed = rand::random::<Block512>();
        let input = rand::random::<U8x16>();
        bench.iter(|| {
            let result = oprf.compute(seed, input);
            std::hint::black_box(result);
        })
    });
}

fn _bench_opprf(points: Vec<(U8x16, Block512)>, inputs: Vec<U8x16>) {
    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let mut oprf = OpprfSender::init(c, &mut rng).unwrap();
            oprf.send(c, &points, points.len(), &mut rng).unwrap();
            Ok(())
        },
        |c| {
            let mut rng = SwankyRng::new();
            let mut oprf = OpprfReceiver::init(c, &mut rng).unwrap();
            oprf.receive(c, &inputs, &mut rng).unwrap();
            Ok(())
        },
    )
    .unwrap();
}

fn bench_opprf(c: &mut Criterion) {
    c.bench_function("opprf::kmprt (t = 1, n = 2^2)", move |bench| {
        let inputs = rand_block_vec(1);
        let points = rand_point_vec(1 << 2);
        bench.iter(|| {
            _bench_opprf(points.clone(), inputs.clone());
            std::hint::black_box(());
        })
    });
    c.bench_function("opprf::kmprt (t = 2^4, n = 2^4)", move |bench| {
        let inputs = rand_block_vec(1 << 4);
        let points = rand_point_vec(1 << 4);
        bench.iter(|| {
            _bench_opprf(points.clone(), inputs.clone());
            std::hint::black_box(());
        })
    });
    c.bench_function("opprf::kmprt (t = 2^8, n = 2^8)", move |bench| {
        let inputs = rand_block_vec(1 << 8);
        let points = rand_point_vec(1 << 8);
        bench.iter(|| {
            _bench_opprf(points.clone(), inputs.clone());
            std::hint::black_box(());
        })
    });
}

// fn bench_opprf_compute(c: &mut Criterion) {
//     c.bench_function("opprf::kmprt (t = 1, compute)", move |bench| {
//         let (sender, receiver) = UnixStream::pair().unwrap();
//         let handle = std::thread::spawn(move || {
//             let mut rng = SwankyRng::new();
//             let reader = BufReader::new(receiver.try_clone().unwrap());
//             let writer = BufWriter::new(receiver);
//             let mut channel = Channel::new(reader, writer);
//             let _ = OpprfSender::init(&mut channel, &mut rng).unwrap();
//         });
//         let mut rng = SwankyRng::new();
//         let reader = BufReader::new(sender.try_clone().unwrap());
//         let writer = BufWriter::new(sender);
//         let mut channel = Channel::new(reader, writer);
//         let oprf = OpprfSender::init(&mut channel, &mut rng).unwrap();
//         handle.join().unwrap();
//         let seed = rand::random::<Block512>();
//         let hint = (0..8).map(|_| rng.gen::<Block512>()).collect_vec();
//         let input = rand::random::<Block>();
//         bench.iter(|| oprf.compute(&seed, &hint, &input))
//     });
// }

criterion_group! {
    name = oprf;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(20);
    targets = bench_opprf, bench_oprf, bench_oprf_compute //,bench_opprf_compute
}

criterion_main!(oprf);
