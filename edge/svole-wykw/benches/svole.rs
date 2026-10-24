//! Subfield vector oblivious linear evaluation benchmarks using `criterion`.

// TODO: criterion might not be the best choice for larger benchmarks.
use criterion::{Criterion, criterion_group, criterion_main};
use swanky_svole_wykw::{LPN_EXTEND_MEDIUM, LPN_SETUP_MEDIUM};
use swanky_svole_wykw::{Receiver, Sender};

use std::{
    hint::black_box,
    sync::{Arc, Mutex},
    time::Duration,
};
use swanky_channel::local::local_channel_pair;
use swanky_field::FiniteField;
use swanky_field_binary::F128b;
use swanky_field_f61p::F61p;
use swanky_rng::SwankyRng;

// TODO: re-enable ggm_utils benchmarks once we've sorted out the private modules issue.
/*#[path = "../src/svole/wykw/ggm_utils.rs"]
mod ggm_utils;*/

fn svole_init<F: FiniteField>() -> (Arc<Mutex<Sender<F>>>, Arc<Mutex<Receiver<F>>>) {
    let (vole_sender, vole_receiver) = local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            Ok(Sender::init(c, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap())
        },
        |c| {
            let mut rng = SwankyRng::new();
            Ok(Receiver::init(c, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM, None).unwrap())
        },
    )
    .unwrap();

    let vole_sender = Arc::new(Mutex::new(vole_sender));
    let vole_receiver = Arc::new(Mutex::new(vole_receiver));
    (vole_sender, vole_receiver)
}

fn bench_svole<F: FiniteField>(
    vole_sender: &Arc<Mutex<Sender<F>>>,
    vole_receiver: &Arc<Mutex<Receiver<F>>>,
) {
    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let mut vole_sender = vole_sender.lock().unwrap();
            let mut out: Vec<(F::PrimeField, F)> = Vec::new();
            vole_sender.send(c, &mut rng, &mut out).unwrap();
            black_box(out);
            Ok(())
        },
        |c| {
            let mut rng = SwankyRng::new();
            let mut vole_receiver = vole_receiver.lock().unwrap();
            let mut out = Vec::new();
            vole_receiver
                .receive::<F::PrimeField>(c, &mut rng, &mut out)
                .unwrap();
            black_box(out);
            Ok(())
        },
    )
    .unwrap();
}

fn bench_svole_gf128(c: &mut Criterion) {
    c.bench_function("svole::extend::Gf128", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<F128b>(&vole_sender, &vole_receiver);
        })
    });
}

fn bench_svole_f61p(c: &mut Criterion) {
    c.bench_function("svole::extend::F61p", move |bench| {
        let (vole_sender, vole_receiver) = svole_init();
        bench.iter(move || {
            bench_svole::<F61p>(&vole_sender, &vole_receiver);
        })
    });
}
fn bench_svole_init<F: FiniteField>() {
    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            black_box(Sender::<F>::init(c, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap());
            Ok(())
        },
        |c| {
            let mut rng = SwankyRng::new();
            black_box(
                Receiver::<F>::init(c, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM, None)
                    .unwrap(),
            );
            Ok(())
        },
    )
    .unwrap();
}

fn bench_svole_init_gf128(c: &mut Criterion) {
    c.bench_function("svole::init::Gf128", move |bench| {
        bench.iter(move || {
            bench_svole_init::<F128b>();
        });
    });
}

fn bench_svole_init_f61p(c: &mut Criterion) {
    c.bench_function("svole::init::F61p", move |bench| {
        bench.iter(move || {
            bench_svole_init::<F61p>();
        })
    });
}

/*fn bench_ggm_<FE: FiniteField>(depth: usize, seed: Block, aes: &(Aes128, Aes128)) {
    let exp = 1 << depth;
    let mut vs = vec![FE::ZERO; exp];
    black_box(ggm_utils::ggm(depth, seed, aes, &mut vs));
}

fn bench_ggm(c: &mut Criterion) {
    let cols = 10_805_248;
    let weight = 1_319;
    let m = cols / weight;
    let depth = 128 - (m as u128 - 1).leading_zeros() as usize;
    let seed = rand::thread_rng().gen();
    let seed0 = rand::thread_rng().gen();
    let seed1 = rand::thread_rng().gen();
    c.bench_function("svole::ggm::F61p", move |bench| {
        let aes0 = Aes128::new(seed0);
        let aes1 = Aes128::new(seed1);
        bench.iter(move || {
            bench_ggm_::<F61p>(depth, seed, &(aes0.clone(), aes1.clone()));
        })
    });
}*/

criterion_group! {
    name = svole;
    config = Criterion::default().warm_up_time(Duration::from_millis(100)).sample_size(10);
    targets =
        bench_svole_init_f61p,
        bench_svole_init_gf128,
        bench_svole_f61p,
        bench_svole_gf128,
        //bench_ggm,
}
criterion_main!(svole);
