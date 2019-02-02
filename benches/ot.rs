use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::*;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const N: usize = 16;
const T: usize = 1 << 15;

fn rand_u8_vec(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random::<u8>()).collect()
}
fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}
fn rand_bool_vec(size: usize) -> Vec<bool> {
    (0..size).map(|_| rand::random::<bool>()).collect()
}
fn rand_block() -> Block {
    rand::random::<Block>()
}

fn _bench_block_ot<OT: BlockObliviousTransfer<UnixStream>>(
    sender: UnixStream,
    receiver: UnixStream,
    bs: &[bool],
    ms: Vec<(Block, Block)>,
) {
    let handle = std::thread::spawn(move || {
        let mut ot = OT::new(sender);
        ot.send(&ms).unwrap();
    });
    let mut ot = OT::new(receiver);
    ot.receive(&bs).unwrap();
    handle.join().unwrap();
}

fn _bench_ot<OT: ObliviousTransfer<UnixStream>>(
    sender: UnixStream,
    receiver: UnixStream,
    bs: &[bool],
    ms: Vec<(Vec<u8>, Vec<u8>)>,
) {
    let handle = std::thread::spawn(move || {
        let mut ot = OT::new(sender);
        ot.send(&ms, N).unwrap();
    });
    let mut ot = OT::new(receiver);
    ot.receive(&bs, N).unwrap();
    handle.join().unwrap();
}

fn bench_ot(c: &mut Criterion) {
    c.bench_function("ot::ChouOrlandiOT", move |bench| {
        let m0 = rand_block();
        let m1 = rand_block();
        let ms = vec![(m0, m1)];
        let b = vec![rand::random::<bool>()];
        bench.iter(|| {
            let (sender, receiver) = UnixStream::pair().unwrap();
            _bench_block_ot::<ChouOrlandiOT<UnixStream>>(sender, receiver, &b, ms.clone())
        })
    });
    c.bench_function("ot::DummyOT", move |bench| {
        let m0 = rand_u8_vec(N);
        let m1 = rand_u8_vec(N);
        let ms = vec![(m0, m1)];
        let b = vec![rand::random::<bool>()];
        bench.iter(|| {
            let (sender, receiver) = UnixStream::pair().unwrap();
            _bench_ot::<DummyOT<UnixStream>>(sender, receiver, &b, ms.clone())
        })
    });
    c.bench_function("ot::NaorPinkasOT", move |bench| {
        let m0 = rand_u8_vec(N);
        let m1 = rand_u8_vec(N);
        let ms = vec![(m0, m1)];
        let b = vec![rand::random::<bool>()];
        bench.iter(|| {
            let (sender, receiver) = UnixStream::pair().unwrap();
            _bench_ot::<NaorPinkasOT<UnixStream>>(sender, receiver, &b, ms.clone())
        })
    });
}

fn bench_otext(c: &mut Criterion) {
    c.bench_function("ot::AlszOT", move |bench| {
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(T);
        bench.iter(|| {
            let (sender, receiver) = UnixStream::pair().unwrap();
            _bench_block_ot::<AlszOT<UnixStream, ChouOrlandiOT<UnixStream>>>(
                sender,
                receiver,
                &bs,
                ms.clone(),
            )
        })
    });
    // c.bench_function("ot::IknpOT", move |bench| {
    //     bench
    //         .iter(|| _bench_otext::<IknpOT<UnixStream, ChouOrlandiOT<UnixStream>>>(&bs, ms.clone()))
    // });
}

criterion_group! {
    name = ot;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_ot, bench_otext
}

criterion_main!(ot);
