use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::*;
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const T: usize = 1 << 16;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}
fn rand_bool_vec(size: usize) -> Vec<bool> {
    (0..size).map(|_| rand::random::<bool>()).collect()
}

fn _bench_block_ot<OT: BlockObliviousTransfer<UnixStream>>(bs: &[bool], ms: Vec<(Block, Block)>) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let mut ot = OT::new();
        let mut reader = BufReader::new(sender.try_clone().unwrap());
        let mut writer = BufWriter::new(sender);
        ot.send(&mut reader, &mut writer, &ms).unwrap();
    });
    let mut ot = OT::new();
    let mut reader = BufReader::new(receiver.try_clone().unwrap());
    let mut writer = BufWriter::new(receiver);
    ot.receive(&mut reader, &mut writer, &bs).unwrap();
    handle.join().unwrap();
}

fn bench_ot(c: &mut Criterion) {
    c.bench_function("ot::ChouOrlandiOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(move || _bench_block_ot::<ChouOrlandiOT<UnixStream>>(&bs, ms.clone()))
    });
    c.bench_function("ot::DummyOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(|| _bench_block_ot::<DummyOT<UnixStream>>(&bs, ms.clone()))
    });
    c.bench_function("ot::NaorPinkasOT", move |bench| {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(128);
        bench.iter(|| _bench_block_ot::<NaorPinkasOT<UnixStream>>(&bs, ms.clone()))
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
            _bench_block_ot::<AlszOT<UnixStream, ChouOrlandiOT<UnixStream>>>(&bs, ms.clone())
        })
    });
}

criterion_group! {
    name = ot;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = // bench_ot,
    bench_otext
}

criterion_main!(ot);
