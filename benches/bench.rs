use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::*;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const N: usize = 32;

fn rand_u8_vec(size: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(size);
    for _ in 0..size {
        v.push(rand::random::<u8>());
    }
    v
}

fn test<OT: ObliviousTransfer<UnixStream>>(m0: &[u8], m1: &[u8]) {
    let m0_ = m0.to_vec().clone();
    let m1_ = m1.to_vec().clone();
    let b = rand::random::<bool>();
    let (sender, receiver) = match UnixStream::pair() {
        Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
        Err(e) => {
            eprintln!("Couldn't create pair of sockets: {:?}", e);
            return;
        }
    };
    let handler = std::thread::spawn(move || {
        let mut ot = OT::new(sender);
        ot.send(&[(m0_, m1_)]).unwrap();
    });
    let mut ot = OT::new(receiver);
    let _results = ot.receive(&[b], N).unwrap();
    handler.join().unwrap();
}

fn bench_chou_orlandi(c: &mut Criterion) {
    let m0 = rand_u8_vec(N);
    let m1 = rand_u8_vec(N);
    c.bench_function("ot::ChouOrlandiOT", move |bench| {
        bench.iter(|| test::<ChouOrlandiOT<UnixStream>>(&m0, &m1))
    });
}

fn bench_dummy(c: &mut Criterion) {
    let m0 = rand_u8_vec(N);
    let m1 = rand_u8_vec(N);
    c.bench_function("ot::DummyOT", move |bench| {
        bench.iter(|| test::<DummyOT<UnixStream>>(&m0, &m1))
    });
}

fn bench_naor_pinkas(c: &mut Criterion) {
    let m0 = rand_u8_vec(N);
    let m1 = rand_u8_vec(N);
    c.bench_function("ot::NaorPinkasOT", move |bench| {
        bench.iter(|| test::<NaorPinkasOT<UnixStream>>(&m0, &m1))
    });
}

const T: usize = 16384;

fn rand_u128_vec(size: usize) -> Vec<u128> {
    (0..size).map(|_| rand::random::<u128>()).collect()
}

fn rand_bool_vec(size: usize) -> Vec<bool> {
    (0..size).map(|_| rand::random::<bool>()).collect()
}

fn test_otext_iknp<OT: ObliviousTransfer<UnixStream>>(n: usize) {
    let m0s = rand_u128_vec(n);
    let m1s = rand_u128_vec(n);
    let bs = rand_bool_vec(n);
    let (sender, receiver) = match UnixStream::pair() {
        Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
        Err(e) => {
            eprintln!("Couldn't create pair of sockets: {:?}", e);
            return;
        }
    };
    std::thread::spawn(move || {
        let mut otext = IknpOT::<UnixStream, OT>::new(sender.clone());
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .map(|(a, b)| (u128::to_ne_bytes(a).to_vec(), u128::to_ne_bytes(b).to_vec()))
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        otext.send(&ms).unwrap();
    });
    let mut otext = IknpOT::<UnixStream, OT>::new(receiver.clone());
    let _results = otext.receive(&bs, 16).unwrap();
    // for (b, result, m0, m1) in itertools::izip!(bs_, results, m0s_, m1s_) {
    //     assert_eq!(bitvec_to_u128(&result), if b { m1 } else { m0 })
    // }
}

fn test_otext_alsz<OT: ObliviousTransfer<UnixStream>>(n: usize) {
    let m0s = rand_u128_vec(n);
    let m1s = rand_u128_vec(n);
    let bs = rand_bool_vec(n);
    let (sender, receiver) = match UnixStream::pair() {
        Ok((s1, s2)) => (Arc::new(Mutex::new(s1)), Arc::new(Mutex::new(s2))),
        Err(e) => {
            eprintln!("Couldn't create pair of sockets: {:?}", e);
            return;
        }
    };
    std::thread::spawn(move || {
        let mut otext = AlszOT::<UnixStream, OT>::new(sender.clone());
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .map(|(a, b)| (u128::to_ne_bytes(a).to_vec(), u128::to_ne_bytes(b).to_vec()))
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        otext.send(&ms).unwrap();
    });
    let mut otext = AlszOT::<UnixStream, OT>::new(receiver.clone());
    let _results = otext.receive(&bs, 16).unwrap();
    // for (b, result, m0, m1) in itertools::izip!(bs_, results, m0s_, m1s_) {
    //     assert_eq!(bitvec_to_u128(&result), if b { m1 } else { m0 })
    // }
}

fn bench_iknp(c: &mut Criterion) {
    c.bench_function("ot::IknpOT", move |bench| {
        bench.iter(|| test_otext_iknp::<ChouOrlandiOT<UnixStream>>(T))
    });
}

fn bench_alsz(c: &mut Criterion) {
    c.bench_function("ot::AlszOT", move |bench| {
        bench.iter(|| test_otext_alsz::<ChouOrlandiOT<UnixStream>>(T))
    });
}

criterion_group! {
    name = ot;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_chou_orlandi, bench_dummy, bench_naor_pinkas, bench_alsz
}

criterion_main!(ot);
