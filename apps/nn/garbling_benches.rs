use std::time::{Duration, SystemTime};
use test;
use itertools::Itertools;
use fancy_garbling::numbers;
use fancy_garbling::garble::garble;
use util;
use neural_net::NeuralNet;

pub fn bench_arith_garbling(
    nn: &NeuralNet,
    image: &[i64],
    bit_width: usize,
    ntests: usize,
    secret_weights: bool,
) { //
    println!("running garble/eval benchmark");
    println!("secret weights={}", secret_weights);

    let q = numbers::modulus_with_width(bit_width as u32);
    println!("q={} primes={:?}", q, numbers::factor(q));
    let mut bun = nn.as_crt_circuit(q, secret_weights);

    let mut garble_time = Duration::new(0,0);
    for _ in 0..ntests {
        let start = SystemTime::now();
        let circ = bun.borrow_circ();
        let gb = garble(circ, &mut rand::thread_rng());
        test::black_box(gb);
        garble_time += SystemTime::now().duration_since(start).unwrap();
    }
    garble_time /= ntests as u32;

    let circ = bun.finish();
    let (en,_de,ev) = garble(&circ, &mut rand::thread_rng());

    let img = image.iter().map(|&i| util::to_mod_q(q,i)).collect_vec();
    let inp = en.encode(&bun.encode(&img));

    let mut eval_time = Duration::new(0,0);
    for _ in 0..ntests {
        let start = SystemTime::now();
        let res = ev.eval(&circ, &inp);
        test::black_box(res);
        eval_time += SystemTime::now().duration_since(start).unwrap();
    }
    eval_time /= ntests as u32;

    println!("garbling took {} ms", garble_time.as_millis());
    println!("eval took {} ms", eval_time.as_millis());
    println!("size: {} ciphertexts", ev.size());
}

pub fn bench_bool_garbling(
    nn: &NeuralNet,
    image: &[i64],
    nbits: usize,
    ntests: usize,
    secret_weights: bool
) {
    println!("running garble/eval benchmark for boolean circuit");
    println!("secret weights={}", secret_weights);

    let circ = nn.as_boolean_circuit(nbits, secret_weights);

    let mut garble_time = Duration::new(0,0);
    for _ in 0..ntests {
        let start = SystemTime::now();
        let gb = garble(&circ, &mut rand::thread_rng());
        test::black_box(gb);
        garble_time += SystemTime::now().duration_since(start).unwrap();
    }
    garble_time /= ntests as u32;

    let (en,_de,ev) = garble(&circ, &mut rand::thread_rng());

    let img = image.iter().map(|&x| if x == -1 { 1 } else if x == 1 { 0 } else { panic!("unknown input {}", x) } ).collect_vec();
    let inp = en.encode(&img);

    let mut eval_time = Duration::new(0,0);
    for _ in 0..ntests {
        let start = SystemTime::now();
        let res = ev.eval(&circ, &inp);
        test::black_box(res);
        eval_time += SystemTime::now().duration_since(start).unwrap();
    }
    eval_time /= ntests as u32;

    println!("garbling took {} ms", garble_time.as_millis());
    println!("eval took {} ms", eval_time.as_millis());
    println!("size: {} ciphertexts", ev.size());
}
