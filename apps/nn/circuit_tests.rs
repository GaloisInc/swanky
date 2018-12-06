use itertools::Itertools;
use fancy_garbling::numbers;
use crate::neural_net::NeuralNet;
use crate::util;

pub fn test_arith_circuit(
    nn: &NeuralNet,
    images: &Vec<Vec<i64>>,
    labels: &[usize],
    bit_width: usize,
    secret_weights: bool,
) {
    println!("running plaintext accuracy evaluation");
    println!("secret weights={}", secret_weights);

    let q = numbers::modulus_with_width(bit_width as u32);
    println!("q={} primes={:?}", q, numbers::factor(q));
    let bun = nn.as_crt_circuit(q, secret_weights);
    bun.borrow_circ().print_info();

    let mut errors = 0;

    for (img_num, img) in images.iter().enumerate() {
        if img_num % 100 == 0 {
            println!("{}/{} {} errors ({}%)",
                     img_num, images.len(), errors,
                     100.0 * (1.0 - errors as f32 / img_num as f32));
        }

        let circ = bun.borrow_circ();

        let modq_img = img.iter().map(|&i| util::to_mod_q(q,i)).collect_vec();
        let inp = bun.encode(&modq_img);
        let raw = circ.eval(&inp);
        let res = bun.decode(&raw);

        let res: Vec<i64> = res.into_iter().map(|x| util::from_mod_q(q,x)).collect();

        let mut max_val = i64::min_value();
        let mut winner = 0;
        for (i, item) in res.into_iter().enumerate() {
            if item > max_val {
                max_val = item;
                winner = i;
            }
        }

        if winner != labels[img_num] {
            errors += 1;
        }
    }
    println!("errors: {}/{}. accuracy: {}%",
             errors, images.len(), 100.0 * (1.0 - errors as f32 / images.len() as f32));
}

pub fn test_bool_circuit(
    nn: &NeuralNet,
    images: &Vec<Vec<i64>>,
    labels: &[usize],
    nbits: usize,
    secret_weights: bool,
) {
    let circ = nn.as_boolean_circuit(nbits, secret_weights);
    circ.print_info();

    println!("noutputs={}", circ.noutputs());
    println!("running plaintext accuracy evaluation for boolean circuit");
    println!("secret weights={}", secret_weights);

    let mut errors = 0;
    for (img_num, img) in images.iter().enumerate() {
        if img_num % 20 == 0 {
            println!("{}/{} {} errors ({}% accuracy)",
                     img_num, images.len(), errors,
                     100.0 * (1.0 - errors as f32 / img_num as f32));
        }

        let inp = img.iter().map(|&x| {
            if x == -1 {
                1
            } else if x == 1 {
                0
            } else {
                panic!("unknown input {}", x)
            }
        }).collect_vec();
        let out = circ.eval(&inp);

        let res = out.chunks(nbits).map(|bs| {
            let x = numbers::u128_from_bits(bs);
            util::from_mod_q(1<<nbits, x)
        }).collect_vec();

        let mut max_val = i64::min_value();
        let mut winner = 0;
        for i in 0..res.len() {
            if res[i] > max_val {
                max_val = res[i];
                winner = i;
            }
        }
        if winner != labels[img_num] {
            errors += 1;
        }
    }

    println!("errors: {}/{}. accuracy: {}%",
             errors, images.len(), 100.0 * (1.0 - errors as f32 / images.len() as f32));
}

