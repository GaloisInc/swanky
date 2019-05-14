use fancy_garbling::dummy::Dummy;
use fancy_garbling::util;
use fancy_garbling::*;
use itertools::Itertools;
use rand::Rng;

fn approx_relu<F: Fancy>(b: &mut F, x: &CrtBundle<F::Item>) {
    let exact = b.crt_relu(&x, "100%", None).unwrap();
    let approx_999 = b.crt_relu(&x, "99.9%", None).unwrap();
    let approx_99 = b.crt_relu(&x, "99%", None).unwrap();
    b.crt_outputs(&[exact, approx_999, approx_99]).unwrap();
}

fn main() {
    let n = 10000;
    let mut rng = rand::thread_rng();

    let mut approx_999_errors = 0;
    let mut approx_99_errors = 0;

    for _ in 0..n {
        let nprimes = rng.gen_range(5, 9);
        let ps = &util::PRIMES[0..nprimes];
        let q = util::product(ps);
        let x = rand::random::<u128>() % q;

        let mut d = Dummy::new();
        let inp = d.crt_encode(x,q).unwrap();
        approx_relu(&mut d, &inp);
        let outs = d
            .get_output()
            .chunks(nprimes)
            .map(|xs| util::crt_inv(xs, ps))
            .collect_vec();

        let should_be = if x >= q / 2 { 0 } else { x };
        assert_eq!(outs[0], should_be);

        if outs[1] != outs[0] {
            approx_999_errors += 1;
        }

        if outs[2] != outs[0] {
            approx_99_errors += 1;
        }
    }

    println!(
        "relu 99.9% errors: {}/{} ({:.2}%)",
        approx_999_errors,
        n,
        100.0 * (1.0 - (approx_999_errors as f64 / n as f64))
    );
    println!(
        "relu 99% errors: {}/{} ({:.2}%)",
        approx_99_errors,
        n,
        100.0 * (1.0 - (approx_99_errors as f64 / n as f64))
    );
}
