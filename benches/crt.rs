#[macro_use]
extern crate criterion;
extern crate fancy_garbling;
extern crate rand;

use criterion::Criterion;
use std::time::Duration;

use fancy_garbling::util::RngExt;
use fancy_garbling::garble::garble;
use fancy_garbling::circuit::crt::CrtBundler;
use fancy_garbling::numbers::modulus_with_width;

fn bench_gb<F:'static>(cr: &mut Criterion, name: &str, gen_bundler: F) where F: Fn(u128) -> CrtBundler {
    cr.bench_function(name, move |bench| {
        let q = modulus_with_width(32);
        let c = gen_bundler(q).finish();
        let mut rng = rand::thread_rng();
        bench.iter(|| {
            let gb = garble(&c, &mut rng);
            criterion::black_box(gb);
        });
    });
}

fn bench_ev<F:'static>(cr: &mut Criterion, name: &str, gen_bundler: F) where F: Fn(u128) -> CrtBundler{
    cr.bench_function(name, move |bench| {
        let q = modulus_with_width(32);
        let mut b = gen_bundler(q);
        let c = b.finish();

        let mut rng = rand::thread_rng();
        let inps = (0..b.ninputs()).map(|_| rng.gen_u128() % q).collect::<Vec<_>>();
        let (en, _, ev) = garble(&c, &mut rng);
        let enc_inp = b.encode(&inps);
        let xs = en.encode(&enc_inp);

        bench.iter(|| {
            let ys = ev.eval(&c, &xs);
            criterion::black_box(ys);
        });
    });
}

fn add_bundler(q: u128) -> CrtBundler {
    let mut b = CrtBundler::new();
    let x = b.input(q);
    let y = b.input(q);
    let z = b.add(x,y);
    b.output(z);
    b
}

fn mul_bundler(q: u128) -> CrtBundler {
    let mut b = CrtBundler::new();
    let x = b.input(q);
    let y = b.input(q);
    let z = b.mul(x,y);
    b.output(z);
    b
}

fn parity_bundler(q: u128) -> CrtBundler {
    let mut b = CrtBundler::new();
    let x = b.input(q);
    let z = b.parity(x);
    b.output_ref(z);
    b
}

fn sgn_bundler(q: u128) -> CrtBundler {
    let mut b = CrtBundler::new();
    let x = b.input(q);
    let ms = std::iter::repeat(4).take(5).collect::<Vec<_>>();
    let z = b.sgn(x,&ms);
    b.output(z);
    b
}

fn add(cr: &mut Criterion) {
    bench_gb(cr, "crt::add_gb", add_bundler);
    bench_ev(cr, "crt::add_ev", add_bundler);
}

fn mul(cr: &mut Criterion) {
    bench_gb(cr, "crt::mul_gb", mul_bundler);
    bench_ev(cr, "crt::mul_ev", mul_bundler);
}

fn parity(cr: &mut Criterion) {
    bench_gb(cr, "crt::parity_gb", parity_bundler);
    bench_ev(cr, "crt::parity_ev", parity_bundler);
}

fn sgn(cr: &mut Criterion) {
    bench_gb(cr, "crt::sgn_gb", sgn_bundler);
    bench_ev(cr, "crt::sgn_ev", sgn_bundler);
}

criterion_group!{
    name = crt;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = add, mul, parity, sgn
}

criterion_main!(crt);
