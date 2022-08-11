use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::{
    circuit::{ArithmeticCircuit as Circuit, CircuitBuilder, CircuitType},
    classic::garble,
    util::RngExt,
    AllWire, FancyArithmetic,
};
use std::time::Duration;

fn bench_garble<F: 'static>(c: &mut Criterion, name: &str, make_circuit: F, q: u16)
where
    F: Fn(u16) -> Circuit,
{
    c.bench_function(&format!("garbling::{}_gb ({})", name, q), move |bench| {
        let c = make_circuit(q);
        bench.iter(|| {
            let gb = garble::<AllWire, _>(&c).unwrap();
            criterion::black_box(gb);
        });
    });
}

fn bench_eval<F: 'static>(c: &mut Criterion, name: &str, make_circuit: F, q: u16)
where
    F: Fn(u16) -> Circuit,
{
    c.bench_function(&format!("garbling::{}_ev ({})", name, q), move |bench| {
        let mut rng = rand::thread_rng();
        let c = make_circuit(q);
        let (en, ev) = garble::<AllWire, _>(&c).unwrap();
        let inps = (0..c.num_garbler_inputs())
            .map(|i| rng.gen_u16() % c.garbler_input_mod(i))
            .collect::<Vec<u16>>();
        let xs = en.encode_garbler_inputs(&inps);
        bench.iter(|| {
            let ys = ev.eval(&c, &xs, &[]).unwrap();
            criterion::black_box(ys);
        });
    });
}

fn proj(q: u16) -> Circuit {
    let tt = (0..q).map(|i| (i + 1) % q).collect::<Vec<u16>>();
    let mut b = CircuitBuilder::new();
    let x = b.garbler_input(q);
    for _ in 0..1000 {
        let _ = b.proj(&x, q, Some(tt.clone())).unwrap();
    }
    b.finish()
}

fn mul(q: u16) -> Circuit {
    let mut b = CircuitBuilder::new();
    let x = b.garbler_input(q);
    for _ in 0..1000 {
        let _ = b.mul(&x, &x).unwrap();
    }
    b.finish()
}

fn proj_gb(c: &mut Criterion) {
    bench_garble(c, "proj", proj, 2);
    bench_garble(c, "proj", proj, 17)
}
fn proj_ev(c: &mut Criterion) {
    bench_eval(c, "proj", proj, 2);
    bench_eval(c, "proj", proj, 17)
}
fn mul_gb(c: &mut Criterion) {
    bench_garble(c, "mul", mul, 2);
    bench_garble(c, "mul", mul, 17)
}
fn mul_ev(c: &mut Criterion) {
    bench_eval(c, "mul", mul, 2);
    bench_eval(c, "mul", mul, 17)
}

criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = proj_gb, proj_ev, mul_gb, mul_ev
}

criterion_main!(garbling);
