use criterion::{criterion_main, criterion_group, Criterion};
use fancy_garbling::circuit::{CircuitBuilder, Circuit};
use fancy_garbling::fancy::Fancy;
use fancy_garbling::garble::garble;
use fancy_garbling::util::RngExt;
use itertools::Itertools;
use std::time::Duration;

fn bench_garble<F:'static>(c: &mut Criterion, name: &str, make_circuit: F, q: u16)
    where F: Fn(u16) -> Circuit
{
    c.bench_function(&format!("garbling::{}{}_gb", name, q), move |bench| {
        let c = make_circuit(q);
        bench.iter(|| {
            let gb = garble(&c);
            criterion::black_box(gb);
        });
    });
}

fn bench_eval<F:'static>(c: &mut Criterion, name: &str, make_circuit: F, q: u16)
    where F: Fn(u16) -> Circuit
{
    c.bench_function(&format!("garbling::{}{}_ev", name, q), move |bench| {
        let mut rng = rand::thread_rng();

        let c = make_circuit(q);
        let (en, _, ev) = garble(&c);

        let inps = (0..c.num_garbler_inputs()).map(|i| {
            rng.gen_u16() % c.garbler_input_mod(i)
        }).collect_vec();

        let xs = en.encode_garbler_inputs(&inps);

        bench.iter(|| {
            let ys = ev.eval(&c, &xs, &[]);
            criterion::black_box(ys);
        });
    });
}

fn proj(q: u16) -> Circuit {
    let b = CircuitBuilder::new();
    let x = b.garbler_input(None, q);
    let tab = (0..q).map(|i| (i + 1) % q).collect_vec();
    let z = b.proj(None, &x, q, &tab);
    b.output(None, &z);
    b.finish()
}

fn half_gate(q: u16) -> Circuit {
    let b = CircuitBuilder::new();
    let x = b.garbler_input(None, q);
    let y = b.garbler_input(None, q);
    let z = b.mul(None, &x,&y);
    b.output(None, &z);
    b.finish()
}

fn proj17_gb(c: &mut Criterion) { bench_garble(c,"proj",proj,17) }
fn proj17_ev(c: &mut Criterion) { bench_eval(c,"proj",proj,17) }
fn mul_gb(c: &mut Criterion) { bench_garble(c,"mul",half_gate,17) }
fn mul_ev(c: &mut Criterion) { bench_eval(c,"mul",half_gate,17) }

criterion_group!{
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = proj17_gb, proj17_ev, mul_gb, mul_ev
}

criterion_main!(garbling);
