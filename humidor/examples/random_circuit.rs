use rand::{Rng, SeedableRng, rngs::StdRng};

extern crate humidor;

use humidor::ligero::interactive;
use humidor::circuit::{Op, Ckt};

type Field = humidor::f2_19x3_26::F;

pub fn random_field_vec<R>(rng: &mut R, size: usize) -> Vec<Field>
    where R: Rng
{
    (0 .. size).map(|_| rng.sample(rand::distributions::Standard)).collect()
}

fn random_ckt<R>(rng: &mut R, w: usize, c: usize) -> Ckt
    where R: Rng
{
    let ops = (0..c).map(|n| {
        let i = rng.gen_range(0 .. w+n);
        let j = rng.gen_range(0 .. w+n);
        if rng.gen_bool(0.5) {
            Op::Add(i, j)
        } else {
            Op::Mul(i, j)
        }
    }).collect();

    Ckt { inp_size: w, ops }
}

fn main() {
    let input_size = 20;
    let circuit_size = 1000;

    println!("Proving a random circuit with {} gates and {} input wires",
        circuit_size, input_size);

    let mut rng = StdRng::from_entropy();
    let ckt = random_ckt(&mut rng, input_size, circuit_size);
    let inp = random_field_vec(&mut rng, input_size);
    let out = *ckt.eval(&inp).last().unwrap() == Field::ZERO;

    let mut prover_time = std::time::Duration::new(0,0);
    let mut verifier_time = std::time::Duration::new(0,0);

    let t = std::time::Instant::now();
    let p = interactive::Prover::new(&ckt, &inp);
    prover_time += t.elapsed();
    println!("Prover setup time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let mut v = interactive::Verifier::new(&ckt);
    verifier_time += t.elapsed();
    println!("Verifier setup time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let r0 = p.round0();
    prover_time += t.elapsed();
    println!("Round 0 time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let r1 = v.round1(r0);
    verifier_time += t.elapsed();
    println!("Round 1 time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let r2 = p.round2(r1);
    prover_time += t.elapsed();
    println!("Round 2 time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let r3 = v.round3(r2);
    verifier_time += t.elapsed();
    println!("Round 3 time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let r4 = p.round4(r3);
    prover_time += t.elapsed();
    println!("Round 4 time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let vout = v.verify(r4);
    verifier_time += t.elapsed();
    println!("Verification time: {:?}", t.elapsed());

    println!("Verifier output {} evaluation output",
        if vout == out { "matches" } else { "does not match" });
    println!("");
    println!("Prover time: {:?}", prover_time);
    println!("Verifier time: {:?}", verifier_time);
    println!("Total time: {:?}", prover_time + verifier_time);
}
