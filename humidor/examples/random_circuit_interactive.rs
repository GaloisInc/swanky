use humidor::ligero::interactive;
use rand::SeedableRng;
use scuttlebutt::AesRng;
use simple_arith_circuit::Circuit;
use std::io::Write;

type Hash = sha2::Sha256;
type Field = scuttlebutt::field::F2e19x3e26;
type Prover = interactive::Prover<Field, Hash>;
type Verifier = interactive::Verifier<Field, Hash>;

fn test_input_size(
    s: usize,
    input_size: usize,
) -> (
    usize,               // proof size in bytes
    usize,               // expected proof size in bytes
    std::time::Duration, // prover time in ms
    std::time::Duration, // verifier time in ms
) {
    let circuit_size = (1usize << s) - input_size;

    println!(
        "Proving a random circuit with {} gates and {} input wires",
        circuit_size, input_size
    );
    println!("---");

    let mut rng = AesRng::from_entropy();
    let (ckt, inp): (Circuit<Field>, _) =
        simple_arith_circuit::circuitgen::random_zero_circuit(input_size, circuit_size, &mut rng);

    let mut prover_time = std::time::Duration::new(0, 0);
    let mut verifier_time = std::time::Duration::new(0, 0);
    let mut proof_size = 0usize;

    let t = std::time::Instant::now();
    let mut p = Prover::new(&mut rng, &ckt, &inp, None);
    prover_time += t.elapsed();
    println!("Prover setup time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let mut v = Verifier::new(&ckt, None);
    verifier_time += t.elapsed();
    println!("Verifier setup time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let r0 = p.round0();
    prover_time += t.elapsed();
    println!("Round 0 time: {:?}", t.elapsed());
    println!("Round 0 size: {}", r0.size());
    proof_size += r0.size();

    let t = std::time::Instant::now();
    let r1 = v.round1(&mut rng, r0);
    verifier_time += t.elapsed();
    println!("Round 1 time: {:?}", t.elapsed());
    println!("Round 1 size: {}", r1.size());

    let t = std::time::Instant::now();
    let r2 = p.round2(r1);
    prover_time += t.elapsed();
    println!("Round 2 time: {:?}", t.elapsed());
    println!("Round 2 size: {}", r2.size());
    proof_size += r2.size();

    let t = std::time::Instant::now();
    let r3 = v.round3(&mut rng, r2);
    verifier_time += t.elapsed();
    println!("Round 3 time: {:?}", t.elapsed());
    println!("Round 3 size: {}", r3.size());

    let t = std::time::Instant::now();
    let r4 = p.round4(r3);
    prover_time += t.elapsed();
    println!("Round 4 time: {:?}", t.elapsed());
    println!("Round 4 size: {}", r4.size());
    proof_size += r4.size();

    let t = std::time::Instant::now();
    let vout = v.verify(r4);
    verifier_time += t.elapsed();
    println!("Verification time: {:?}", t.elapsed());

    let expected_size = p.expected_proof_size();
    println!("---");
    println!(
        "Verifier {} proof",
        if vout { "accepts" } else { "rejects" }
    );
    println!("---");
    println!("Prover time: {:?}", prover_time);
    println!("Verifier time: {:?}", verifier_time);
    println!("Total time: {:?}", prover_time + verifier_time);
    println!("Proof size: {}kb", proof_size as f64 / 1024f64);
    println!("Expected size: {}kb", expected_size as f64 / 1024f64);
    println!();

    (proof_size, expected_size, prover_time, verifier_time)
}

fn main() -> std::io::Result<()> {
    let mut f = std::fs::File::create("random_circuit_interactive.csv")?;
    f.write_all("# circuit size,\tproof size (kb),\texpected size (kb),\tprover time (ms),\tverifier time (ms)\n\n".as_bytes())?;

    for s in 13..=24 {
        let (ps, es, p, v) = test_input_size(s, 2048);
        f.write_all(
            format!(
                "{},\t{},\t{},\t{},\t{},\n",
                1 << s,
                ps,
                es,
                p.as_millis(),
                v.as_millis()
            )
            .as_bytes(),
        )?;
    }

    Ok(())
}
