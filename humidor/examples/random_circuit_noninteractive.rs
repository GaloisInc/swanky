use rand::{SeedableRng, rngs::StdRng};
use std::io::Write;

extern crate humidor;

use humidor::ligero::noninteractive;

fn test_input_size(s: usize) -> (
    usize, // proof size in bytes
    usize, // expected proof size in bytes
    std::time::Duration, // prover time in ms
    std::time::Duration, // verifier time in ms
) {
    let input_size = 256;
    let circuit_size = (1usize << s) - 256;

    println!("Proving a random circuit with {} gates and {} input wires",
        circuit_size, input_size);
    println!("---");

    let mut rng = StdRng::from_entropy();
    let (ckt, inp) = humidor::circuit::random_ckt_zero(&mut rng, input_size, circuit_size);

    let mut prover_time = std::time::Duration::new(0,0);
    let mut verifier_time = std::time::Duration::new(0,0);

    let t = std::time::Instant::now();
    let p = noninteractive::Prover::new(&ckt, &inp);
    prover_time += t.elapsed();
    println!("Prover setup time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let v = noninteractive::Verifier::new(&ckt);
    verifier_time += t.elapsed();
    println!("Verifier setup time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let proof = p.make_proof();
    prover_time += t.elapsed();
    println!("Proof generation time: {:?}", t.elapsed());
    let proof_size = proof.size();

    let t = std::time::Instant::now();
    let vout = v.verify(proof);
    verifier_time += t.elapsed();
    println!("Verification time: {:?}", t.elapsed());

    let expected_size = p.expected_proof_size();
    println!("---");
    println!("Verifier {} proof",
        if vout { "accepts" } else { "rejects" });
    println!("---");
    println!("Prover time: {:?}", prover_time);
    println!("Verifier time: {:?}", verifier_time);
    println!("Total time: {:?}", prover_time + verifier_time);
    println!("Proof size: {}kb", proof_size as f64 / 1024f64);
    println!("Expected size: {}kb", expected_size as f64 / 1024f64);
    println!("");

    (proof_size, expected_size, prover_time, verifier_time)
}

fn main() -> std::io::Result<()> {
    let mut f = std::fs::File::create("random_circuit_noninteractive.csv")?;
    f.write_all("# circuit size,\tproof size (kb),\tprover time (ms),\tverifier time (ms)\n\n".as_bytes())?;

    for s in 10..23 {
        let (ps, es, p, v) = test_input_size(s);
        f.write_all(format!("{},\t{},\t{},\t{},\t{}\n",
                1 << s, ps, es, p.as_millis(), v.as_millis()).as_bytes())?;
    }

    Ok(())
}
