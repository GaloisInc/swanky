use rand::SeedableRng;
use std::io::Write;
use scuttlebutt::AesRng;

extern crate humidor;

use humidor::ligero::noninteractive;
use humidor::circuit::Ckt;
use humidor::merkle::Sha256;

type Field = scuttlebutt::field::F2_19x3_26;

fn test_shared_witness_size(s: usize, input_size: usize, total_size: usize) -> (
    usize, // proof size in bytes
    usize, // expected proof size in bytes
    std::time::Duration, // prover time in ms
    std::time::Duration, // verifier time in ms
) {
    let circuit_size = total_size - input_size;
    let shared_size = 1usize << s;
    debug_assert!(shared_size <= input_size);

    println!("Proving a random circuit with {} gates and {} input registers, {} of which are shared",
        circuit_size, input_size, shared_size);
    println!("---");

    let mut rng = AesRng::from_entropy();
    let (mut ckt, inp): (Ckt<Field>, _) = humidor::circuit::random_ckt_zero(
        &mut rng,
        input_size,
        circuit_size,
    );
    ckt.shared = 0..shared_size;

    let mut prover_time = std::time::Duration::new(0,0);
    let mut verifier_time = std::time::Duration::new(0,0);

    let t = std::time::Instant::now();
    let mut p = <noninteractive::Prover<_, Sha256>>::new(&mut rng, &ckt, &inp);
    prover_time += t.elapsed();
    println!("Prover setup time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let mut v = noninteractive::Verifier::new(&ckt);
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

fn test_size(filename: &str, total_size: usize) -> std::io::Result<()> {
    let mut f = std::fs::File::create(filename)?;
    f.write_all("# shared witness reg,\tproof size (kb),\texpected size (kb),\tprover time (ms),\tverifier time (ms)\n\n".as_bytes())?;

    for s in 0..=14 {
        let (ps, es, p, v) = test_shared_witness_size(s, 1 << 14, total_size);
        f.write_all(format!("{},\t{},\t{},\t{},\t{}\n",
                1 << s, ps, es, p.as_millis(), v.as_millis()).as_bytes())?;
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    test_size("random_circuit_shared_witness_2_16.csv", 1 << 16)?;
    test_size("random_circuit_shared_witness_2_18.csv", 1 << 19)?;
    test_size("random_circuit_shared_witness_2_20.csv", 1 << 22)?;

    Ok(())
}
