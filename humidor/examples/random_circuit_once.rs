use rand::SeedableRng;
use scuttlebutt::AesRng;

extern crate humidor;

use humidor::ligero::noninteractive;
use humidor::circuit::Ckt;
use humidor::merkle::Sha256;

type Field = scuttlebutt::field::F2_19x3_26;

fn main() {
    let total_size = 1usize << 16;
    let input_size = 1usize << 14;
    let shared_size = input_size;
    let circuit_size = total_size - input_size;
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
}
