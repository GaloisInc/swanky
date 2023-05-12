use humidor::ligero::noninteractive;
use rand::SeedableRng;
use scuttlebutt::AesRng;
use simple_arith_circuit::Circuit;

type Hash = sha2::Sha256;
type Field = scuttlebutt::field::F2e19x3e26;
type Prover = noninteractive::Prover<Field, Hash>;
type Verifier = noninteractive::Verifier<Field, Hash>;

fn main() {
    let total_size = 1usize << 20;
    let input_size = 1usize << 16;
    let shared_size = input_size;
    let circuit_size = total_size - input_size;
    debug_assert!(shared_size <= input_size);

    println!(
        "Proving a random circuit with {} gates and {} input registers, {} of which are shared",
        circuit_size, input_size, shared_size
    );
    println!("---");

    let mut rng = AesRng::from_entropy();
    let (ckt, inp): (Circuit<Field>, _) =
        simple_arith_circuit::circuitgen::random_zero_circuit(input_size, circuit_size, &mut rng);

    let mut prover_time = std::time::Duration::new(0, 0);
    let mut verifier_time = std::time::Duration::new(0, 0);

    let t = std::time::Instant::now();
    let mut p = Prover::new(&mut rng, &ckt, &inp, Some(0..shared_size));
    prover_time += t.elapsed();
    println!("Prover setup time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let mut v = Verifier::new(&ckt, Some(0..shared_size));
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
}
