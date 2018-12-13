use fancy_garbling::circuit::Builder;
use fancy_garbling::util::RngExt;

fn main() {
    let mut rng = rand::thread_rng();

    // half-gate
    let mut b = Builder::new();
    let q = rng.gen_prime();
    let x = b.input(q);
    let y = b.input(q);
    let z = b.half_gate(x,y);
    b.output(z);
    let c = b.finish();
    c.to_file("half_gate.json").unwrap();

    // and-gate-fan-n
    let mut b = Builder::new();
    let mut inps = Vec::new();
    let n = 2 + (rng.gen_usize() % 200);
    for _ in 0..n {
        inps.push(b.input(2));
    }
    let z = b.and_many(&inps);
    b.output(z);
    let c = b.finish();
    c.to_file("and_gate_fan_n.json").unwrap()
}
