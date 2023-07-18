use diet_mac_and_cheese::edabits::{ProverConv, VerifierConv};
use ocelot::svole::{LPN_EXTEND_MEDIUM, LPN_SETUP_MEDIUM};
use scuttlebutt::{channel::track_unix_channel_pair, field::F61p, AesRng};
use std::time::Instant;

type Prover = ProverConv<F61p>;
type Verifier = VerifierConv<F61p>;

fn run() {
    let (mut sender, mut receiver) = track_unix_channel_pair();
    let nb_bits: usize = 8;
    let n = 1_000_000;
    let num_bucket = 3;
    let num_cut = num_bucket;
    let handle = std::thread::spawn(move || {
        #[cfg(target_os = "linux")]
        {
            let mut cpu_set = nix::sched::CpuSet::new();
            cpu_set.set(1).unwrap();
            nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
        }
        let mut rng = AesRng::new();
        let start = Instant::now();
        let mut fconv_sender =
            Prover::init(&mut sender, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap();
        println!("Send time (init): {:?}", start.elapsed());
        let start = Instant::now();
        let edabits = fconv_sender
            .random_edabits(&mut sender, &mut rng, nb_bits, n)
            .unwrap();
        println!("Send time (random edabits): {:?}", start.elapsed());
        let start = Instant::now();
        let _ = fconv_sender
            .conv(&mut sender, &mut rng, num_bucket, num_cut, &edabits, None)
            .unwrap();
        println!("Send time (conv): {:?}", start.elapsed());
    });
    #[cfg(target_os = "linux")]
    {
        let mut cpu_set = nix::sched::CpuSet::new();
        cpu_set.set(3).unwrap();
        nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
    }
    let mut rng = AesRng::new();
    let start = Instant::now();
    let mut fconv_receiver =
        Verifier::init(&mut receiver, &mut rng, LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM).unwrap();
    println!("Receive time (init): {:?}", start.elapsed());
    println!(
        "Send communication (init): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (init): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    receiver.clear();
    let start = Instant::now();
    let edabits_mac = fconv_receiver
        .random_edabits(&mut receiver, &mut rng, nb_bits, n)
        .unwrap();
    println!("Receive time (random edabits): {:?}", start.elapsed());
    println!(
        "Send communication (random edabits): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (random edabits): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    receiver.clear();
    let start = Instant::now();
    fconv_receiver
        .conv(
            &mut receiver,
            &mut rng,
            num_bucket,
            num_cut,
            &edabits_mac,
            None,
        )
        .unwrap();
    println!("Receive time (conv): {:?}", start.elapsed());
    println!(
        "Send communication (conv): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (conv): {:.4} Mb",
        receiver.kilobits_written() / 1000.0
    );
    handle.join().unwrap();
}

fn main() {
    println!("\nField: F61p \n");
    run()
}
