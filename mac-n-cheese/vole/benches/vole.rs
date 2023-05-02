use keyed_arena::KeyedArena;
use mac_n_cheese_party::{IS_PROVER, IS_VERIFIER};
use rand::SeedableRng;
use scuttlebutt::{
    field::{F128p, F56b, F61p, F63b, FiniteField, IsSubFieldOf, F2},
    AbstractChannel, AesRng, Block,
};
use std::str::FromStr;
use std::{any::type_name, hint::black_box, time::Instant};

use mac_n_cheese_vole::{
    mac::Mac,
    specialization::{FiniteFieldSpecialization, NoSpecialization, SmallBinaryFieldSpecialization},
    vole::{VoleReceiver, VoleSender, VoleSizes},
};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn do_bench<
    VF: FiniteField + IsSubFieldOf<FE>,
    FE: FiniteField,
    S: FiniteFieldSpecialization<VF, FE>,
>() {
    use scuttlebutt::Channel;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().unwrap();
    let mut base_vole_rng = AesRng::from_seed(Block::from(2456));
    let alpha = FE::random(&mut base_vole_rng);
    let delta = -alpha;
    let mut base_svoles_s = Vec::new();
    let mut base_svoles_r = Vec::new();
    let sizes = VoleSizes::of::<VF, FE>();
    for _ in 0..sizes.base_voles_needed {
        let x = VF::random(&mut base_vole_rng);
        let beta = FE::random(&mut base_vole_rng);
        let tag = x * alpha + beta;
        base_svoles_s.push(Mac::prover_new(IS_PROVER, x, beta));
        base_svoles_r.push(Mac::verifier_new(IS_VERIFIER, tag));
    }
    let sender = std::thread::spawn(move || {
        let mut rng = AesRng::from_seed(Block::from(456));
        let mut channel = Channel::new(
            BufReader::new(a.try_clone().unwrap()),
            BufWriter::new(a.try_clone().unwrap()),
        );
        let out = VoleSender::<(VF, FE, S)>::init(&mut channel, &mut rng).unwrap();
        channel.flush().unwrap();
        out
    });
    let svole_receiver = {
        let mut rng = AesRng::from_seed(Block::from(455820961));
        let mut channel = Channel::new(
            BufReader::new(b.try_clone().unwrap()),
            BufWriter::new(b.try_clone().unwrap()),
        );
        let out = VoleReceiver::<(VF, FE, S)>::init(&mut channel, &mut rng, delta).unwrap();
        channel.flush().unwrap();
        out
    };
    let svole_sender = sender.join().unwrap();
    let mut comms_1 = vec![0; sizes.comms_1s];
    let mut comms_2 = vec![0; sizes.comms_2r];
    let mut comms_3 = vec![0; sizes.comms_3s];
    let mut comms_4 = vec![0; sizes.comms_4r];
    let mut comms_5 = vec![0; sizes.comms_5s];
    let selector = 43;
    let mut arena = KeyedArena::with_capacity(256_000, 16);
    let sender_rng_initial = AesRng::from_seed(Block::from(3485));
    let mut sender_rng = sender_rng_initial.clone();
    let receiver_rng_initial = AesRng::from_seed(Block::from(12359));
    let mut receiver_rng = receiver_rng_initial.clone();
    let svole_sender_stage2 = svole_sender
        .send(
            &arena,
            selector,
            &mut sender_rng,
            &base_svoles_s,
            &mut comms_1,
        )
        .unwrap();
    let mut r_output = vec![Mac::zero(); sizes.voles_outputted];
    let svole_receiver_stage2 = svole_receiver
        .receive(
            &arena,
            selector,
            &mut receiver_rng,
            &base_svoles_r,
            &mut r_output,
            &comms_1,
            &mut comms_2,
        )
        .unwrap();
    let mut s_output = vec![Mac::zero(); sizes.voles_outputted];
    let svole_sender_stage3 = svole_sender_stage2
        .stage2(
            &svole_sender,
            &arena,
            &base_svoles_s,
            &mut s_output,
            &comms_2,
            &mut comms_3,
        )
        .unwrap();
    let svole_receiver_stage3 = svole_receiver_stage2
        .stage2(
            &svole_receiver,
            &arena,
            &base_svoles_r,
            &mut r_output,
            &comms_3,
            &mut comms_4,
        )
        .unwrap();
    svole_sender_stage3
        .stage3(
            &svole_sender,
            &arena,
            &base_svoles_s,
            &mut s_output,
            &comms_4,
            &mut comms_5,
        )
        .unwrap();
    let alpha = -delta;
    svole_receiver_stage3
        .stage3(
            &svole_receiver,
            &arena,
            &base_svoles_r,
            &mut r_output,
            &comms_5,
        )
        .unwrap();
    let mut sender_voles = s_output;
    let mut receiver_voles = r_output;
    assert_eq!(sender_voles.len(), receiver_voles.len());
    for (sv, tag) in sender_voles.iter().zip(receiver_voles.iter()) {
        let (x, beta) = (*sv).into();
        assert_eq!(x * alpha + beta, tag.tag(IS_VERIFIER));
    }
    for (sv, tag) in sender_voles.iter().zip(receiver_voles.iter()) {
        let (x, beta) = (*sv).into();
        assert_eq!(x * alpha + beta, tag.tag(IS_VERIFIER));
    }
    println!(
        "do_bench<{}, {}, {}> has sizes:\n{:#?}",
        type_name::<VF>(),
        type_name::<FE>(),
        type_name::<S>(),
        VoleSizes::of::<VF, FE>()
    );
    let n: usize = usize::from_str(&std::env::var("N").unwrap_or("15".to_string())).unwrap();
    let start = Instant::now();
    for _ in 0..n {
        arena.reset();
        let mut rng = sender_rng_initial.clone();
        let svole_sender_stage2 = svole_sender
            .send(
                &arena,
                selector,
                &mut rng,
                black_box(&base_svoles_s),
                black_box(comms_1.as_mut_slice()),
            )
            .unwrap();
        sender_voles.fill(Mac::zero());
        let svole_sender_stage3 = svole_sender_stage2
            .stage2(
                &svole_sender,
                &arena,
                &base_svoles_s,
                &mut sender_voles,
                black_box(comms_2.as_slice()),
                black_box(comms_3.as_mut_slice()),
            )
            .unwrap();
        svole_sender_stage3
            .stage3(
                &svole_sender,
                &arena,
                &base_svoles_s,
                &mut sender_voles,
                black_box(comms_4.as_slice()),
                black_box(comms_5.as_mut_slice()),
            )
            .unwrap();
        black_box(sender_voles.as_slice());
    }
    let elapsed = start.elapsed();
    let per_vole = elapsed / u32::try_from(n * sizes.voles_outputted).unwrap();
    println!("Did {n} sender iterations in {elapsed:?} pervole={per_vole:?}");
    let start = Instant::now();
    for _ in 0..n {
        arena.reset();
        let mut rng = receiver_rng_initial.clone();
        let svole_receiver_stage2 = svole_receiver
            .receive(
                &arena,
                selector,
                &mut rng,
                black_box(&base_svoles_r),
                &mut receiver_voles,
                black_box(comms_1.as_slice()),
                black_box(comms_2.as_mut_slice()),
            )
            .unwrap();
        let svole_receiver_stage3 = svole_receiver_stage2
            .stage2(
                &svole_receiver,
                &arena,
                &base_svoles_r,
                &mut receiver_voles,
                black_box(comms_3.as_slice()),
                black_box(comms_4.as_mut_slice()),
            )
            .unwrap();
        let receiver_voles = svole_receiver_stage3
            .stage3(
                &svole_receiver,
                &arena,
                &base_svoles_r,
                &mut receiver_voles,
                black_box(comms_5.as_slice()),
            )
            .unwrap();
        black_box(receiver_voles);
    }
    let elapsed = start.elapsed();
    let per_vole = elapsed / u32::try_from(n * sizes.voles_outputted).unwrap();
    println!("Did {n} receiver iterations in {elapsed:?} pervole={per_vole:?}");
}

fn main() {
    do_bench::<F2, F63b, SmallBinaryFieldSpecialization>();
    do_bench::<F63b, F63b, NoSpecialization>();
    do_bench::<F2, F56b, SmallBinaryFieldSpecialization>();
    do_bench::<F56b, F56b, NoSpecialization>();
    do_bench::<F61p, F61p, NoSpecialization>();
    do_bench::<F128p, F128p, NoSpecialization>();
}
