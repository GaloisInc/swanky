use keyed_arena::KeyedArena;
use mac_n_cheese_party::{IS_PROVER, IS_VERIFIER};
use rand::SeedableRng;
use scuttlebutt::{
    field::{F128p, F56b, F61p, F63b, FiniteField, IsSubFieldOf, F2},
    AbstractChannel, AesRng, Block,
};

use crate::{
    mac::Mac,
    specialization::{FiniteFieldSpecialization, NoSpecialization, SmallBinaryFieldSpecialization},
    vole::{VoleReceiver, VoleSender, VoleSizes},
};

fn do_test<
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
    let arena = KeyedArena::with_capacity(0, 0);
    let svole_sender_stage2 = svole_sender
        .send(
            &arena,
            selector,
            &mut AesRng::from_seed(Block::from(3485)),
            &base_svoles_s,
            &mut comms_1,
        )
        .unwrap();
    let mut r_output = vec![Mac::zero(); sizes.voles_outputted];
    let svole_receiver_stage2 = svole_receiver
        .receive(
            &arena,
            selector,
            &mut AesRng::from_seed(Block::from(85357)),
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
    let sender_voles = s_output;
    let receiver_voles = r_output;
    assert_eq!(sender_voles.len(), receiver_voles.len());
    for (sv, tag) in sender_voles.iter().zip(receiver_voles.iter()) {
        let (x, beta) = (*sv).into();
        assert_eq!(x * alpha + beta, tag.tag(IS_VERIFIER));
    }
}

#[test]
fn test_f63b_binary() {
    do_test::<F2, F63b, SmallBinaryFieldSpecialization>();
}
#[test]
fn test_f63b() {
    do_test::<F63b, F63b, NoSpecialization>();
}
#[test]
fn test_f56b_binary() {
    do_test::<F2, F56b, SmallBinaryFieldSpecialization>();
}
#[test]
fn test_f56b() {
    do_test::<F56b, F56b, NoSpecialization>();
}
#[test]
fn test_f61p() {
    do_test::<F61p, F61p, NoSpecialization>();
}
#[test]
fn test_f128p() {
    do_test::<F128p, F128p, NoSpecialization>();
}
