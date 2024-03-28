use std::env;
use std::path::PathBuf;

use diet_mac_and_cheese::sieveir_reader_fbs::{read_types, InputFlatbuffers};
use eyre::{bail, Result};
use schmivitz::circuit::{run_prover, RelationStreamer};
use vectoreyes::{Aes128EncryptOnly, AesBlockCipher, U8x16};

use rand::{thread_rng, Rng, RngCore};
use schmivitz::all_but_one_vc::IV;
use schmivitz::all_but_one_vc::{commit, open, Seed};
use schmivitz::convert_to_vole::{
    bitwise_f128b_from_f8b, bools_to_u8, chal_dec, sign, verify, vole_commit, vole_open,
    vole_recompose_q, vole_reconstruct, Chall3,
};
use schmivitz::parameters::REPETITION_PARAM;
use swanky_field::{FiniteRing, IsSubFieldOf};
use swanky_field_binary::F2;
use swanky_field_binary::{F128b, F8b};
use swanky_serialization::CanonicalSerialize;

use schmivitz::proof::ProverPreparer2;

fn test1() {
    let how_many = 1_000_000;
    let t = std::time::Instant::now();
    let sk = vec![1u8];
    let pk = vec![1u8];
    let (sig, u, v) = sign(sk, pk.clone(), how_many);
    let (b, q, chall3) = verify(pk, sig, how_many);

    let mut vs = Vec::with_capacity(how_many);
    for _ in 0..how_many {
        vs.push([F8b::ZERO; REPETITION_PARAM]);
    }

    for pos in 0..how_many {
        for tau in 0..REPETITION_PARAM {
            vs[pos][tau] = v[tau][pos];
        }
    }
    let mut v_f128b: Vec<F128b> = Vec::with_capacity(how_many);
    for pos in 0..how_many {
        let val = bitwise_f128b_from_f8b(&vs[pos]);
        v_f128b.push(val);
    }

    // compute the big delta
    let mut big_delta = [F8b::default(); REPETITION_PARAM];
    for tau in 0..REPETITION_PARAM {
        let delta_i = chal_dec(&chall3, tau);
        let delta_f8b: F8b = bools_to_u8(&delta_i).into();
        big_delta[tau] = delta_f8b;
    }
    let big_delta_f128b = bitwise_f128b_from_f8b(&big_delta);

    for pos in 0..how_many {
        assert_eq!(v_f128b[pos] + u[pos] * big_delta_f128b, q[pos]);
    }

    println!("VOLE-it-Head completed in: {:?}", t.elapsed());
    assert!(b);
}

fn grit() {
    let args: Vec<String> = env::args().collect();

    // Check that two arguments are provided
    if args.len() != 3 {
        eprintln!("Usage: {} <inputs> <relation>", args[0]);
        std::process::exit(1);
    }

    // Extract the paths provided as arguments
    let inputs = &args[1];
    let relation = &args[2];

    // Transform the paths into PathBuf
    let path_inputs = PathBuf::from(inputs);
    let path_relation = PathBuf::from(relation);

    // Display the transformed paths
    println!("Path inputs: {:?}", path_inputs);
    println!("Path relation: {:?}", path_relation);

    run_prover(path_inputs, path_relation).unwrap();
}

fn main() {
    //grit()
    test1();
}
