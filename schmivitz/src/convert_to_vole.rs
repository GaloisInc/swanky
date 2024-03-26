/*! */
use blake3::hash;
use eyre::{bail, Result};
use vectoreyes::{Aes128EncryptOnly, AesBlockCipher, U8x16};

use crate::all_but_one_vc::IV;
use crate::all_but_one_vc::{commit, open, reconstruct, Com, Decom, Pdecom, Seed};
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use swanky_field::{FiniteRing, IsSubFieldOf};
use swanky_field_binary::F128b;
use swanky_field_binary::F8b;
use swanky_field_binary::F2;
use swanky_serialization::CanonicalSerialize;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

pub(crate) struct PRG {
    aes0: Aes128EncryptOnly,
    counter: u128,
}

impl PRG {
    /// Create a PRG from an an initialization vector `iv`.
    fn new(seed: IV, iv: IV) -> Self {
        let aes0 = Aes128EncryptOnly::new_with_key(seed);

        let bytes = iv.to_bytes();
        let mut counter = 0;
        for b in bytes {
            counter = (counter << 8) + (b as u128);
        }
        Self { aes0, counter }
    }

    fn incr(&mut self) {
        self.counter += 1;
    }

    /// Function that returns a pseudo-random vector of F2 values
    fn prg(mut self, l: usize) -> Vec<F2> {
        let mut res = Vec::with_capacity(l);
        let mut remaining: i64 = l.try_into().unwrap();

        while remaining > 0 {
            let t = self.aes0.encrypt(self.counter.to_le_bytes().into());
            self.incr();

            let v = t.to_bytes();

            for u in v.iter() {
                for i in 0..8 {
                    if remaining <= 0 {
                        return res;
                    }

                    res.push(((u >> i & 1 as u8) == 1).into());
                    remaining -= 1;
                }
            }
        }
        res
    }
    /// Pseudo-random generate seeds to initialize other prgs
    fn generate_prg_seeds(mut self, repetition_param: usize) -> Vec<Seed> {
        let mut res = vec![];

        for i in 0..repetition_param {
            let t = self.aes0.encrypt(self.counter.to_le_bytes().into());
            self.incr();

            res.push(t);
        }
        res
    }
}

fn h1(inp: &[u8], out: &mut [u8]) {
    assert_eq!(out.len(), (SECURITY_PARAM / 8) * 2 /* IV*/);
    let mut hasher = sha3::Shake128::default();
    hasher.update(inp);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

/// Third challenge
pub type Chall3 = [u8; REPETITION_PARAM];

fn h_chall3(/* TODO */) -> Chall3 {
    [0u8; REPETITION_PARAM]
}

type H3 = [u8; SECURITY_PARAM / 8 + 128 / 8];

fn h3(inp: &[u8]) -> H3 {
    let mut hasher = sha3::Shake128::default();
    hasher.update(inp);
    let mut reader = hasher.finalize_xof();

    let mut out: H3 = Default::default();
    reader.read(&mut out);
    out
}

fn convert_to_vole_prover(seeds: &[Seed], iv: IV, l: usize) -> (Vec<F2>, Vec<F8b>) {
    assert!(seeds.len() == 256);
    let mut u_res = vec![F2::ZERO; l];
    let mut v_res = vec![F8b::ZERO; l];

    let mut i = 0u8;
    for seed in seeds.iter() {
        let prg = PRG::new(*seed, iv);
        let v = prg.prg(l);
        for (j, r) in v.iter().enumerate() {
            let i_f8b: F8b = i.into();
            u_res[j] += r;
            v_res[j] += *r * i_f8b;
        }
        i = i.wrapping_add(1);
    }

    (u_res, v_res)
}
///
pub fn bools_to_f8b(d: &[bool]) -> u8 {
    debug_assert!(d.len() == 8);
    let mut r: u8 = 0;
    for (i, b) in d.iter().enumerate() {
        r |= if *b { 1u8 << i } else { 0u8 };
    }

    r
}

// NOTE: the return type is different than ConvertToVOLE in the paper, where is should be a Vec<Vec<F2>>
fn convert_to_vole_verifier(seeds: &[Seed], iv: IV, l: usize, delta: u8) -> Vec<F8b> {
    assert_eq!(seeds.len(), 256);
    let mut v_res = vec![F8b::ZERO; l];

    let mut i = 0u8;

    //println!("delta_u8 {}", delta);
    for (j, seed) in seeds.iter().enumerate() {
        if j != delta as usize {
            let prg = PRG::new(*seed, iv);
            let v = prg.prg(l);
            for (j, r) in v.iter().enumerate() {
                let delta_f8b: F8b = delta.into();
                let i_f8b: F8b = i.into();
                v_res[j] += *r * (delta_f8b - i_f8b);
            }
        } else {
            assert_eq!(*seed, U8x16::default());
        }
        i = i.wrapping_add(1);
    }

    v_res
}
///
pub type Corrections = Vec<Vec<F2>>;

/// Figure 5.4
pub fn vole_commit(
    r: IV,
    iv: IV,
    l: usize,
) -> (Com, Vec<Decom>, Corrections, Vec<F2>, Vec<Vec<F8b>>) {
    let prg_seeds = PRG::new(r, iv).generate_prg_seeds(REPETITION_PARAM);
    let mut u = Vec::with_capacity(REPETITION_PARAM);
    let mut v = Vec::with_capacity(REPETITION_PARAM);
    let mut decom = Vec::with_capacity(REPETITION_PARAM);
    let mut com = Vec::with_capacity(REPETITION_PARAM);
    for i in 0..REPETITION_PARAM {
        let (com_i, decom_i, seeds) = commit(prg_seeds[i], iv, 8);
        let (u_i, v_i) = convert_to_vole_prover(&seeds, iv, l);
        com.push(com_i);
        decom.push(decom_i);
        u.push(u_i);
        v.push(v_i);
    }

    // let's compute the corrections
    let u_0 = u[0].clone(); // TODO: opt transmute here
    let mut corr = Vec::with_capacity(REPETITION_PARAM - 1);
    for i in 1..REPETITION_PARAM {
        let mut ci = Vec::with_capacity(l);
        debug_assert_eq!(l, u_0.len());
        for j in 0..l {
            let c = u_0[j] + u[i][j];
            ci.push(c);
        }
        corr.push(ci);
    }
    debug_assert_eq!(corr.len(), REPETITION_PARAM - 1);

    (
        com[0], // TODO H1 all of them
        decom, corr, u_0, v, // TODO: not exactly same as V in the FAEST spec
    )
}

/// steps 20-22 of Fig 8.2
pub fn vole_open(chal: &[u8], decom: Vec<Decom>) -> Vec<Pdecom> {
    let mut pdecom = Vec::with_capacity(REPETITION_PARAM);
    for i in 0..REPETITION_PARAM {
        let delta_i = chal_dec(&chal, i);
        let pdecom_i = open(&decom[i], delta_i);
        pdecom.push(pdecom_i);
    }
    pdecom
}

const FIXED_CHALLENGE: [bool; 8] = //[false; 8];
    [true, true, false, true, false, true, false, true];
//[false, true, false, true, false, false, false, true];
//

/// TODO: remove pub
pub fn chal_dec(buf: &[u8], i: usize) -> Vec<bool> {
    //let mut dec = vec![];

    //assert!(dec.len() == REPETITION_PARAM);
    //let mut r = vec![false; 8];
    //r.copy_from_slice(&FIXED_CHALLENGE);
    //r
    let b = buf[i];
    let mut r = vec![false; 8];
    for i in 0..8 {
        r[i] = ((b >> i) & 1) != 0;
    }
    r
}

/// Figure 5.5 in FAEST spec v1.1
pub fn vole_reconstruct(
    chal: &[u8], // bytes from fiat-shamir challenge
    pdecom: Vec<Pdecom>,
    iv: IV,
    l: usize,
) -> (Com, Vec<Vec<F8b>>) {
    assert_eq!(pdecom.len(), REPETITION_PARAM);
    assert_eq!(chal.len(), REPETITION_PARAM);
    let mut qs = Vec::with_capacity(REPETITION_PARAM);
    let mut com = Vec::with_capacity(REPETITION_PARAM);
    for i in 0..REPETITION_PARAM {
        let delta = chal_dec(&chal, i);
        let (com_i, seeds) = reconstruct(pdecom[i].clone(), delta.clone(), iv);
        com.push(com_i);

        // let's recompose the seeds and
        let mut seeds_shifted = vec![U8x16::default(); 256];
        let delta_u8 = bools_to_f8b(&delta);
        //println!("delta_u8 {}", delta_u8);
        let mut c = 0;
        for i in 0..256 {
            if i != delta_u8 as usize {
                seeds_shifted[i] = seeds[c];
                c += 1;
            }
        }

        let q_i = convert_to_vole_verifier(&seeds_shifted, iv, l, bools_to_f8b(&delta));

        //let tmp: [F8b; 16];
        //tmp.copy_from_slice(&q_i);
        //qs.push(F8b::form_superfield(&tmp.into()));
        qs.push(q_i);
    }

    (
        com[0], // TODO H1 all of them
        qs,
    )
}

/// Lines 7-14 of Figure 8.3
pub fn vole_recompose_q(
    q: Vec<Vec<F8b>>,
    chall3: &Chall3,
    corr: Corrections,
    how_many: usize,
) -> Vec<F128b> {
    // Q_0 is the same
    // Change Q_i with the corrections:
    // loop Q_i xor (\delta_0 c_i ... \delta_7 c_7)
    // Q = (Q_0 ... Q_{tau-1})
    let mut qs = Vec::with_capacity(how_many);
    for _ in 0..how_many {
        qs.push([F8b::default(); REPETITION_PARAM]);
    }
    for pos in 0..how_many {
        qs[pos][0] = q[0][pos];
    }
    for tau in 1..REPETITION_PARAM {
        let delta = chal_dec(chall3, tau);

        for pos in 0..how_many {
            let c_tau = corr[tau - 1][pos];
            let mut delta_times_corr = [F2::default(); 8];
            for (i, d) in delta.iter().enumerate() {
                let corr = (if *d { F2::ONE } else { F2::ZERO }) * c_tau; // TODO: can optimize that
                                                                          //println!("bit:{:?} corr:{:?}", *d, corr);
                delta_times_corr[i] = corr;
            }
            let delta_times_corr_f8b: F8b = F2::form_superfield(&delta_times_corr.into());
            //println!("delta_times:{:?}", delta_times_corr_f8b);
            qs[pos][tau] = q[tau][pos] + delta_times_corr_f8b;
        }
    }

    let mut q_128b: Vec<F128b> = Vec::with_capacity(how_many);
    for pos in 0..how_many {
        q_128b.push(F8b::form_superfield(&qs[pos].into()));
    }
    q_128b
}

type Signature = (Corrections, Vec<Pdecom>, Chall3, IV);

fn l_hat(l: usize) -> usize {
    l + 16 + 2 * SECURITY_PARAM
}

/// Adaptation of FAEST Sign function adapted from Fig. 8.2
pub fn sign(sk: Vec<u8>, pk: Vec<u8>, l: usize) -> Signature {
    let rho = [0u8; 16];

    // line 2
    let mut mu = vec![0; SECURITY_PARAM / 8 + 128 / 8 /*IV*/ ];
    h1(&pk, &mut mu);

    // line 3
    let mut h3_inp = vec![];
    h3_inp.extend(sk);
    h3_inp.extend(mu);
    h3_inp.extend(rho);
    let r_iv = h3(&h3_inp);

    // splitting r_iv into r and iv
    let mut r_part: [u8; 16] = [0u8; 16];
    r_part.copy_from_slice(&r_iv[0..8]);
    let r = U8x16::from_bytes((&r_part).into()).unwrap();
    let mut iv_part: [u8; 16] = [0u8; 16];
    iv_part.copy_from_slice(&r_iv[8..16]);
    let iv = U8x16::from_bytes(&iv_part.into()).unwrap();

    // line 4
    let (h, decom, corr, u, v) = vole_commit(r, iv, l_hat(l));

    // TODO: lines 6-20
    let chall1 = vec![0u8; 0];

    let chall3 = h_chall3();

    // lines 20-22
    let pdecom = vole_open(&chall3, decom);

    (corr, pdecom, chall3, iv)
}

/// Adpation of FAEST Verify function Fig. 8.3
pub fn verify(pk: Vec<u8>, sig: Signature, l: usize) -> bool {
    // line 1
    let (corr, pdecom, chall3, iv) = sig;

    let rho = [0u8; 16];

    // line 2
    let mut mu = vec![0; SECURITY_PARAM / 8 + 128 / 8 /*IV*/ ];
    h1(&pk, &mut mu);

    let (h_ver, q) = vole_reconstruct(&chall3, pdecom, iv, l_hat(l));

    return true;
}

mod test {
    use eyre::{bail, Result};
    use vectoreyes::{Aes128EncryptOnly, AesBlockCipher, U8x16};

    use crate::all_but_one_vc::IV;
    use crate::all_but_one_vc::{commit, open, Seed};
    use crate::convert_to_vole::{chal_dec, vole_open};

    use super::{
        bools_to_f8b, convert_to_vole_prover, convert_to_vole_verifier, vole_commit,
        vole_recompose_q, vole_reconstruct, Chall3,
    };
    use crate::parameters::REPETITION_PARAM;
    use rand::{thread_rng, Rng, RngCore};
    use swanky_field::{FiniteRing, IsSubFieldOf};
    use swanky_field_binary::F2;
    use swanky_field_binary::{F128b, F8b};
    use swanky_serialization::CanonicalSerialize;

    #[test]
    fn test_convert_to_vole() {
        let mut seeds = vec![];
        let rng = &mut thread_rng();

        let mut arr = [0u8; 16];
        for _ in 0..256 {
            rng.try_fill_bytes(&mut arr).unwrap();
            seeds.push(U8x16::from_bytes(&arr.into()).unwrap());
        }

        rng.try_fill_bytes(&mut arr).unwrap();
        let iv = U8x16::from_bytes(&arr.into()).unwrap();

        let delta = 3u8;
        let how_many = 10;
        let (u, vs) = convert_to_vole_prover(&seeds, iv, how_many);

        let mut seeds_verifier = [U8x16::default(); 256];
        for i in 0..256 {
            if i != (delta as usize) {
                seeds_verifier[i] = seeds[i];
            }
        }
        let qs = convert_to_vole_verifier(&seeds_verifier, iv, how_many, delta);

        println!("Minus one {:?}", -(F8b::ONE));
        for ((u, v), q) in u.iter().zip(vs.iter()).zip(qs.iter()) {
            let delta_f8b: F8b = delta.into();
            assert_eq!(*q, (*u * delta_f8b) - *v);
        }
    }

    #[test]
    fn test_vole_commit_reconstruct() {
        let mut seeds = vec![];
        let rng = &mut thread_rng();

        let mut arr = [0u8; 16];
        for _ in 0..256 {
            rng.try_fill_bytes(&mut arr).unwrap();
            seeds.push(U8x16::from_bytes(&arr.into()).unwrap());
        }

        rng.try_fill_bytes(&mut arr).unwrap();
        let iv = U8x16::from_bytes(&arr.into()).unwrap();

        // This is the delta challenge, set to zero for now, but should come from a challenge
        //let delta = super::chal_dec(); //vec![false; 8];
        let how_many = 10_000;

        let (h, decom, corr, u, v) = vole_commit(seeds[0], iv, how_many);

        let mut chall3: Chall3 = Default::default();
        chall3[0] = 2;

        let pdecom = vole_open(&chall3, decom);

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
            v_f128b.push(F8b::form_superfield(&vs[pos].into()));
        }

        let (h_ver, q) = vole_reconstruct(&chall3, pdecom, iv, how_many);

        // Change Q_i with the corrections:
        // loop Q_i xor (\delta_0 c_i ... \delta_7 c_7)
        // Q = (Q_0 ... Q_{tau-1})
        let q_f128b = vole_recompose_q(q, &chall3, corr, how_many);

        // compute the big delta
        let mut big_delta = [F8b::default(); REPETITION_PARAM];
        for tau in 0..REPETITION_PARAM {
            let delta_i = chal_dec(&chall3, tau);
            let delta_f8b: F8b = bools_to_f8b(&delta_i).into();
            big_delta[tau] = delta_f8b;
        }
        let big_delta_f128b: F128b = F8b::form_superfield(&big_delta.into());

        for pos in 0..how_many {
            //assert_eq!(v_f128b[pos], q_f128b[pos]);
            assert_eq!(v_f128b[pos] + u[pos] * big_delta_f128b, q_f128b[pos]);
        }
    }
}
