/*! */
use eyre::{bail, Result};
use vectoreyes::{Aes128EncryptOnly, AesBlockCipher, U8x16};

use crate::all_but_one_vc::IV;
use crate::all_but_one_vc::{commit, open, reconstruct, Com, Decom, Pdecom, Seed};
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
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

fn h1_core(inp: &[u8], out: &mut [u8]) {
    assert_eq!(out.len(), (SECURITY_PARAM / 8) * 2);
    let mut hasher = sha3::Shake128::default();
    hasher.update(inp);
    hasher.update(&[1u8]);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

/// Result of [`h1`] hash function.
pub type H1 = [u8; (SECURITY_PARAM / 8) * 2];

/// H1 hash function.
///
/// It is called at the beginning of the protocol on both sides.
fn h1(inp: &[u8]) -> H1 {
    let mut out = H1::default();
    h1_core(inp, &mut out);
    out
}

/// This is `$H_2^3$` in FAEST spec
fn h2(inp: &[u8], out: &mut [u8]) {
    let mut hasher = Shake128::default();
    hasher.update(inp);
    hasher.update(&[2u8]);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

/// Length of 1st challenge in bytes.
const CHALL1_LENGTH: usize = (SECURITY_PARAM * 6) / 8;
/// First challenge
pub type Chall1 = [u8; CHALL1_LENGTH];

/// This is `$H_2^2$` in FAEST spec.
fn h_chall1(inp: &[u8]) -> Chall1 {
    let mut out: Chall1 = [0u8; CHALL1_LENGTH]; // NOTE: default does not work here
    h2(inp, &mut out);
    out
}

/// Length of 2nd challenge in bytes.
const CHALL2_LENGTH: usize = (SECURITY_PARAM * 3 + 64) / 8;
/// Second challenge
pub type Chall2 = [u8; CHALL2_LENGTH];

/// This is `$H_2^2$` in FAEST spec.
fn h_chall2(inp: &[u8]) -> Chall2 {
    let mut out: Chall2 = [0u8; CHALL2_LENGTH]; // NOTE: default does not work here
    h2(inp, &mut out);
    out
}

/// Length of 3rd challenge in bytes.
const CHALL3_LENGTH: usize = SECURITY_PARAM / 8;
/// Third challenge.
pub type Chall3 = [u8; CHALL3_LENGTH];

/// This is `$H_2^3$` in FAEST spec.
fn h_chall3(inp: &[u8]) -> Chall3 {
    let mut out = Chall3::default();
    h2(inp, &mut out);
    out
}

type H3 = [u8; SECURITY_PARAM / 8 + 128 / 8];

/// H3 function
fn h3(inp: &[u8]) -> H3 {
    let mut hasher = Shake128::default();
    hasher.update(inp);
    hasher.update(&[3u8]);
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
pub fn bools_to_u8(d: &[bool]) -> u8 {
    debug_assert_eq!(d.len(), 8);
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
        let delta_u8 = bools_to_u8(&delta);
        //println!("delta_u8 {}", delta_u8);
        let mut c = 0;
        for i in 0..256 {
            if i != delta_u8 as usize {
                seeds_shifted[i] = seeds[c];
                c += 1;
            }
        }

        let q_i = convert_to_vole_verifier(&seeds_shifted, iv, l, bools_to_u8(&delta));

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

///
pub fn bitwise_f128b_from_f8b(v: &[F8b; REPETITION_PARAM]) -> F128b {
    let mut tmp: [u8; REPETITION_PARAM] = [0; REPETITION_PARAM];
    for (i, b) in v.iter().enumerate() {
        tmp[i] = b.to_bytes()[0];
    }
    F128b::from_bytes(&tmp.into()).unwrap()
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
        let val = bitwise_f128b_from_f8b(&qs[pos]);
        q_128b.push(val);
    }
    q_128b
}

fn recompose_d(chall3: &Chall3, u_tilda: &[F2]) -> Vec<F2> {
    assert_eq!(u_tilda.len(), SECURITY_PARAM + B);
    let how_many = u_tilda.len();
    let mut qs = Vec::with_capacity(how_many * REPETITION_PARAM * 8);

    for tau in 0..REPETITION_PARAM {
        let delta = chal_dec(chall3, tau);
        let delta_f2: Vec<_> = delta
            .iter()
            .map(|b| if *b { F2::ONE } else { F2::ZERO })
            .collect();
        for b in delta_f2 {
            for u in u_tilda.iter() {
                qs.push(b * *u);
            }
        }
    }
    assert_eq!(qs.len(), how_many * REPETITION_PARAM * 8);

    qs
}

fn l_hat(l: usize) -> usize {
    l + B + 2 * SECURITY_PARAM
}

fn corrections_to_bytes(corr: &Corrections) -> Vec<u8> {
    // Corrections are a vector containing tau vectors of long size
    let how_many = corr[0].len();
    let tau = corr.len();
    let mut out = Vec::with_capacity((how_many * tau) / 8);

    let mut b = 0u8;
    let mut i = 0;
    for c in corr.iter() {
        for bit in c.iter() {
            b |= if *bit == F2::ZERO { 0 } else { 1 << i };
            if i == 7 {
                out.push(b);
                b = 0u8;
                i = 0;
            } else {
                i += 1;
            }
        }
    }
    out
}

fn compute_r_iv(sk: &[u8], mu: &H1, rho: &[u8]) -> (U8x16, U8x16) {
    let mut h3_inp = vec![];
    h3_inp.extend(sk);
    h3_inp.extend(mu);
    h3_inp.extend(rho);
    let r_iv: H3 = h3(&h3_inp);

    // splitting r_iv into r and iv
    let mut r_part: [u8; 16] = [0u8; SECURITY_PARAM / 8];
    r_part.copy_from_slice(&r_iv[0..SECURITY_PARAM / 8]);
    let r = U8x16::from_bytes((&r_part).into()).unwrap();
    let mut iv_part: [u8; 16] = [0u8; 128 / 8];
    iv_part.copy_from_slice(&r_iv[SECURITY_PARAM / 8..(SECURITY_PARAM + 128) / 8]);
    let iv = U8x16::from_bytes(&iv_part.into()).unwrap();
    (r, iv)
}

fn compute_chall_1(mu: &H1, h_com: &Com, corr: &Corrections, iv: &IV) -> Chall1 {
    let mut inp = vec![];
    inp.extend(mu);
    // TODO: add `h``
    inp.extend(corrections_to_bytes(&corr));
    inp.extend(iv.to_bytes());
    h_chall1(&inp)
}

fn compute_chall_2(chall1: &Chall1 /* TODO remaining parameters*/) -> Chall2 {
    let mut inp = vec![];
    inp.extend(chall1);
    // TODO: add more
    h_chall2(&inp)
}

fn compute_chall_3(chall2: &Chall2 /* TODO remaining parameters*/) -> Chall3 {
    let mut inp = vec![];
    inp.extend(chall2);
    // TODO: add more
    h_chall3(&inp)
}

const B: usize = 16;

fn to_field_f128_and_pad<I: Iterator<Item = F2>>(x: I, x_len: usize) -> Vec<F128b> {
    let floor = x_len / 128;
    let how_many = floor + if (x_len - (floor) * 128) != 0 { 1 } else { 0 };
    let mut out = Vec::with_capacity(how_many);

    let mut b_128 = [0u8; 128 / 8];
    let mut byte_num = 0;
    let mut bit_num: usize = 0;
    for b in x.into_iter() {
        b_128[byte_num] |= if b == F2::ZERO { 0 } else { 1 << bit_num };
        if bit_num == 7 {
            bit_num = 0; // restart at the beginning of byte
            if byte_num == (128 / 8) - 1 {
                out.push(F128b::from_bytes(&b_128.into()).unwrap());
                byte_num = 0;
                b_128 = [0u8; 128 / 8]; // reset
            } else {
                byte_num += 1;
            }
        } else {
            bit_num += 1;
        }
    }
    if (bit_num != 0) | (byte_num != 0) {
        out.push(F128b::from_bytes(&b_128.into()).unwrap())
    }

    assert_eq!(out.len(), how_many);
    out
}

fn simply_vole_hash<I1: Iterator<Item = F2>, I2: Iterator<Item = F2>>(
    seed: &[u8],
    x0: I1,
    x0_len: usize,
    x1: I2,
    x1_len: usize,
) -> Vec<F2> {
    assert_eq!(seed.len(), CHALL1_LENGTH);
    let byte_len: usize = 128 / 8;
    let mut tmp = [u8::default(); 128 / 8];
    tmp.copy_from_slice(&seed[0..byte_len]);
    let r0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len..byte_len * 2]);
    let r1 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 2..byte_len * 3]);
    let r2 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 3..byte_len * 4]);
    let r3 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 4..byte_len * 5]);
    let s0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 5..byte_len * 6]);
    let s1 = F128b::from_bytes(&tmp.into()).unwrap();

    // TODO: we dont need to compute how_many, we could directly use `x0_vec.len()`
    let floor = x0_len / SECURITY_PARAM;
    let how_many = floor
        + if (x0_len - floor * SECURITY_PARAM) != 0 {
            1
        } else {
            0
        };

    let x0_vec = to_field_f128_and_pad(x0, x0_len);
    assert_eq!(x0_vec.len(), how_many);
    let mut h0 = F128b::ZERO;
    let mut h1 = F128b::ZERO;
    let mut s0_power = s0;
    let mut s1_power = s1;
    for i in 0..how_many {
        h0 += s0_power * x0_vec[i];
        h1 += s1_power * x0_vec[i];
        s0_power *= s0; // TODO: should I do the power in reverse order?? as in the spec
        s1_power *= s1;
    }
    let h2 = r0 * h0 + r1 * h1;
    let h3 = r2 * h0 + r3 * h1;

    let h2_bits = h2.bit_decomposition();
    let h3_bits = h3.bit_decomposition();

    let mut all_bits = vec![];
    all_bits.extend_from_slice(h2_bits.as_slice());
    all_bits.extend_from_slice(h3_bits.as_slice());

    all_bits.truncate(x1_len);
    all_bits
        .iter()
        .zip(x1.into_iter())
        .map(|(b1, b2)| (if *b1 { F2::ONE } else { F2::ZERO }) + b2)
        .collect()
}

struct BitDecomposer<'a> {
    data: &'a Vec<Vec<F8b>>,
    outer_index: usize,
    inner_index: usize,
    bit_index: u8,
}

impl<'a> BitDecomposer<'a> {
    fn new(data: &'a Vec<Vec<F8b>>) -> Self {
        Self {
            data,
            outer_index: 0,
            inner_index: 0,
            bit_index: 0,
        }
    }

    fn next_position(&mut self) {
        if self.inner_index == self.data[0].len() - 1 {
            self.inner_index = 0;
            if self.bit_index == 7 {
                self.bit_index = 0;
                self.outer_index += 1;
            } else {
                self.bit_index += 1;
            }
        } else {
            self.inner_index += 1;
        }
    }

    fn is_out_of_range(&self) -> bool {
        self.outer_index >= self.data.len()
    }
}

impl<'a> Iterator for BitDecomposer<'a> {
    type Item = F2;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_out_of_range() {
            return None;
        }

        let b = if self.data[self.outer_index][self.inner_index].get_bit(self.bit_index) == 1u8 {
            F2::ONE
        } else {
            F2::ZERO
        };
        self.next_position();
        Some(b)
    }
}

fn decompose_bits<'a>(data: &'a Vec<Vec<F8b>>) -> BitDecomposer<'a> {
    BitDecomposer::new(data)
}

fn bits_to_u8_many(bits: &[F2]) -> Vec<u8> {
    let mut idx = 0;
    let mut b = 0u8;
    let mut out = vec![];

    for bit in bits.iter() {
        b |= (if *bit == F2::ZERO { 0 } else { 1 }) << idx;
        if idx == 7 {
            idx = 0;
            out.push(b);
            b = 0u8; // reset
        } else {
            idx += 1;
        }
    }
    if idx != 0 {
        out.push(b);
    }
    out
}

fn vec_f128b_to_f2(v: &[F128b]) -> Vec<F2> {
    let mut out: Vec<F2> = vec![];
    let len = v.len();

    for j in 0..128 {
        for k in 0..len {
            // TODO: that's super inefficient
            let bools: Vec<_> = v[k]
                .bit_decomposition()
                .as_slice()
                .iter()
                .map(|b| if *b { F2::ONE } else { F2::ZERO })
                .collect();
            out.push(bools[j]);
        }
    }
    assert_eq!(out.len(), v.len() * 128);
    out
}

type U_HASH = Vec<F2>;

type Signature = (Corrections, U_HASH, Vec<Pdecom>, Chall3, IV);

/// Adaptation of FAEST Sign function adapted from Fig. 8.2
pub fn sign(
    sk: Vec<u8>,
    pk: Vec<u8>,
    l: usize,
) -> (
    Signature,
    Vec<F2>,       /* for debugging */
    Vec<Vec<F8b>>, /* for debugging */
) {
    let rho = [0u8; 16];

    // line 2
    let mu: H1 = h1(&pk); // DIFF: the FAEST spec also hashes an input `msg`, but we dont have this here

    // line 3
    let (r, iv) = compute_r_iv(&sk, &mu, &rho);

    // lines 4-5
    let (h, decom, corr, u, v) = vole_commit(r, iv, l_hat(l));

    // lines 6
    let chall1 = compute_chall_1(&mu, &h, &corr, &iv);

    // line 7-8

    println!("P chall1:{:?}", chall1);
    let u_tilda = simply_vole_hash(
        &chall1,
        u[0..l + SECURITY_PARAM].into_iter().map(|b| *b),
        l + SECURITY_PARAM,
        u[l + SECURITY_PARAM..l + 2 * SECURITY_PARAM + B]
            .into_iter()
            .map(|b| *b),
        SECURITY_PARAM + B,
    );

    let mut v_tilda: Vec<F2> = Vec::with_capacity((l + SECURITY_PARAM) * SECURITY_PARAM);
    let v_bits: Vec<F2> = decompose_bits(&v).into_iter().collect();
    assert_eq!(v_bits.len(), (l_hat(l) * SECURITY_PARAM));
    let split = l + SECURITY_PARAM; // split between x0 and x1
    let step = l_hat(l);
    for i in 0..SECURITY_PARAM {
        let start = step * i;
        let newt = simply_vole_hash(
            &chall1,
            v_bits[start..start + split].iter().map(|b| *b),
            l + SECURITY_PARAM,
            v_bits[start + split..start + step].iter().map(|b| *b),
            SECURITY_PARAM + B,
        );
        v_tilda.extend(newt);
    }
    // println!("q_tilda {:?}", v_tilda);

    println!("LEN: {}", v_tilda.len());

    let h_v = h1(&bits_to_u8_many(&v_tilda));
    println!("h_v {:?}", h_v);

    // TODO: lines 9-12

    // line 13
    let chall2 = compute_chall_2(&chall1 /*TODO: add more */);

    // Line 18
    let chall3 = compute_chall_3(&chall2 /*TODO: add more */);
    println!("P chall3:{:?}", chall3);
    // lines 20-22
    let pdecom = vole_open(&chall3, decom);

    ((corr, u_tilda, pdecom, chall3, iv), u, v)
}

/// Adpation of FAEST Verify function Fig. 8.3
pub fn verify(
    pk: Vec<u8>,
    sig: Signature,
    l: usize,
) -> (
    bool,
    Vec<F128b>, /* for debugging */
    Chall3,     /* for debugging */
) {
    // line 1
    let (corr, u_tilda, pdecom, chall3, iv) = sig;

    // line 2
    let mu: H1 = h1(&pk);

    // lines 3-4
    let (h, q) = vole_reconstruct(&chall3, pdecom, iv, l_hat(l));

    // line 5
    let chall1 = compute_chall_1(&mu, &h, &corr, &iv);

    // lines 6-14
    let q_f128b = vole_recompose_q(
        q,
        &chall3,
        corr,
        l_hat(l), /* TODO: unsure about this value*/
    );

    let q_bits = vec_f128b_to_f2(&q_f128b);
    //println!("q_bits {:?}", t);

    println!("V chall1:{:?}", chall1);

    println!("V T{:?}", q_bits.iter().take(100).collect::<Vec<_>>());

    let mut q_tilda: Vec<F2> = Vec::with_capacity((l + SECURITY_PARAM) * SECURITY_PARAM);
    let split = l + SECURITY_PARAM; // split between x0 and x1
    let step = l_hat(l);
    for i in 0..SECURITY_PARAM {
        let start = step * i;
        let newt = simply_vole_hash(
            &chall1,
            q_bits[start..start + split].iter().map(|b| *b),
            l + SECURITY_PARAM,
            q_bits[start + split..start + step].iter().map(|b| *b),
            SECURITY_PARAM + B,
        );
        q_tilda.extend(newt);
    }
    //println!("q_tilda {:?}", q_tilda);

    let big_d = recompose_d(&chall3, &u_tilda);
    //let big_d_bits = f128b_to_f2(&big_d);
    let q_xor_d: Vec<F2> = q_tilda
        .iter()
        .zip(big_d.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    println!("LEN: {}", q_xor_d.len());

    let h_v = h1(&bits_to_u8_many(&q_xor_d));
    println!("h_q {:?}", h_v);

    // TODO: line 15
    // TODO: line 16

    // line 17
    let chall2 = compute_chall_2(&chall1 /*TODO: add more */);

    // Line 20
    let chall3_prime = compute_chall_3(&chall2 /*TODO: add more */);

    return (chall3_prime == chall3, q_f128b, chall3);
}

#[cfg(test)]
mod test {
    use vectoreyes::U8x16;

    use super::{
        bitwise_f128b_from_f8b, bools_to_u8, compute_chall_1, compute_chall_2, compute_chall_3,
        compute_r_iv, convert_to_vole_prover, convert_to_vole_verifier, decompose_bits, h1, l_hat,
        sign, simply_vole_hash, to_field_f128_and_pad, vec_f128b_to_f2, verify, vole_commit,
        vole_recompose_q, vole_reconstruct, B, H1,
    };
    use crate::convert_to_vole::{chal_dec, vole_open};
    use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
    use rand::{thread_rng, RngCore};
    use swanky_field::FiniteRing;
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
        let sk = vec![1u8];
        let pk = vec![1u8];

        let how_many = l_hat(1_000);

        let mu: H1 = h1(&pk);
        let rho = [0u8; 16];
        let (r, iv) = compute_r_iv(&sk, &mu, &rho);

        let (h, decom, corr, u, v) = vole_commit(r, iv, how_many);

        let chall1 = compute_chall_1(&mu, &h, &corr, &iv);
        let chall2 = compute_chall_2(&chall1 /*TODO: add more */);
        let chall3 = compute_chall_3(&chall2 /*TODO: add more */);

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
            let val = bitwise_f128b_from_f8b(&vs[pos]);
            v_f128b.push(val);
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
            let delta_f8b: F8b = bools_to_u8(&delta_i).into();
            big_delta[tau] = delta_f8b;
        }
        let big_delta_f128b = bitwise_f128b_from_f8b(&big_delta);

        for pos in 0..how_many {
            //assert_eq!(v_f128b[pos], q_f128b[pos]);
            assert_eq!(v_f128b[pos] + u[pos] * big_delta_f128b, q_f128b[pos]);
        }
    }

    #[test]
    fn test_padding_of_to_field_f128_and_pad() {
        let v = vec![F2::ZERO; 1000];
        let t = to_field_f128_and_pad(v.into_iter(), 1000);
        assert_eq!(t.len(), 1000 / 128 + 1);

        let v = vec![F2::ZERO; 128];
        let t = to_field_f128_and_pad(v.into_iter(), 128);
        assert_eq!(t.len(), 1);

        let v = vec![F2::ZERO; 129];
        let t = to_field_f128_and_pad(v.into_iter(), 129);
        assert_eq!(t.len(), 2);

        let mut v = vec![F2::ZERO; 130];
        v[0] = F2::ONE;
        v[129] = F2::ONE;
        let t = to_field_f128_and_pad(v.into_iter(), 129);
        let mut res1 = [0u8; 16];
        res1[0] = 1u8;
        assert_eq!(t[0], F128b::from_bytes(&res1.into()).unwrap());
        let mut res2 = [0u8; 16];
        res2[0] = 2u8;
        assert_eq!(t[1], F128b::from_bytes(&res2.into()).unwrap());
        // TODO: Could generate random values and decompose the generated F128b and check the equivalence
    }

    // Test that [`vole_hash`] returns 0 when all the inputs are 0.
    #[test]
    fn test_vole_hash_zero() {
        let seeds = [0u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let x0 = [F2::ZERO; HOW_MANY + SECURITY_PARAM];
        let x1 = [F2::ZERO; SECURITY_PARAM + B];
        let v = simply_vole_hash(
            &seeds,
            x0.into_iter(),
            HOW_MANY + SECURITY_PARAM,
            x1.into_iter(),
            SECURITY_PARAM + B,
        );
        for b in v.iter() {
            assert_eq!(*b, F2::ZERO);
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    #[test]
    fn test_vole_hash_last_xor() {
        let seeds = [0u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let x0 = [F2::ZERO; HOW_MANY + SECURITY_PARAM];
        let mut x1 = [F2::ZERO; SECURITY_PARAM + B];
        let pos = 13;
        x1[pos] = F2::ONE;
        let v = simply_vole_hash(
            &seeds,
            x0.into_iter(),
            HOW_MANY + SECURITY_PARAM,
            x1.into_iter(),
            SECURITY_PARAM + B,
        );
        for (i, b) in v.iter().enumerate() {
            if i == pos {
                assert_eq!(*b, F2::ONE);
            } else {
                assert_eq!(*b, F2::ZERO);
            }
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    #[test]
    fn test_vole_hash_is_linear() {
        let seeds = [1u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        const BOUND: usize = HOW_MANY + SECURITY_PARAM;
        const LAST: usize = SECURITY_PARAM + B;
        let x0 = [F2::ONE; HOW_MANY + 2 * SECURITY_PARAM + B];
        let x1 = [F2::ZERO; HOW_MANY + 2 * SECURITY_PARAM + B];
        let x2 = [F2::ONE; HOW_MANY + 2 * SECURITY_PARAM + B];

        let v0 = simply_vole_hash(
            &seeds,
            x0.clone().into_iter().take(BOUND),
            BOUND,
            x0.clone().into_iter().skip(BOUND),
            LAST,
        );
        let v1 = simply_vole_hash(
            &seeds,
            x1.clone().into_iter().take(BOUND),
            BOUND,
            x1.clone().into_iter().skip(BOUND),
            LAST,
        );
        let v2 = simply_vole_hash(
            &seeds,
            x2.clone().into_iter().take(BOUND),
            BOUND,
            x2.clone().into_iter().skip(BOUND),
            LAST,
        );
        for ((a, b), c) in v0.iter().zip(v1.iter()).zip(v2.iter()) {
            assert_eq!(*a + *b, *c);
        }
    }

    #[test]
    fn test_bit_decomposer() {
        let v: Vec<Vec<F8b>> = vec![vec![2u8.into(), 128u8.into()], vec![0u8.into(), 5.into()]];
        let indices = [2, 2 * 8 - 1, 2 * 8 + 1, 2 * 8 + 5];

        for (i, b) in decompose_bits(&v).into_iter().enumerate() {
            if i == indices[0] || i == indices[1] || i == indices[2] || i == indices[3] {
                assert_eq!(b, F2::ONE);
            } else {
                assert_eq!(b, F2::ZERO);
            }
        }
    }

    #[test]
    fn test_sign_verify() {
        let how_many = 100;
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

        assert!(b);
    }

    #[test]
    fn test_form() {
        let v = [27u8; 16];
        let t: F128b = F128b::from_bytes(&v.into()).unwrap();
        assert_eq!(t.to_bytes()[0], 27u8);
        assert_eq!(t.to_bytes()[1], 27u8);

        let v = 43u8;
        let v_f8b: F8b = F8b::from(v);
        let v_back: u8 = v_f8b.to_bytes()[0];
        assert_eq!(v_back, 43u8);
    }

    #[test]
    fn test_f128b_to_f2() {
        let mut part1 = [0u8; 16];
        let mut part2 = [0u8; 16];
        part1[0] = 1;
        part2[0] = 2;
        part2[1] = 4;

        let t = vec_f128b_to_f2(&[
            F128b::from_bytes(&part1.into()).unwrap(),
            F128b::from_bytes(&part2.into()).unwrap(),
        ]);

        for (i, b) in t.iter().enumerate() {
            if i == 0 || i == 3 || i == (8 + 2) * 2 + 1 {
                assert_eq!(*b, F2::ONE);
            } else {
                assert_eq!(*b, F2::ZERO);
            }
        }
    }
}
