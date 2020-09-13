// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Weng-Yang-Katz-Wang SpsVole protocol (cf.
//! <https://eprint.iacr.org/2020/925>, Figure 5).

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{
        copee::to_fpr,
        svole_ext::{EqReceiver, EqSender, SpsVoleReceiver, SpsVoleSender},
        SVoleReceiver,
        SVoleSender,
    },
};
use generic_array::typenum::Unsigned;
use num::pow;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_core::RngCore;
use scuttlebutt::{
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel,
    AesRng,
    Block,
    Malicious,
};
use std::{
    arch::x86_64::*,
    marker::PhantomData,
    ops::{MulAssign, SubAssign},
};
/// SpsVole Sender.
#[derive(Clone)]
pub struct Sender<OT: OtReceiver + Malicious, FE: FF, SV: SVoleSender, EQ: EqSender> {
    _ot: PhantomData<OT>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _eq: PhantomData<EQ>,
    svole: SV,
    ot: OT,
    pows: Vec<FE>,
}

/// SpsVole Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtSender + Malicious, FE: FF, SV: SVoleReceiver, EQ: EqReceiver> {
    _ot: PhantomData<OT>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    _eq: PhantomData<EQ>,
    svole: SV,
    ot: OT,
    delta: FE,
    pows: Vec<FE>,
}

/// Constructing GGM tree with `h-1` levels.
pub fn prg(depth: usize, seed: Block) -> Vec<Block> {
    let h = depth;
    let mut sv = Vec::new();
    sv.push(seed);
    for i in 1..h + 1 {
        let exp = pow(2, i - 1);
        for j in 0..exp {
            let s = sv[j + exp - 1];
            //PRG G
            let mut rng = AesRng::from_seed(s);
            let (s0, s1) = rng.gen::<(Block, Block)>();
            sv.push(s0);
            sv.push(s1);
        }
    }
    sv
}

/// constructing leaves.
/*pub fn prg_prime<FE: FF>(depth: usize, sv: &[Block]) -> Vec<FE> {
    let h = depth as usize;
    let exp = pow(2, h - 1);
    let mut v = Vec::new();
    for j in 0..exp {
        let temp = sv[h - 1 + j];
        // PRG G'
        let mut rng = AesRng::from_seed(temp);
        let (fe0, fe1) = (FE::random(&mut rng), FE::random(&mut rng));
        v.push(fe0);
        v.push(fe1);
    }
    v
}*/

/// The input vector length `n` may be included in the arguments.
pub fn ggm<FE: FF>(h: usize, seed: Block) -> (Vec<FE>, Vec<(Block, Block)>) {
    //let len: u128 = pow(2, nbits) - 1;
    //let h = 128 - (len - 1).leading_zeros() as usize;
    println!("h={}", h);
    let mut sv = prg(h, seed);
    println!("sv={:?}", sv);
    let zero: __m128i = unsafe { _mm_setzero_si128() };
    let vec_even: Vec<&Block> = sv.iter().skip(1).step_by(2).collect();
    let vec_odd: Vec<&Block> = sv.iter().skip(2).step_by(2).collect();
    let zip_seeds: Vec<(Block, Block)> = vec_even
        .iter()
        .zip(vec_odd.iter())
        .map(|(&s, &t)| (*s, *t))
        .collect();
    let mut k0: Vec<Block> = Vec::new();
    let mut k1: Vec<Block> = Vec::new();
    for i in 1..h + 1 {
        let mut res0 = Block(zero);
        let mut res1 = Block(zero);
        let exp = pow(2, i - 1);
        for j in 0..exp {
            res0 ^= zip_seeds[j + exp - 1].0;
            res1 ^= zip_seeds[j + exp - 1].1;
        }
        k0.push(res0);
        k1.push(res1);
    }
    let exp = pow(2, h);
    let mut v: Vec<FE> = vec![FE::zero(); exp];
    for j in 0..exp {
        v[j] = FE::from_uniform_bytes(&<[u8; 16]>::from(sv[j + exp - 1]));
    }
    let keys: Vec<(Block, Block)> = k0.iter().zip(k1.iter()).map(|(&k, &l)| (k, l)).collect();
    (v, keys)
}

/// GGM prime is used compute the vector of field elements except one entry at `alpha`.
//TODO: this can be fixed and optimized later.
pub fn ggm_prime<FE: FF>(alpha: usize, keys: &[Block]) -> Vec<FE> {
    let nbits = 128 - (alpha as u128 - 1).leading_zeros() as usize;
    let h = keys.len();
    let mut a = unpack_bits(&alpha.to_le_bytes(), h);
    a.reverse();
    let zero: __m128i = unsafe { _mm_setzero_si128() };
    let mut sv: Vec<Block> = vec![Block(zero); pow(2, h)];
    sv.insert(1 + !a[0] as usize, keys[0]);
    for i in 2..h {
        let exp = pow(2, i - 1) as usize;
        let mut tmp = a.clone();
        tmp.truncate(i - 1);
        for j in 0..exp - 1 {
            if j == bv_to_u128(&tmp) as usize {
                continue;
            } else {
                let s = sv[j + exp - 1];
                //PRG G
                let mut rng = AesRng::from_seed(s);
                let (s0, s1) = rng.gen::<(Block, Block)>();
                sv.insert(2 * j + pow(2, i) - 1, s0);
                sv.insert(2 * j + pow(2, i), s1);
            }
        }
        let mut tmp = a.clone();
        tmp.truncate(i);
        let a_i_comp = !a[i - 1];
        tmp.push(a_i_comp);
        let a_i_star = bv_to_u128(&tmp);
        let s_alpha =
            (0..exp - 1)
                .filter(|j| *j != a_i_star as usize)
                .fold(Block(zero), |mut sum, j| {
                    sum ^= sv[pow(2, i) + 2 * j + a_i_comp as usize - 1];
                    sum
                });
        sv.insert((a_i_star + pow(2, i)) as usize - 2, s_alpha ^ keys[i - 1]);
    }
    let mut tmp = a.clone();
    tmp.truncate(h - 1);
    let exp = pow(2, h - 1) as usize;
    let len = pow(2, h);
    let mut v = Vec::with_capacity(len);
    for i in 0..len {
        v.push(FE::zero());
    }
    for j in 0..exp {
        let temp = sv[exp + j - 1];
        if j == bv_to_u128(&tmp) as usize {
            continue;
        } else {
            // PRG G'
            let mut rng = AesRng::from_seed(temp);
            let (fe0, fe1) = (FE::random(&mut rng), FE::random(&mut rng));
            v.insert(2 * j, fe0);
            v.insert(2 * j + 1, fe1);
            v.pop();
            v.pop();
        }
    }
    let a_l = a[h - 1];
    tmp.push(!a_l);
    tmp.reverse();
    let ind = bv_to_u128(&tmp);
    let exp = pow(2, h - 1);
    let mut sum = FE::zero();
    if a_l {
        sum = v.iter().step_by(2).map(|u| *u).sum();
    } else {
        sum = v.iter().skip(1).step_by(2).map(|u| *u).sum();
    }
    sum += FE::from_uniform_bytes(&<[u8; 16]>::from(keys[h - 1]));
    v.insert(ind as usize, sum);
    v
}

/// Implement SpsVole for Sender type.
impl<
        OT: OtReceiver<Msg = Block> + Malicious,
        FE: FF,
        SV: SVoleSender<Msg = FE>,
        EQ: EqSender<Msg = FE>,
    > SpsVoleSender for Sender<OT, FE, SV, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let g = FE::generator();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let ot_receiver = OT::init(channel, rng).unwrap();
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
            acc *= g;
        }
        let svole_sender = SV::init(channel, rng).unwrap();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _eq: PhantomData::<EQ>,
            pows,
            svole: svole_sender,
            ot: ot_receiver,
        })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        mut rng: &mut RNG,
        len: u128,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let levels = 128 - (len - 1).leading_zeros() as usize;
        let n = len as usize;
        let ac = self.svole.send(channel, 1, rng).unwrap();
        let (a, c): (Vec<FE::PrimeField>, Vec<FE>) = ac.iter().cloned().unzip();
        let g = FE::PrimeField::generator();
        let beta = g.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
        let _delta_ = c.clone();
        let mut a_prime = beta.clone();
        a_prime.sub_assign(a[0]);
        channel.write_fe(a_prime)?;
        let alpha = rng.gen_range(0, n);
        let mut u = vec![FE::PrimeField::zero(); n];
        u[alpha] = beta;
        let choices = unpack_bits(&(!alpha).to_le_bytes(), levels);
        let keys = self.ot.receive(channel, &choices, rng).unwrap();
        let v: Vec<FE> = ggm_prime(alpha, &keys);
        let delta_ = c[0];
        let mut d: FE = channel.read_fe().unwrap();
        let mut w: Vec<FE> = v;
        let sum_w = w.iter().enumerate().filter(|(i, _w)| *i != alpha).fold(
            FE::zero(),
            |mut sum: FE, (_, w)| {
                sum.add_assign(*w);
                sum
            },
        );
        d.add_assign(sum_w);
        w[alpha] = delta_;
        w[alpha].sub_assign(d);
        // Both parties send (extend, r), gets (x, z)
        let xz = self.svole.send(channel, r, rng).unwrap();
        let (x, z): (Vec<FE::PrimeField>, Vec<FE>) = xz.iter().cloned().unzip();
        // Sampling `chi`s.
        let chi: Vec<FE> = (0..n).map(|_| FE::random(&mut rng)).collect();
        let chi_alpha = chi[alpha].to_polynomial_coefficients();
        let x_star: Vec<FE::PrimeField> = chi_alpha
            .iter()
            .zip(x.iter().cloned())
            .map(|(chi, x)| {
                let mut tmp = *chi;
                tmp.mul_assign(beta);
                tmp.sub_assign(x);
                tmp
            })
            .collect();
        // Sends chis and x_star
        for item in chi.iter() {
            channel.write_fe(*item)?;
        }
        for item in x_star.iter() {
            channel.write_fe(*item)?;
        }
        let z_ = z
            .iter()
            .zip(self.pows.iter())
            .fold(FE::zero(), |mut sum, (z, pow)| {
                let mut tmp = *z;
                tmp.mul_assign(*pow);
                sum.add_assign(*z);
                sum
            });
        let mut va = chi
            .iter()
            .zip(w.iter().cloned())
            .fold(FE::zero(), |mut sum, (chi, mut w)| {
                w.mul_assign(*chi);
                sum.add_assign(w);
                sum
            });
        va.sub_assign(z_);
        let mut eq_sender = EQ::init()?;
        let res = eq_sender.send(channel, &va);
        match res {
            Ok(b) => {
                if b {
                    let uw = u.iter().zip(w.iter()).map(|(u, w)| (*u, *w)).collect();
                    Ok(uw)
                } else {
                    return Err(Error::Other("EQ check fails".to_string()));
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// Implement SVoleReceiver for Receiver type.
impl<
        OT: OtSender<Msg = Block> + Malicious,
        FE: FF,
        SV: SVoleReceiver<Msg = FE>,
        EQ: EqReceiver<Msg = FE>,
    > SpsVoleReceiver for Receiver<OT, FE, SV, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let ot_sender = OT::init(channel, &mut rng).unwrap();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::generator();
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
            acc *= g;
        }
        let sv_receiver = SV::init(channel, rng).unwrap();
        let delta = sv_receiver.delta();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            _eq: PhantomData::<EQ>,
            pows,
            delta,
            ot: ot_sender,
            svole: sv_receiver,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        len: u128,
    ) -> Result<Vec<FE>, Error> {
        let n = len as usize;
        let depth = 128 - (n - 1).leading_zeros();
        let b = self.svole.receive(channel, 1, rng)?;
        let mut a_prime: FE = channel.read_fe()?;
        let mut gamma = b[0];
        a_prime.mul_assign(self.delta);
        gamma.sub_assign(a_prime);
        // Sample `s` from `$\{0,1\}$`
        let seed = rand::random::<Block>();
        let (v, keys) = ggm(depth as usize, seed);
        self.ot.send(channel, &keys, rng)?;
        channel.flush()?;
        // compute d and sends out
        let sum = v.iter().fold(FE::zero(), |mut sum, v| {
            sum.add_assign(*v);
            sum
        });
        let mut d = gamma.clone();
        d.sub_assign(sum);
        channel.write_fe(a_prime)?;
        channel.flush()?;
        let r = FE::ByteReprLen::to_usize();
        let y_star = self.svole.receive(channel, r, rng).unwrap();
        // Receives `chi`s from the Sender
        let chi: Vec<FE> = (0..n).map(|_| channel.read_fe().unwrap()).collect();
        let x_star: Vec<FE> = (0..r).map(|_| channel.read_fe().unwrap()).collect();
        let y = y_star.clone();
        for (y, mut x) in y.iter().zip(x_star.iter().cloned()) {
            x.mul_assign(self.delta);
            let mut tmp = *y;
            tmp.sub_assign(x);
        }
        // sets Y
        let y_ =
            self.pows
                .iter()
                .zip(y.iter().cloned())
                .fold(FE::zero(), |mut sum, (pow, mut y)| {
                    y.mul_assign(*pow);
                    sum.add_assign(y);
                    sum
                });
        let mut vb = chi
            .iter()
            .zip(v.iter().cloned())
            .fold(FE::zero(), |mut sum, (chi, mut v)| {
                v.mul_assign(*chi);
                sum.add_assign(v);
                sum
            });
        vb.sub_assign(y_);
        let mut eq_receiver = EQ::init().unwrap();
        let res = eq_receiver.receive(channel, rng, &vb);
        match res {
            Ok(b) => {
                if b {
                    Ok(v)
                } else {
                    return Err(Error::Other("EQ check fails".to_string()));
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// Convert bit-vector to a number.
pub fn bv_to_u128(v: &[bool]) -> u128 {
    v.iter()
        .enumerate()
        .map(|(i, &v)| pow(2, i) * v as u128)
        .sum()
}
/// Minimal bit-vector representation of a number.
pub fn u128_to_bv(n: u128) -> Vec<bool> {
    let nbits = 128 - (n - 1).leading_zeros() as usize;
    (0..nbits).map(|i| ((n >> i) & 1) != 0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::field::Gf128;

    #[test]
    fn test_bv_to_u128() {
        let x = rand::random::<u128>();
        let bv = u128_to_bv(x);
        assert_eq!(bv_to_u128(&bv), x);
    }

    #[test]
    fn test_ggm() {
        let x = rand::random::<Block>();
        // Runs for a while if the range is over 20.
        let depth = rand::thread_rng().gen_range(1, 18);
        let (v, keys) = ggm::<Gf128>(depth, x);
        let k: Vec<Block> = keys.iter().map(|k| k.0).collect();
        let leaves = pow(2, depth);
        let alpha = leaves - 1;
        let v1 = ggm_prime::<Gf128>(alpha, &k);
        for i in 0..leaves {
            if i != alpha {
                assert_eq!(v[i], v1[i]);
            }
        }
    }
}
