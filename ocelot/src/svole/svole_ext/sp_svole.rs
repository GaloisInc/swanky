// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of single-point svole protocol using dummy ggm_prime for
//! testing purposes.

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{
        svole_ext::{
            ggm_utils::{dot_product, ggm, ggm_prime},
            EqReceiver,
            EqSender,
            SpsVoleReceiver,
            SpsVoleSender,
        },
        SVoleReceiver,
        SVoleSender,
    },
};
use generic_array::typenum::Unsigned;
use rand::{CryptoRng, Rng};
use rand_core::RngCore;
use scuttlebutt::{
    field::FiniteField as FF,
    utils::unpack_bits,
    AbstractChannel,
    Block,
    Malicious,
};
use std::marker::PhantomData;

/// SpsVole Sender.
#[derive(Clone)]
pub struct Sender<OT: OtReceiver, FE: FF, SV: SVoleSender, EQ: EqSender> {
    _eq: PhantomData<EQ>,
    svole: SV,
    ot: OT,
    pows: Vec<FE>,
}

/// SpsVole Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtSender, FE: FF, SV: SVoleReceiver, EQ: EqReceiver> {
    _eq: PhantomData<EQ>,
    svole: SV,
    ot: OT,
    delta: FE,
    pows: Vec<FE>,
}

/// Implement SpsVoleSender for Sender type.
impl<
        OT: OtReceiver<Msg = Block> + Malicious,
        FE: FF,
        SV: SVoleSender<Msg = FE>,
        EQ: EqSender<Msg = FE>,
    > SpsVoleSender<SV> for Sender<OT, FE, SV, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
        base_svole: SV,
    ) -> Result<Self, Error> {
        let g = FE::GENERATOR;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let ot = OT::init(channel, rng)?;
        let mut acc = FE::ONE;
        let mut pows = vec![FE::ZERO; r];
        for item in pows.iter_mut().take(r) {
            *item = acc;
            acc *= g;
        }
        Ok(Self {
            _eq: PhantomData::<EQ>,
            pows,
            svole: base_svole,
            ot,
        })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let depth = 128 - (len as u128 - 1).leading_zeros() as usize;
        let n = len;
        let (a, delta) = self.svole.send(channel, 1, rng)?[0];
        let mut beta = FE::PrimeField::random(&mut rng);
        while beta == FE::PrimeField::ZERO {
            beta = FE::PrimeField::random(&mut rng);
        }
        let a_prime = beta - a;
        channel.write_fe(a_prime)?;
        let alpha = rng.gen_range(0, n);
        let mut us = vec![FE::PrimeField::ZERO; n];
        us[alpha] = beta;
        let mut choices = unpack_bits(&(!alpha).to_le_bytes(), depth);
        choices.reverse(); // to get the first bit as MSB.
        let keys = self.ot.receive(channel, &choices, rng).unwrap();
        let vs: Vec<FE> = ggm_prime::<FE>(alpha, &keys);
        let mut ws = vec![FE::ZERO; n];
        for i in 0..n {
            if i != alpha {
                ws[i] = vs[i];
            }
        }
        let d: FE = channel.read_fe()?;
        let sum = ws
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != alpha)
            .map(|(_, &x)| x)
            .sum();
        ws[alpha] = delta - (d + sum);
        // Consistency check
        /*let xz = self.svole.send(channel, r, rng)?;
        let xs: Vec<FE::PrimeField> = xz.iter().map(|&x| x.0).collect();
        let zs: Vec<FE> = xz.iter().map(|&x| x.1).collect();
        let chis: Vec<FE> = (0..n).map(|_| FE::random(rng)).collect();
        let chi_alpha: Vec<FE::PrimeField> = chis[alpha].to_polynomial_coefficients().to_vec();
        let x_stars: Vec<FE::PrimeField> = chi_alpha
            .iter()
            .zip(xs.iter())
            .map(|(&chi_alpha, x)| chi_alpha * beta - *x)
            .collect();
        for chi in chis.iter() {
            channel.write_fe(*chi)?;
        }
        for x in x_stars.iter() {
            channel.write_fe(*x)?;
        }
        let z = dot_product(zs.iter(), self.pows.iter());
        let va = dot_product(chis.iter(), ws.iter()) - z;
        let mut sender = EQ::init()?;
        let b = sender.send(channel, &va)?;
        if b {
            let res = us.iter().zip(ws.iter()).map(|(&u, &w)| (u, w)).collect();
            Ok(res)
        } else {
            Err(Error::EqCheckFailed)
        }*/
        let res = us.iter().zip(ws.iter()).map(|(&u, &w)| (u, w)).collect();
        Ok(res)
    }
    fn send_batch_consistancy_check<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        uws: Vec<Vec<(FE::PrimeField, FE)>>,
        rng: &mut RNG) -> Result<bool, Error> {
            let r = FE::PolynomialFormNumCoefficients::to_usize();
            let xzs = self.svole.send(channel, r, rng)?;
            let xs: Vec<FE::PrimeField> = xzs.iter().map(|&x| x.0).collect();
        let zs: Vec<FE> = xzs.iter().map(|&x| x.1).collect();
            let n = len;
            let t = uws.len();
            let mut alphas = vec![0; t];
            let mut betas = vec![FE::PrimeField::ZERO; t];
            let mut chi_alphas = vec![vec![FE::PrimeField::ZERO]; t];
            let mut chis = vec![vec![FE::ZERO; n]; t];
            let ws: Vec<Vec<FE>> = uws.iter().map(|x| x.iter().map(|(_,w)| *w).collect()).collect();
            for j in 0..t {
                chis[j] = (0..n).map(|_| FE::random(rng)).collect();
                for (i, (u, _)) in uws[j].iter().enumerate(){
                    if *u != FE::PrimeField::ZERO
                    {
                        alphas[j] = i;
                        betas[j] = *u;
                    }
                }
                chi_alphas[j] = ((chis[j])[alphas[j]]).to_polynomial_coefficients().to_vec();
               }
           let x_stars: Vec<FE::PrimeField> = chi_alphas
            .iter().cloned()
            .zip(xs.iter())
            .enumerate().map(|(j, (chi_alpha, x))| chi_alpha[j] * betas[j] - *x)
            .collect();
            for i in 0..n {
                for j in 0..t {
                    channel.write_fe((chis[j])[i])?;
                }
            }
            for x in x_stars.iter() {
                channel.write_fe(*x)?;
            }
            let z = dot_product(zs.iter(), self.pows.iter());
            let va =(0..t).map(|j| dot_product(chis[j].iter(), ws[j].iter())).sum::<FE>() - z;
            let mut sender = EQ::init()?;
            let b = sender.send(channel, &va)?;
            if b {
                Ok(true)
            } else {
                Err(Error::EqCheckFailed)
            }
        }
}

/// Implement SpsVoleReceiver for Receiver type.
impl<
        OT: OtSender<Msg = Block> + Malicious,
        FE: FF,
        SV: SVoleReceiver<Msg = FE>,
        EQ: EqReceiver<Msg = FE>,
    > SpsVoleReceiver<SV> for Receiver<OT, FE, SV, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        mut rng: &mut RNG,
        base_svole: SV,
    ) -> Result<Self, Error> {
        let ot = OT::init(channel, &mut rng)?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::GENERATOR;
        let mut acc = FE::ONE;
        let mut pows = vec![FE::ZERO; r];
        for item in pows.iter_mut().take(r) {
            *item = acc;
            acc *= g;
        }
        let delta = base_svole.delta();
        Ok(Self {
            _eq: PhantomData::<EQ>,
            pows,
            delta,
            ot,
            svole: base_svole,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let depth = 128 - (len as u128 - 1).leading_zeros();
        let n = len;
        let b = self.svole.receive(channel, 1, rng)?[0];
        let a_prime = channel.read_fe::<FE::PrimeField>()?;
        let gamma = b - self.delta.multiply_by_prime_subfield(a_prime);
        let seed = rand::random::<Block>();
        let (vs, keys) = ggm::<FE>(depth as usize, seed);
        self.ot.send(channel, &keys, rng)?;
        // compute d and sends out
        let d = gamma - vs.clone().into_iter().sum();
        channel.write_fe(d)?;
        channel.flush()?;
        /*
        let y_star = self.svole.receive(channel, r, rng)?;
        let mut chi: Vec<FE> = vec![FE::ZERO; n];
        for item in chi.iter_mut() {
            *item = channel.read_fe::<FE>()?;
        }
        let mut x_star: Vec<FE::PrimeField> = vec![FE::PrimeField::ZERO; r];
        for item in x_star.iter_mut() {
            *item = channel.read_fe()?;
        }
        let ys: Vec<FE> = y_star
            .into_iter()
            .zip(x_star.into_iter())
            .map(|(y, x)| y - self.delta.multiply_by_prime_subfield(x))
            .collect();
        // sets Y
        let y = dot_product(ys.iter(), self.pows.iter());
        let vb = dot_product(chi.iter(), vs.iter()) - y;
        let mut receiver = EQ::init()?;
        let res = receiver.receive(channel, rng, &vb)?;
        if res {
            Ok(vs)
        } else {
            Err(Error::EqCheckFailed)
        }*/
        Ok(vs)
    }
    fn receive_batch_consistancy_check<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        vs: Vec<Vec<FE>>,
        rng: &mut RNG) -> Result<bool, Error>{
            let r = FE::PolynomialFormNumCoefficients::to_usize();
            let y_stars = self.svole.receive(channel, r, rng)?;
            let n = len;
            let t = vs.len();
            let mut chis = vec![vec![FE::ZERO; n]; t];
            for i in 0..n {
                for j in 0..t {
                    (chis[j])[i] = channel.read_fe()?;
                }
            }
            let mut x_star: Vec<FE::PrimeField> = vec![FE::PrimeField::ZERO; r];
            for item in x_star.iter_mut() {
                *item = channel.read_fe()?;
            }
            let ys: Vec<FE> = y_stars
            .into_iter()
            .zip(x_star.into_iter())
            .map(|(y, x)| y - self.delta.multiply_by_prime_subfield(x))
            .collect();
            let y = dot_product(ys.iter(), self.pows.iter());
            let vb = (0..t).map(|j| dot_product(chis[j].iter(), vs[j].iter())).sum::<FE>() - y;
            let mut receiver = EQ::init()?;
        let res = receiver.receive(channel, rng, &vb)?;
        if res {
            Ok(true)
        } else {
            Err(Error::EqCheckFailed)
        }
        }
}
