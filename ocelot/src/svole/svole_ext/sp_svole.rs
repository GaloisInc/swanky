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
            ggm_utils::{dot_product, ggm, ggm_prime, point_wise_addition, scalar_multiplication},
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
use std::marker::PhantomData;

/// SpsVole Sender.
#[derive(Clone)]
pub struct Sender<OT: OtReceiver, FE: FF, EQ: EqSender> {
    _eq: PhantomData<EQ>,
    ot: OT,
    pows: Vec<FE>,
    uws: Vec<(FE::PrimeField, FE)>,
    counter: usize,
    iters: usize,
}

/// SpsVole Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtSender, FE: FF, EQ: EqReceiver> {
    _eq: PhantomData<EQ>,
    ot: OT,
    delta: FE,
    pows: Vec<FE>,
    vs: Vec<FE>,
    counter: usize,
    iters: usize,
}

/// Implement SpsVoleSender for Sender type.
impl<
        OT: OtReceiver<Msg = Block> + Malicious,
        FE: FF,
        SV: SVoleSender<Msg = FE>,
        EQ: EqSender<Msg = FE>,
    > SpsVoleSender<SV> for Sender<OT, FE, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
        base_svole: &mut SV,
        iters: usize,
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
        let uws = base_svole.send(channel, iters + r, rng)?;
        Ok(Self {
            _eq: PhantomData::<EQ>,
            pows,
            ot,
            uws,
            counter: 0,
            iters,
        })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        mut rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        //let r = FE::PolynomialFormNumCoefficients::to_usize();
        if self.counter >= self.iters {
            return Err(Error::Other(
                "The number of iterations allowed exhausted!".to_string(),
            ));
        }
        let depth = 128 - (len as u128 - 1).leading_zeros() as usize;
        let n = len;
        //let (a, delta) = self.svole.send(channel, 1, rng)?[0];
        let (a, delta) = self.uws[self.counter];
        self.counter += 1;
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
        let res = us.iter().zip(ws.iter()).map(|(&u, &w)| (u, w)).collect();
        Ok(res)
    }
    fn voles(&self) -> Vec<(FE::PrimeField, FE)> {
        self.uws.clone()
    }
    fn send_batch_consistency_check<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        uws: Vec<Vec<(FE::PrimeField, FE)>>,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        if self.counter >= self.iters + r {
            return Err(Error::Other("No more consistency checks!".to_string()));
        }
        //let xzs = self.svole.send(channel, r, rng)?;
        let xzs: Vec<(FE::PrimeField, FE)> = (0..r).map(|i| self.uws[self.counter + i]).collect();
        self.counter += r;
        let xs: Vec<FE::PrimeField> = xzs.iter().map(|&x| x.0).collect();
        let zs: Vec<FE> = xzs.iter().map(|&x| x.1).collect();
        let n = len;
        let t = uws.len();
        let seed = rand::random::<Block>();
        let mut rng_chi = AesRng::from_seed(seed);
        let chis: Vec<Vec<FE>> = (0..t)
            .map(|_| (0..n).map(|_| FE::random(&mut rng_chi)).collect())
            .collect();
        debug_assert!(chis.len() == t);
        debug_assert!(chis[0].len() == n);
        channel.write_block(&seed)?;
        let mut alphas = vec![0; t];
        let mut betas = vec![FE::PrimeField::ZERO; t];
        let mut chi_alphas = vec![vec![FE::PrimeField::ZERO; r]; t];
        let ws: Vec<Vec<FE>> = uws
            .iter()
            .map(|x| x.iter().map(|(_, w)| *w).collect())
            .collect();
        for j in 0..t {
            for (i, (u, _)) in uws[j].iter().enumerate() {
                if *u != FE::PrimeField::ZERO {
                    alphas[j] = i;
                    betas[j] = *u;
                }
            }
            chi_alphas[j] = ((chis[j])[alphas[j]]).to_polynomial_coefficients().to_vec();
        }
        let x_tmp: Vec<Vec<_>> = (0..t)
            .map(|i| scalar_multiplication(betas[i], &chi_alphas[i]))
            .collect();
        debug_assert!(x_tmp[0].len() == r);
        debug_assert!(x_tmp.len() == t);
        let mut x_stars = vec![FE::PrimeField::ZERO; r];
        for item in x_tmp.iter().take(t) {
            x_stars = point_wise_addition(x_stars.iter(), item.iter());
        }
        debug_assert!(x_stars.len() == r);
        x_stars = x_stars
            .iter()
            .cloned()
            .zip(xs.iter())
            .map(|(y, x)| y - *x)
            .collect();
        debug_assert!(x_stars.len() == r);
        for x in x_stars.iter() {
            channel.write_fe(*x)?;
        }
        let z = dot_product(zs.iter(), self.pows.iter());
        let va = (0..t)
            .map(|j| dot_product(chis[j].iter(), ws[j].iter()))
            .sum::<FE>()
            - z;
        let mut sender = EQ::init()?;
        let b = sender.send(channel, &va)?;
        if b {
            Ok(())
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
    > SpsVoleReceiver<SV> for Receiver<OT, FE, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        mut rng: &mut RNG,
        base_svole: &mut SV,
        iters: usize,
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
        let vs = base_svole.receive(channel, iters + r, rng)?;
        Ok(Self {
            _eq: PhantomData::<EQ>,
            pows,
            delta,
            ot,
            vs,
            counter: 0,
            iters,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn voles(&self) -> Vec<FE> {
        self.vs.clone()
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        if self.counter >= self.iters {
            return Err(Error::Other(
                "The number of iterations allowed exhausted!".to_string(),
            ));
        }
        let depth = 128 - (len as u128 - 1).leading_zeros();
        //let n = len;
        //let b = self.svole.receive(channel, 1, rng)?[0];
        let b = self.vs[self.counter];
        self.counter += 1;
        let a_prime = channel.read_fe::<FE::PrimeField>()?;
        let gamma = b - self.delta.multiply_by_prime_subfield(a_prime);
        let seed = rand::random::<Block>();
        let (vs, keys) = ggm::<FE>(depth as usize, seed);
        self.ot.send(channel, &keys, rng)?;
        // compute d and sends out
        let d = gamma - vs.clone().into_iter().sum();
        channel.write_fe(d)?;
        channel.flush()?;
        Ok(vs)
    }
    fn receive_batch_consistency_check<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        len: usize,
        vs: Vec<Vec<FE>>,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        if self.counter >= self.iters + r {
            return Err(Error::Other("No more consistency checks!".to_string()));
        }
        //let y_stars = self.svole.receive(channel, r, rng)?;
        let y_stars: Vec<FE> = (0..r).map(|i| self.vs[self.counter + i]).collect();
        self.counter += r;
        let n = len;
        let t = vs.len();
        let seed = channel.read_block()?;
        let mut rng_chi = AesRng::from_seed(seed);
        let chis: Vec<Vec<FE>> = (0..t)
            .map(|_| (0..n).map(|_| FE::random(&mut rng_chi)).collect())
            .collect();
        let mut x_stars: Vec<FE::PrimeField> = vec![FE::PrimeField::ZERO; r];
        for item in x_stars.iter_mut() {
            *item = channel.read_fe()?;
        }
        let ys: Vec<FE> = y_stars
            .into_iter()
            .zip(x_stars.into_iter())
            .map(|(y, x)| y - self.delta.multiply_by_prime_subfield(x))
            .collect();
        let y = dot_product(ys.iter(), self.pows.iter());
        let vb = (0..t)
            .map(|j| dot_product(chis[j].iter(), vs[j].iter()))
            .sum::<FE>()
            - y;
        let mut receiver = EQ::init()?;
        let res = receiver.receive(channel, rng, &vb)?;
        if res {
            Ok(())
        } else {
            Err(Error::EqCheckFailed)
        }
    }
}
