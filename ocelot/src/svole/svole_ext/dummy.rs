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
        svole_ext::{ggm_utils::ggm, EqReceiver, EqSender, SpsVoleReceiver, SpsVoleSender},
        svole_utils::{dot_prod, to_fpr, to_fpr_vec},
        SVoleReceiver,
        SVoleSender,
    },
};
use generic_array::{typenum::Unsigned, GenericArray};
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
    _sv: PhantomData<SV>,
    _eq: PhantomData<EQ>,
    svole: SV,
    ot: OT,
    pows: Vec<FE>,
}

/// SpsVole Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtSender, FE: FF, SV: SVoleReceiver, EQ: EqReceiver> {
    _sv: PhantomData<SV>,
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
    > SpsVoleSender for Sender<OT, FE, SV, EQ>
{
    type Msg = FE;
    fn init<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let g = FE::generator();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let ot_receiver = OT::init(channel, rng)?;
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
            acc *= g;
        }
        let svole_sender = SV::init(channel, rng)?;
        Ok(Self {
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
        len: u128,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let depth = 128 - (len - 1).leading_zeros() as usize;
        let n = len as usize;
        let ac = self.svole.send(channel, 1, rng)?;
        let (a, c): (Vec<FE::PrimeField>, Vec<FE>) = ac.iter().cloned().unzip();
        let g = FE::PrimeField::generator();
        let beta = g.clone();
        beta.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
        let mut a_prime: FE::PrimeField = beta.clone();
        a_prime -= a[0];
        channel.write_fe::<FE::PrimeField>(a_prime)?;
        let alpha = rng.gen_range(0, n);
        let mut u = vec![FE::PrimeField::zero(); n];
        u[alpha] = beta;
        let choices = unpack_bits(&(!alpha).to_le_bytes(), depth);
        let keys = self.ot.receive(channel, &choices, rng).unwrap();
        /**************************/
        //let v: Vec<FE> = ggm_prime(alpha, &keys);
        // getting this vector from the receiver is completely insecure, I'm just doing this for
        // testing purposes.
        let mut v: Vec<FE> = vec![FE::zero(); n];
        for i in 0..n {
            v[i] = channel.read_fe()?;
        }

        /*************************/
        let delta_ = c[0];
        let mut d: FE = channel.read_fe::<FE>()?;
        let mut w: Vec<FE> = v;
        let sum_w = w
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != alpha)
            .map(|(_, &x)| x)
            .sum();
        w[alpha] = delta_;
        d += sum_w;
        w[alpha] -= d;
        // Both parties send (extend, r), gets (x, z)
        let xz = self.svole.send(channel, r, rng)?;
        let (x, z): (Vec<FE::PrimeField>, Vec<FE>) = xz.iter().cloned().unzip();
        // Sampling `chi`s.
        let chi: Vec<FE> = (0..n).map(|_| FE::random(rng)).collect();
        let chi_alpha_vec: Vec<GenericArray<FE::PrimeField, FE::PolynomialFormNumCoefficients>> =
            (0..n)
                .map(|i| chi[i].to_polynomial_coefficients())
                .collect();
        let chi_alpha: Vec<FE> = (0..n)
            .map(|i| dot_prod(&to_fpr_vec(&chi_alpha_vec[i].to_vec()), &self.pows))
            .collect();
        let mut x_star: Vec<FE::PrimeField> = chi_alpha_vec[alpha]
            .to_vec()
            .iter()
            .map(|&x| x * beta)
            .collect();
        x_star = x_star
            .iter()
            .zip(x.iter().cloned())
            .map(|(&x_s, x)| x_s - x)
            .collect();
        // Sends chis and x_star
        for item in chi_alpha.iter() {
            channel.write_fe(*item)?;
        }
        //channel.flush()?;
        for item in x_star.iter() {
            channel.write_fe(*item)?;
        }
        //channel.flush()?;
        let z_ = dot_prod(&z, &self.pows);
        let mut va = dot_prod(&chi_alpha, &w);
        va -= z_;
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

/// Implement SpsVoleReceiver for Receiver type.
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
        let ot_sender = OT::init(channel, &mut rng)?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let g = FE::generator();
        let mut acc = FE::one();
        let mut pows = vec![FE::zero(); r];
        for i in 0..r {
            pows[i] = acc;
            acc *= g;
        }
        let sv_receiver = SV::init(channel, rng)?;
        let delta = sv_receiver.delta();
        Ok(Self {
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
        len: u128,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        let n = len as usize;
        let depth = 128 - (len - 1).leading_zeros();
        let b = self.svole.receive(channel, 1, rng)?;
        let a_prime = channel.read_fe::<FE::PrimeField>()?;
        let mut gamma = b[0];
        let mut delta_ = self.delta;
        delta_ *= to_fpr(a_prime);
        gamma -= delta_;
        // Sample `s` from `$\{0,1\}$`
        let seed = rand::random::<Block>();
        let (v, keys) = ggm::<FE>(depth as usize, seed);
        self.ot.send(channel, &keys, rng)?;
        /******************************/
        //Sending this to the other party is completely insecure.
        for i in 0..n {
            channel.write_fe(v[i])?;
        }
        channel.flush()?;
        /*****************************/
        // compute d and sends out
        let mut d = gamma.clone();
        d -= v.iter().map(|&u| u).sum();
        channel.write_fe::<FE>(d)?;
        channel.flush()?;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let y_star = self.svole.receive(channel, r, rng)?;
        // Receives `chi`s from the Sender
        let mut chi: Vec<FE> = vec![FE::zero(); n];
        for i in 0..n {
            chi[i] = channel.read_fe::<FE>()?;
        }
        let mut x_star: Vec<FE::PrimeField> = vec![FE::PrimeField::zero(); r];
        for i in 0..r {
            x_star[i] = channel.read_fe()?;
        }
        let x_delta: Vec<FE> = x_star
            .iter()
            .map(|&x| to_fpr::<FE>(x) * self.delta)
            .collect();
        let y: Vec<FE> = y_star
            .iter()
            .cloned()
            .zip(x_delta.iter().cloned())
            .map(|(y, xd)| y - xd)
            .collect();
        // sets Y
        let y_ = dot_prod(&y, &self.pows);
        let mut vb = dot_prod(&chi, &v);
        vb -= y_;
        let mut eq_receiver = EQ::init()?;
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
