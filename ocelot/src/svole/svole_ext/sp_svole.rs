// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Single-point Subfield Vector Oblivious Linear-function Evaluation (SpsVole)
//!
//! This module provides implementations of SpsVole Traits.

use crate::{
    errors::Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
    svole::{
        CopeeReceiver, CopeeSender, Params, SVoleReceiver, SVoleSender,
        svole_ext::{SpsVoleSender, SpsVoleReceiver},
    },
};
use rand::Rng;
use digest::generic_array::typenum::Unsigned;
use generic_array::GenericArray;
use rand::SeedableRng;
use scuttlebutt::{field::FiniteField as FF, AbstractChannel, AesRng, Block, Malicious};
use std::marker::PhantomData;

/// A SpsVole Sender.
#[derive(Clone)]
pub struct Sender<OT: OtSender + Malicious, CP: CopeeSender, FE: FF, SV:SVoleSender> {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    svole: SV,
}

/// A SpsVole Receiver.
#[derive(Clone)]
pub struct Receiver<OT: OtReceiver + Malicious, CP: CopeeReceiver, FE: FF, SV:SVoleReceiver> {
    _ot: PhantomData<OT>,
    _cp: PhantomData<CP>,
    _fe: PhantomData<FE>,
    _sv: PhantomData<SV>,
    delta: FE,
    svole: SV,
}

/// Implement SpsVole for Sender type.
impl<OT: OtSender<Msg = Block> + Malicious, 
    FE: FF, CP: CopeeSender<Msg = FE>, 
    SV: SVoleSender<Msg = FE>> SpsVoleSender
    for Sender<OT, CP, FE, SV>
{
    type Msg = FE;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let vsender = SV::init(channel).unwrap();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            svole: vsender,
        })
    }

    fn send<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<(Vec<FE>, Vec<FE>), Error> {
        let (a, c) = self.svole.send(channel).unwrap();
        let g = FE::generator();
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut two = FE::one();
        two.add_assign(FE::one());
        let beta = two.pow(rng.gen_range(0, FE::MULTIPLICATIVE_GROUP_ORDER));
        // Sends out a'=\beta-a
        let a_prime = beta.clone();
        a_prime.sub_assign(a[0]);
        channel.write_bytes(a_prime.to_bytes().as_slice())?;
        // Samples \alpha in [0,n)
        let alpha = rng.gen_range(0, Params::N);
        let mut u = vec![FE::zero(); Params::N];
        u[alpha] = beta;
        // Sampling `ui`s i for in `[n]`.
        let u: Vec<FE> = (0..Params::N).map(|_| FE::random(&mut rng)).collect();
        assert_eq!(u.len(), Params::N);
        let u_ = u.clone();
        // Sampling `ah`s h in `[r]`.
        let a: Vec<FE> = (0..Params::R).map(|_| FE::random(&mut rng)).collect();
        //Calling COPEe extend on the vector `u`.
        let w = self.copee.send(channel, u.clone())?;
        let w_ = w.clone();
        // Calling COPEe on the vector `a`
        let mut c = self.copee.send(channel, a.clone())?;
        let nbytes = FE::ByteReprLen::to_usize();
        // Sender receives `chi`s from the receiver
        let mut chi: Vec<FE> = (0..Params::N)
            .map(|_| {
                let mut data = vec![0u8; nbytes];
                channel.read_bytes(&mut data).unwrap();
                FE::from_bytes(GenericArray::from_slice(&data)).unwrap()
            })
            .collect();
        // Sender computes x
        let x_sum = (0..Params::N).fold(FE::zero(), |sum, i| {
            let mut chi_ = chi[i].clone();
            chi_.mul_assign(u[i]);
            chi_.add_assign(sum);
            chi_
        });
        let x = (0..Params::R).fold(x_sum, |mut sum, h| {
            let mut g_h = g.pow(h as u128);
            g_h.mul_assign(a[h]);
            sum.add_assign(g_h);
            sum
        });

        // Sender computes z
        let z_sum = (0..Params::N).fold(FE::zero(), |mut sum, i| {
            chi[i].mul_assign(w[i]);
            sum.add_assign(chi[i]);
            sum
        });
        let z = (0..Params::R).fold(z_sum, |mut sum, h| {
            let g_h = g.pow(h as u128);
            c[h].mul_assign(g_h);
            sum.add_assign(c[h]);
            sum
        });

        // Send out (x, z) to the Receiver.
        channel.write_bytes(x.to_bytes().as_slice())?;
        channel.write_bytes(z.to_bytes().as_slice())?;
        channel.flush()?;
        Ok((u_, w_))
    }
}

/// Implement SVoleReceiver for Receiver type.
impl<OT: OtReceiver<Msg = Block> + Malicious, FE: FF, CP: CopeeReceiver<Msg = FE>, SV: SVoleReceiver<Msg = FE>> SVoleReceiver
    for Receiver<OT, CP, FE, SV>
{
    type Msg = FE;
    fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let sv = SV::init(channel).unwrap();
        let delta = sv.get_delta();
        Ok(Self {
            _ot: PhantomData::<OT>,
            _cp: PhantomData::<CP>,
            _fe: PhantomData::<FE>,
            _sv: PhantomData::<SV>,
            svole: sv,
            delta,
        })
    }

    fn get_delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel>(&mut self, channel: &mut C) -> Result<Option<Vec<FE>>, Error> {
        let Some(b) = self.svole.receive(channel).unwrap();
        // Sample `s` from `\{0,1\}`
        let seed = rand::random::<Block>();
        let v: Vec<FE> = self.copee.receive(channel, Params::N).unwrap();
        let v_ = v.clone();
        let mut b: Vec<FE> = self.copee.receive(channel, Params::N).unwrap();
        let nbytes = FE::ByteReprLen::to_usize();
        // Sampling `chi`s.
        let seed = rand::random::<Block>();
        let mut rng = AesRng::from_seed(seed);
        let mut chi: Vec<FE> = (0..Params::N).map(|_| FE::random(&mut rng)).collect();
        // Send `chi`s to the Sender.
        for i in 0..Params::N {
            channel.write_bytes(chi[i].to_bytes().as_slice()).unwrap();
        }
        channel.flush()?;
        // Receive (x, z) from the Sender.
        let mut data_x = vec![0u8; nbytes];
        channel.read_bytes(&mut data_x).unwrap();
        let x = FE::from_bytes(GenericArray::from_slice(&data_x)).unwrap();
        let mut data_z = vec![0u8; nbytes];
        channel.read_bytes(&mut data_z).unwrap();
        let z = FE::from_bytes(GenericArray::from_slice(&data_z)).unwrap();
        // compute y
        let y_sum = (0..Params::N).fold(FE::zero(), |sum, i| {
            chi[i].mul_assign(v[i]);
            chi[i].add_assign(sum);
            chi[i]
        });
        let g = FE::generator();
        let y = (0..Params::R).fold(y_sum, |sum, h| {
            let powr = g.pow(h as u128);
            b[h].mul_assign(powr);
            b[h].add_assign(sum);
            b[h]
        });
        let mut delta_ = self.delta.clone();
        delta_.mul_assign(x);
        delta_.add_assign(y);
        if z == delta_ {
            Ok(Some(v_))
        } else {
            Ok(None)
        }
    }
}
