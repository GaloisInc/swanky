// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the EQ protocol based on the functionality presented in Figure 10
//! and the description below in the Weng et als work (cf.
//! <https://eprint.iacr.org/2020/925>, page no. 29).

use crate::{
    errors::Error,
    svole::svole_ext::{EqReceiver, EqSender},
};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use scuttlebutt::{
    commitment::{Commitment, ShaCommitment},
    field::FiniteField,
    AbstractChannel,
};
use std::marker::PhantomData;

/// Eq Sender.
#[derive(Clone)]
pub struct Sender<FE: FiniteField> {
    _fe: PhantomData<FE>,
}

impl<FE: FiniteField> EqSender for Sender<FE> {
    type Msg = FE;
    fn init() -> Result<Self, Error> {
        Ok(Self {
            _fe: PhantomData::<FE>,
        })
    }
    fn send<C: AbstractChannel>(&mut self, channel: &mut C, input: &FE) -> Result<bool, Error> {
        let va = *input;
        channel.write_fe(va)?;
        channel.flush()?;
        let mut comm_vb = [0u8; 32];
        channel.read_bytes(&mut comm_vb)?;
        let mut seed = [0u8; 32];
        channel.read_bytes(&mut seed)?;
        let vb = channel.read_fe::<FE>()?;
        let mut commit = ShaCommitment::new(seed);
        commit.input(&vb.to_bytes());
        let res = commit.finish();
        if res == comm_vb {
            Ok(va == vb)
        } else {
            Err(Error::Other(
                "Failed Opening commitments in EQ protocol.".to_string(),
            ))
        }
    }
}

/// Eq Receiver.
#[derive(Clone)]
pub struct Receiver<FE: FiniteField> {
    _fe: PhantomData<FE>,
}

impl<FE: FiniteField> EqReceiver for Receiver<FE> {
    type Msg = FE;
    fn init() -> Result<Self, Error> {
        Ok(Self {
            _fe: PhantomData::<FE>,
        })
    }
    fn receive<C: AbstractChannel, RNG: CryptoRng + RngCore>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        input: &FE,
    ) -> Result<bool, Error> {
        let vb = *input;
        let va = channel.read_fe::<FE>()?;
        let seed = rng.gen::<[u8; 32]>();
        let mut commit = ShaCommitment::new(seed);
        commit.input(&vb.to_bytes());
        let result = commit.finish();
        channel.write_bytes(&result)?;
        channel.write_bytes(&seed)?;
        channel.write_fe(vb)?;
        channel.flush()?;
        Ok(va == vb)
    }
}

#[cfg(test)]
mod tests {
    use crate::svole::svole_ext::{
        eq::{Receiver, Sender},
        EqReceiver,
        EqSender,
    };
    use scuttlebutt::{
        field::{FiniteField as FF, Fp, Gf128, F2},
        AesRng,
        Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_eq_<FE: FF + Send, Eqsender: EqSender<Msg = FE>, Eqreceiver: EqReceiver<Msg = FE>>() {
        let mut rng = AesRng::new();
        let input = FE::random(&mut rng);
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut eq_sender = Eqsender::init().unwrap();
            eq_sender.send(&mut channel, &input).unwrap()
        });
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut eq_receiver = Eqreceiver::init().unwrap();
        let v = eq_receiver.receive(&mut channel, &mut rng, &input).unwrap();
        let w = handle.join().unwrap();
        assert_eq!(w, true);
        assert_eq!(w, v);
    }

    #[test]
    fn test_eq() {
        test_eq_::<Fp, Sender<Fp>, Receiver<Fp>>();
        test_eq_::<F2, Sender<F2>, Receiver<F2>>();
        test_eq_::<Gf128, Sender<Gf128>, Receiver<Gf128>>();
    }
}
