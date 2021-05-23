// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This is the implementation of field conversion

use crate::errors::Error;
use rand::{
    distributions::{Distribution, Uniform},
    CryptoRng, Rng, SeedableRng,
};
use scuttlebutt::{
    field::{FiniteField, F2},
    AbstractChannel,
};
use std::marker::PhantomData;

// F_com protocol
struct FComSender<FE: FiniteField> {
    phantom: PhantomData<FE>,
}

impl<FE: FiniteField> FComSender<FE> {
    pub fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let b = channel.read_bool()?;
        if b {
            Ok(Self {
                phantom: PhantomData,
            })
        } else {
            Err(Error::Other("Error in init".to_string()))
        }
    }

    pub fn comrandom<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(FE, FE), Error> {
        let x = FE::random(rng);

        channel.write_fe::<FE>(x);
        channel.flush()?;
        let mac = channel.read_fe::<FE>()?;
        Ok((x, mac))
    }

    pub fn cominput<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        v: FE,
    ) -> Result<(FE, FE), Error> {
        let (r, rmac) = self.comrandom(channel, rng)?;

        let y = v - r;
        channel.write_fe::<FE>(y);
        channel.flush()?;

        Ok((r, rmac))
    }

    pub fn comcheckzero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        comx: FE,
    ) -> Result<(), Error> {
        channel.write_fe::<FE>(comx);
        channel.flush()?;
        Ok(())
    }

    pub fn comopen<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x: FE,
        comx: FE,
    ) -> Result<(), Error> {
        channel.write_fe::<FE>(x);
        channel.flush()?;

        return self.comcheckzero(channel, comx);
    }
}

struct FComReceiver<FE: FiniteField> {
    delta: FE,
}

impl<FE: FiniteField> FComReceiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        channel.write_bool(true);
        channel.flush()?;
        let delta = FE::random(rng);
        Ok(Self { delta: delta })
    }

    pub fn get_delta(self) -> FE {
        self.delta
    }

    pub fn comrandom<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<FE, Error> {
        let x = channel.read_fe::<FE>()?;
        let key = FE::random(rng);
        channel.write_fe(self.delta * x + key)?;
        channel.flush()?;
        Ok(key)
    }

    pub fn cominput<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<FE, Error> {
        let rmac = self.comrandom(channel, rng)?;
        let y = channel.read_fe::<FE>()?;

        let vmac = rmac - self.delta * y;
        Ok(vmac)
    }

    pub fn comcheckzero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        key: FE,
    ) -> Result<bool, Error> {
        let m = channel.read_fe::<FE>()?;
        if key == m {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn comopen<C: AbstractChannel>(&mut self, channel: &mut C, key: FE) -> Result<bool, Error> {
        let x = channel.read_fe::<FE>()?;

        return self.comcheckzero(channel, key + self.delta * x);
    }
}

// Edabits

struct EdaBits<FE: FiniteField> {
    bindec: Vec<F2>,
    value: FE,
    length: usize,
}

struct SenderConv<FE: FiniteField> {
    fcomF2: FComSender<F2>,
    fcom: FComSender<FE>,
}

// Protocol for checking conversion

impl<FE: FiniteField> SenderConv<FE> {
    pub fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let a = FComSender::init(channel)?;
        let b = FComSender::init(channel)?;
        Ok(Self { fcomF2: a, fcom: b })
    }

    pub fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        edabits: EdaBits<FE>,
    ) -> Result<Self, Error> {
        // step 0: not in the paper
        // let's commit the edabits

        let mut c2_com = Vec::with_capacity(edabits.length);
        for c in edabits.bindec {
            let x = self.fcomF2.cominput(channel, rng, c)?;
            c2_com.push(x);
        }
        let cm_com = self.fcom.cominput(channel, rng, edabits.value)?;

        // step 6
        // let pick only one bucket for now
        // and not even random just the same as the input
        Err(Error::Other("Not implemented yet".to_string()))
    }
}

struct ReceiverConv<FE: FiniteField> {
    fcomF2: FComReceiver<F2>,
    fcom: FComReceiver<FE>,
}

const NB_BITS: usize = 5;

impl<FE: FiniteField> ReceiverConv<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let a = FComReceiver::init(channel, rng)?;
        let b = FComReceiver::init(channel, rng)?;
        Ok(Self { fcomF2: a, fcom: b })
    }

    pub fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        // step 0: not in the paper
        // let's commit the edabits

        let mut c2_com = Vec::with_capacity(NB_BITS);
        for _ in 1..NB_BITS {
            let x = self.fcomF2.cominput(channel, rng)?;
            c2_com.push(x);
        }
        let cm_com = self.fcom.cominput(channel, rng)?;

        // step 6
        // let pick only one bucket for now
        // and not even random just the same as the input
        Err(Error::Other("Not implemented yet".to_string()))
    }
}

#[cfg(test)]
mod tests {

    use super::{FComReceiver, FComSender};
    use scuttlebutt::{
        field::{F61p, FiniteField, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    // TODO: For now this test is not testing anything
    fn test_fcom<FE: FiniteField>() -> Vec<(FE, FE)> {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComSender::<FE>::init(&mut channel).unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let x = fcom.comrandom(&mut channel, &mut rng).unwrap();
                v.push(x);
            }
            let mut r = Vec::new();
            for i in 0..count {
                let b = fcom.comopen(&mut channel, v[i].0, v[i].1).unwrap();
                r.push(b);
            }
            v
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComReceiver::<FE>::init(&mut channel, &mut rng).unwrap();
        let mut v = Vec::new();
        for _ in 0..count {
            let x = fcom.comrandom(&mut channel, &mut rng).unwrap();

            v.push(x);
        }
        let mut r = Vec::new();
        for i in 0..count {
            println!("HERE");
            let b = fcom.comopen(&mut channel, v[i]).unwrap();
            r.push(b);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(r[i], true);
        }
        resprover
    }

    #[test]
    fn test_fcom_f61p() {
        let t = test_fcom::<F61p>();

        for (x, _) in t.iter() {
            println!("{}", x);
        }
    }
}
