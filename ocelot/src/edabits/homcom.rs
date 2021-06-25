// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This is the implementation of field conversion

use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::{field::FiniteField, AbstractChannel};
use std::marker::PhantomData;

// F_com protocol
pub struct FComSender<FE: FiniteField> {
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

    pub fn f_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(FE, FE), Error> {
        let x = FE::random(rng);

        channel.write_fe::<FE>(x)?;
        channel.flush()?;
        let mac = channel.read_fe::<FE>()?;
        Ok((x, mac))
    }

    pub fn f_input<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: FE,
    ) -> Result<FE, Error> {
        let (r, rmac) = self.f_random(channel, rng)?;

        let y = x - r;
        channel.write_fe::<FE>(y)?;
        channel.flush()?;

        Ok(rmac)
    }

    pub fn f_affine_add_cst(&self, cst: FE, x: FE, x_mac: FE) -> (FE, FE) {
        return (cst + x, x_mac);
    }

    pub fn f_affine_mult_cst(&self, cst: FE, x: FE, x_mac: FE) -> (FE, FE) {
        return (cst * x, cst * x_mac);
    }

    pub fn f_check_zero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x_mac: FE,
    ) -> Result<(), Error> {
        channel.write_fe::<FE>(x_mac)?;
        channel.flush()?;
        Ok(())
    }

    pub fn f_open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x: FE,
        x_mac: FE,
    ) -> Result<(), Error> {
        channel.write_fe::<FE>(x)?;
        channel.flush()?;

        return self.f_check_zero(channel, x_mac);
    }

    // TODO: dummy MultiplyCheck
    pub fn f_check_multiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        x: FE,
        x_mac: FE,
        y: FE,
        y_mac: FE,
        z: FE,
        z_mac: FE,
    ) -> Result<(), Error> {
        let _ = self.f_open(channel, x, x_mac)?;
        let _ = self.f_open(channel, y, y_mac)?;
        let _ = self.f_open(channel, z, z_mac)?;
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct FComReceiver<FE: FiniteField> {
    delta: FE,
}

impl<FE: FiniteField> FComReceiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        channel.write_bool(true)?;
        channel.flush()?;
        let delta = FE::random(rng);
        Ok(Self { delta: delta })
    }

    pub fn get_delta(self) -> FE {
        self.delta
    }

    pub fn f_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
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

    pub fn f_input<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<FE, Error> {
        let r_mac = self.f_random(channel, rng)?;
        let y = channel.read_fe::<FE>()?;

        let v_mac = r_mac - self.delta * y;
        Ok(v_mac)
    }

    pub fn f_affine_add_cst(&self, cst: FE, x_mac: FE) -> FE {
        return x_mac - self.delta * cst;
    }

    pub fn f_affine_mult_cst(&self, cst: FE, x_mac: FE) -> FE {
        return cst * x_mac;
    }

    pub fn f_check_zero<C: AbstractChannel>(self, channel: &mut C, key: FE) -> Result<bool, Error> {
        let m = channel.read_fe::<FE>()?;
        if key == m {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn f_open<C: AbstractChannel>(&mut self, channel: &mut C, key: FE) -> Result<FE, Error> {
        let x = channel.read_fe::<FE>()?;
        let b = self.f_check_zero(channel, key + self.delta * x)?;
        if b {
            Ok(x)
        } else {
            Err(Error::Other("open fails at checkzero".to_string()))
        }
    }

    // TODO: dummy MultiplyCheck
    pub fn f_check_multiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        x_mac: FE,
        y_mac: FE,
        z_mac: FE,
    ) -> Result<(), Error> {
        let x = self.f_open(channel, x_mac)?;
        let y = self.f_open(channel, y_mac)?;
        let z = self.f_open(channel, z_mac)?;
        if z == x * y {
            Ok(())
        } else {
            Err(Error::Other("checkMultiply fails".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{FComReceiver, FComSender};
    use scuttlebutt::{
        field::{F61p, FiniteField},
        AbstractChannel, AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_fcom_random<FE: FiniteField>() -> Vec<(FE, FE)> {
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
                let x = fcom.f_random(&mut channel, &mut rng).unwrap();
                v.push(x);
            }
            let mut r = Vec::new();
            for i in 0..count {
                let b = fcom.f_open(&mut channel, v[i].0, v[i].1).unwrap();
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
            let x = fcom.f_random(&mut channel, &mut rng).unwrap();

            v.push(x);
        }
        let mut r = Vec::new();
        for i in 0..count {
            let b = fcom.f_open(&mut channel, v[i]).unwrap();
            r.push(b);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(r[i], resprover[i].0);
        }
        resprover
    }

    fn test_fcom_affine() -> () {
        let count = 200;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComSender::<F61p>::init(&mut channel).unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let (x, x_mac) = fcom.f_random(&mut channel, &mut rng).unwrap();
                let cst = F61p::random(&mut rng);
                channel.write_fe::<F61p>(cst).unwrap();
                channel.flush().unwrap();
                let (m, m_mac) = fcom.f_affine_mult_cst(cst, x, x_mac);
                v.push((x, cst, m, m_mac));
                let (a, a_mac) = fcom.f_affine_add_cst(cst, x, x_mac);
                v.push((x, cst, a, a_mac));
            }

            let mut r = Vec::new();
            for i in 0..count {
                let b = fcom.f_open(&mut channel, v[i].2, v[i].3).unwrap();
                r.push(b);
            }
            v
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComReceiver::<F61p>::init(&mut channel, &mut rng).unwrap();
        let mut v = Vec::new();
        for _ in 0..count {
            let x_mac = fcom.f_random(&mut channel, &mut rng).unwrap();
            let cst = channel.read_fe().unwrap();
            let m_mac = fcom.f_affine_mult_cst(cst, x_mac);
            v.push((x_mac, cst, m_mac));
            let a_mac = fcom.f_affine_add_cst(cst, x_mac);
            v.push((x_mac, cst, a_mac));
        }

        let mut r = Vec::new();
        for i in 0..count {
            let b = fcom.f_open(&mut channel, v[i].2).unwrap();
            r.push(b);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(r[i], resprover[i].2);
        }
        ()
    }

    #[test]
    fn test_fcom_random_f61p() {
        let _t = test_fcom_random::<F61p>();
    }

    #[test]
    fn test_fcom_affine_f61p() {
        let _t = test_fcom_affine();
    }
}
