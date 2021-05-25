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

    pub fn cRandom<C: AbstractChannel, RNG: CryptoRng + Rng>(
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

    pub fn cInput<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: FE,
    ) -> Result<FE, Error> {
        let (r, rmac) = self.cRandom(channel, rng)?;

        let y = x - r;
        channel.write_fe::<FE>(y);
        channel.flush()?;

        Ok(rmac)
    }

    pub fn cCheckZero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x_com: FE,
    ) -> Result<(), Error> {
        channel.write_fe::<FE>(x_com);
        channel.flush()?;
        Ok(())
    }

    pub fn cOpen<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x: FE,
        x_com: FE,
    ) -> Result<(), Error> {
        channel.write_fe::<FE>(x);
        channel.flush()?;

        return self.cCheckZero(channel, x_com);
    }

    pub fn cCheckMultiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: FE,
        x_com: FE,
        y: FE,
        y_com: FE,
        z: FE,
        z_com: FE,
    ) -> Result<(), Error> {
        Err(Error::Other("NotYetImplemented".to_string()))
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

    pub fn cRandom<C: AbstractChannel, RNG: CryptoRng + Rng>(
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

    pub fn cInput<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<FE, Error> {
        let r_com = self.cRandom(channel, rng)?;
        let y = channel.read_fe::<FE>()?;

        let v_com = r_com - self.delta * y;
        Ok(v_com)
    }

    pub fn cCheckZero<C: AbstractChannel>(
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

    pub fn cOpen<C: AbstractChannel>(&mut self, channel: &mut C, key: FE) -> Result<FE, Error> {
        let x = channel.read_fe::<FE>()?;
        let b = self.cCheckZero(channel, key + self.delta * x)?;
        if b {
            Ok(x)
        } else {
            Err(Error::Other("open fails at checkzero".to_string()))
        }
    }

    pub fn cCheckMultiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x_com: FE,
        y_com: FE,
        z_com: FE,
    ) -> Result<(), Error> {
        Err(Error::Other("NotYetImplemented".to_string()))
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

fn bitADDcarry(v: Vec<(F2, F2)>) -> (Vec<F2>, F2) {
    let mut c0 = F2::ZERO;
    let l = v.len();
    let mut res = Vec::with_capacity(l);
    for (x, y) in v.iter() {
        let c = c0 + (x + c0) * (y + c0);
        let z = x + y + c0;
        res.push(z);
        c0 = c;
    }
    (res, c0)
}

// Protocol for checking conversion

impl<FE: FiniteField> SenderConv<FE> {
    pub fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let a = FComSender::init(channel)?;
        let b = FComSender::init(channel)?;
        Ok(Self { fcomF2: a, fcom: b })
    }

    pub fn convertBit2A<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        r_f2: F2,
        r_com_f2: F2,
        r_m: FE,
        x_f2: F2,
        x_com_f2: F2,
    ) -> Result<(FE, FE), Error> {
        let x = if x_f2 == F2::ONE { FE::ONE } else { FE::ZERO };
        self.fcomF2
            .cOpen(channel, r_f2 + x_f2, r_com_f2 + x_com_f2)?;
        let c = r_f2 + x_f2;
        let x_com = r_m + if c == F2::ONE { -(r_m + r_m) } else { FE::ZERO };
        Ok((x, x_com))
    }

    fn bitADDcarry<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: Vec<(F2, F2)>,
        y: Vec<(F2, F2)>,
    ) -> Result<(Vec<(F2, F2)>, (F2, F2)), Error> {
        let xl = x.len();
        let yl = y.len();
        if xl != yl {
            return Err(Error::Other(
                "incompatible input vectors in bitADDcarry".to_string(),
            ));
        }

        let mut res = Vec::with_capacity(xl);

        let mut ci = F2::ZERO;
        let mut ci_com = self.fcomF2.cInput(channel, rng, ci)?;
        for i in 0..xl {
            let (xi, xi_com) = x[i];
            let (yi, yi_com) = y[i];

            let and1 = xi + ci;
            let and1_com = xi_com + ci_com;

            let and2 = yi + ci;
            let and2_com = yi_com + ci_com;

            let and_res = and1 * and2;
            let and_res_com = self.fcomF2.cInput(channel, rng, and_res)?;
            self.fcomF2.cCheckMultiply(
                channel,
                rng,
                and1,
                and1_com,
                and2,
                and2_com,
                and_res,
                and_res_com,
            );

            let c = ci + and_res;
            let c_com = ci_com + and_res_com;

            let z = xi + yi + ci;
            let z_com = xi_com + yi_com + ci_com;

            res.push((z, z_com));

            ci = c;
            ci_com = c_com;
        }
        Ok((res, (ci, ci_com)))
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
            let x = self.fcomF2.cInput(channel, rng, c)?;
            c2_com.push((c, x));
        }
        let c_m_com = self.fcom.cInput(channel, rng, edabits.value)?;

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

    pub fn convertBit2A<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        r_com_f2: F2,
        r_m: FE,
        x_com_f2: F2,
    ) -> Result<FE, Error> {
        let c = self.fcomF2.cOpen(channel, r_com_f2 + x_com_f2)?;
        let x_m_com = (if c == F2::ONE {
            -self.fcom.delta
        } else {
            FE::ZERO
        }) + r_m
            + if c == F2::ONE { -(r_m + r_m) } else { FE::ZERO };
        Ok(x_m_com)
    }

    fn bitADDcarry<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: Vec<F2>,
        y: Vec<F2>,
    ) -> Result<(Vec<F2>, F2), Error> {
        let xl = x.len();
        let yl = y.len();
        if xl != yl {
            return Err(Error::Other(
                "incompatible input vectors in bitADDcarry".to_string(),
            ));
        }

        let mut res = Vec::with_capacity(xl);

        let mut ci_com = self.fcomF2.cInput(channel, rng)?;
        for i in 0..xl {
            let xi_com = x[i];
            let yi_com = y[i];

            let and1_com = xi_com + ci_com;
            let and2_com = yi_com + ci_com;

            let and_res_com = self.fcomF2.cInput(channel, rng)?;

            self.fcomF2
                .cCheckMultiply(channel, rng, and1_com, and2_com, and_res_com);

            let c_com = ci_com + and_res_com;

            let z_com = xi_com + yi_com + ci_com;

            res.push(z_com);

            ci_com = c_com;
        }
        Ok((res, ci_com))
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
            let x = self.fcomF2.cInput(channel, rng)?;
            c2_com.push(x);
        }
        let cm_com = self.fcom.cInput(channel, rng)?;

        // step 6
        // let pick only one bucket for now
        // and not even random just the same as the input
        Err(Error::Other("Not implemented yet".to_string()))
    }
}

#[cfg(test)]
mod tests {

    use super::{FComReceiver, FComSender, ReceiverConv, SenderConv};
    use scuttlebutt::{
        field::{F61p, FiniteField, F2},
        AesRng, Channel,
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
                let x = fcom.cRandom(&mut channel, &mut rng).unwrap();
                v.push(x);
            }
            let mut r = Vec::new();
            for i in 0..count {
                let b = fcom.cOpen(&mut channel, v[i].0, v[i].1).unwrap();
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
            let x = fcom.cRandom(&mut channel, &mut rng).unwrap();

            v.push(x);
        }
        let mut r = Vec::new();
        for i in 0..count {
            let b = fcom.cOpen(&mut channel, v[i]).unwrap();
            r.push(b);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(r[i], resprover[i].0);
        }
        resprover
    }

    fn test_convertBit2A<FE: FiniteField>() -> () {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = SenderConv::<FE>::init(&mut channel).unwrap();

            let mut res = Vec::new();
            for i in 0..count {
                let (rb, rb_com) = fconv.fcomF2.cRandom(&mut channel, &mut rng).unwrap();
                let rm = if rb == F2::ONE { FE::ONE } else { FE::ZERO };
                let rm_com = fconv.fcom.cInput(&mut channel, &mut rng, rm).unwrap();
                let (x_f2, x_f2_com) = fconv.fcomF2.cRandom(&mut channel, &mut rng).unwrap();

                let (x_m, x_m_com) = fconv
                    .convertBit2A(&mut channel, &mut rng, rb, rb_com, rm_com, x_f2, x_f2_com)
                    .unwrap();

                let _ = fconv.fcom.cOpen(&mut channel, x_m, x_m_com).unwrap();
                // println!(
                //     "{}",
                //     if (x_m == FE::ONE) {
                //         "ONE".to_string()
                //     } else {
                //         if (x_m == FE::ZERO) {
                //             "ZERO".to_string()
                //         } else {
                //             "DFGDFGDG".to_string()
                //         }
                //     }
                // );
                assert_eq!(
                    if x_f2 == F2::ZERO {
                        x_m == FE::ZERO
                    } else {
                        x_m == FE::ONE
                    },
                    true
                );
                res.push((x_f2, x_m));
            }
            res
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut res = Vec::new();
        for i in 0..count {
            let rb_com = fconv.fcomF2.cRandom(&mut channel, &mut rng).unwrap();
            let r_m_com = fconv.fcom.cInput(&mut channel, &mut rng).unwrap();
            let x_f2_com = fconv.fcomF2.cRandom(&mut channel, &mut rng).unwrap();

            let x_m_com = fconv
                .convertBit2A(&mut channel, &mut rng, rb_com, r_m_com, x_f2_com)
                .unwrap();

            let x_m = fconv.fcom.cOpen(&mut channel, x_m_com).unwrap();
            res.push(x_m);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(resprover[i].1, res[i]);
        }
    }

    #[test]
    fn test_fcom_random_f61p() {
        let t = test_fcom_random::<F61p>();

        // for (x, _) in t.iter() {
        //     println!("{}", x);
        // }
    }

    #[test]
    fn test_fconv_convertBit2A_f61p() {
        let t = test_convertBit2A::<F61p>();
    }
}
