// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This is the implementation of field conversion

use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::{
    field::{FiniteField, F2},
    AbstractChannel,
};

use super::homcom::{FComReceiver, FComSender};

/// Edabits struct
#[derive(Clone)]
struct EdaBits<FE: FiniteField> {
    bits: Vec<F2>,
    value: FE,
}

/// Conversion protocol sender
struct SenderConv<FE: FiniteField> {
    fcom_f2: FComSender<F2>,
    fcom: FComSender<FE>,
}

const NB_BITS: usize = 6;

fn convert_f2_to_field<FE: FiniteField>(v: &Vec<F2>) -> FE {
    let mut res = FE::ZERO;

    for i in 0..v.len() {
        let b = v[v.len() - i - 1];
        res += res; // double
        if b == F2::ONE {
            res += FE::ONE;
        }
    }
    res
}

fn power_two<FE: FiniteField>(m: usize) -> FE {
    let mut res = FE::ONE;

    for _ in 0..m {
        res = res + res;
    }

    res
}

// Protocol for checking conversion

impl<FE: FiniteField> SenderConv<FE> {
    pub fn init<C: AbstractChannel>(channel: &mut C) -> Result<Self, Error> {
        let a = FComSender::init(channel)?;
        let b = FComSender::init(channel)?;
        Ok(Self {
            fcom_f2: a,
            fcom: b,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        r: F2,
        r_mac: F2,
        r_m_mac: FE,
        x: F2,
        x_mac: F2,
    ) -> Result<(FE, FE), Error> {
        let x_m = if x == F2::ONE { FE::ONE } else { FE::ZERO };
        self.fcom_f2.f_open(channel, r + x, r_mac + x_mac)?;
        let c = r + x;
        let x_m_mac = r_m_mac
            + if c == F2::ONE {
                -(r_m_mac + r_m_mac)
            } else {
                FE::ZERO
            };
        Ok((x_m, x_m_mac))
    }

    fn bit_add_carry<C: AbstractChannel, RNG: CryptoRng + Rng>(
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
                "incompatible input vectors in bit_add_carry".to_string(),
            ));
        }

        let mut res = Vec::with_capacity(xl);

        let mut ci = F2::ZERO;
        let mut ci_mac = self.fcom_f2.f_input(channel, rng, ci)?;
        for i in 0..xl {
            let (xi, xi_mac) = x[i];
            let (yi, yi_mac) = y[i];

            let and1 = xi + ci;
            let and1_mac = xi_mac + ci_mac;

            let and2 = yi + ci;
            let and2_mac = yi_mac + ci_mac;

            let and_res = and1 * and2;
            let and_res_mac = self.fcom_f2.f_input(channel, rng, and_res)?;
            self.fcom_f2.f_check_multiply(
                channel,
                rng,
                and1,
                and1_mac,
                and2,
                and2_mac,
                and_res,
                and_res_mac,
            )?;

            let c = ci + and_res;
            let c_mac = ci_mac + and_res_mac;

            let z = xi + yi + ci;
            let z_mac = xi_mac + yi_mac + ci_mac;

            res.push((z, z_mac));

            ci = c;
            ci_mac = c_mac;
        }
        Ok((res, (ci, ci_mac)))
    }

    fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        edabits: EdaBits<FE>,
    ) -> Result<(), Error> {
        // step 0: not in the paper
        // commit the edabits
        let mut c = Vec::new();
        for ci in edabits.bits {
            let ci_mac = self.fcom_f2.f_input(channel, rng, ci)?;
            c.push((ci, ci_mac));
        }
        let c_m = edabits.value;
        let c_m_mac = self.fcom.f_input(channel, rng, c_m)?;

        // step 1)a): commit a random edabit
        let mut r = Vec::with_capacity(NB_BITS);
        for _ in 0..NB_BITS {
            let (x, x_mac) = self.fcom_f2.f_random(channel, rng)?;
            r.push((x, x_mac));
        }

        let mut iv: Vec<F2> = Vec::with_capacity(NB_BITS);
        for (x, _) in r.iter() {
            iv.push(*x)
        }
        let r_m: FE = convert_f2_to_field(&iv);
        let r_m_mac = self.fcom.f_input(channel, rng, r_m)?;

        // step 1)b): commit a random dabit
        let (b, b_mac) = self.fcom_f2.f_random(channel, rng)?;
        let b_m = if b == F2::ZERO { FE::ZERO } else { FE::ONE };
        let b_m_mac = self.fcom.f_input(channel, rng, b_m)?;

        // step 1)c): TODO: random multiplication triples
        // step 2): TODO: verify dabit

        // step 3)-5): TODO: generate permutations, apply them, cut-choose

        // step 6) TODO: currently only let pick only one bucket for now
        // 6)a)
        let c_plus_r_mac = c_m_mac + r_m_mac;

        // 6)b)
        let (e, e_carry) = self.bit_add_carry(channel, rng, c, r)?;

        // 6)c)
        let (_, e_m_mac) =
            self.convert_bit_2_field(channel, rng, b, b_mac, b_m_mac, e_carry.0, e_carry.1)?;

        // 6)d)
        let e1_mac = c_plus_r_mac - power_two::<FE>(NB_BITS) * e_m_mac;

        // 6)e)
        let mut ei = Vec::new();
        for i in 0..NB_BITS {
            let elm = self.fcom_f2.f_open(channel, e[i].0, e[i].1)?;
            ei.push(elm);
        }

        // Remark this is not necessary for the prover, bc cst addition dont show up in mac
        // let s = convert_f2_to_field(ei);
        let _ = self.fcom.f_check_zero(channel, e1_mac)?;

        Ok(())
    }
}

/// Conversion protocol receiver
struct ReceiverConv<FE: FiniteField> {
    fcom_f2: FComReceiver<F2>,
    fcom: FComReceiver<FE>,
}

impl<FE: FiniteField> ReceiverConv<FE> {
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let a = FComReceiver::init(channel, rng)?;
        let b = FComReceiver::init(channel, rng)?;
        Ok(Self {
            fcom_f2: a,
            fcom: b,
        })
    }

    fn convert_bit_2_field<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        r_mac: F2,
        r_m_mac: FE,
        x_mac: F2,
    ) -> Result<FE, Error> {
        let c = self.fcom_f2.f_open(channel, r_mac + x_mac)?;
        let x_m_mac = (if c == F2::ONE {
            -self.fcom.get_delta()
        } else {
            FE::ZERO
        }) + r_m_mac
            + if c == F2::ONE {
                -(r_m_mac + r_m_mac)
            } else {
                FE::ZERO
            };
        Ok(x_m_mac)
    }

    fn bit_add_carry<C: AbstractChannel, RNG: CryptoRng + Rng>(
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
                "incompatible input vectors in bit_add_carry".to_string(),
            ));
        }

        let mut res = Vec::with_capacity(xl);

        let mut ci_mac = self.fcom_f2.f_input(channel, rng)?;
        for i in 0..xl {
            let xi_mac = x[i];
            let yi_mac = y[i];

            let and1_mac = xi_mac + ci_mac;
            let and2_mac = yi_mac + ci_mac;

            let and_res_mac = self.fcom_f2.f_input(channel, rng)?;

            self.fcom_f2
                .f_check_multiply(channel, rng, and1_mac, and2_mac, and_res_mac)?;

            let c_mac = ci_mac + and_res_mac;

            let z_mac = xi_mac + yi_mac + ci_mac;

            res.push(z_mac);

            ci_mac = c_mac;
        }
        Ok((res, ci_mac))
    }

    fn conv<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        // step 0: not in the paper
        // commit the edabits
        let mut c_mac = Vec::new();
        for _ in 0..NB_BITS {
            let ci_mac = self.fcom_f2.f_input(channel, rng)?;
            c_mac.push(ci_mac);
        }

        let c_m_mac = self.fcom.f_input(channel, rng)?;

        // step 1)a): commit a random edabit
        let mut r_mac = Vec::with_capacity(NB_BITS);
        for _ in 0..NB_BITS {
            let x_mac = self.fcom_f2.f_random(channel, rng)?;
            r_mac.push(x_mac);
        }

        let r_m_mac = self.fcom.f_input(channel, rng)?;

        // step 1)b): commit a random dabit
        let b_mac = self.fcom_f2.f_random(channel, rng)?;
        let b_m_mac = self.fcom.f_input(channel, rng)?;

        // step 1)c): TODO: random multiplication triples
        // step 2): TODO: verify dabit

        // step 3)-5): TODO: generate permutations, apply them, cut-choose

        // step 6) TODO: currently only let pick only one bucket for now
        // 6)a)
        let c_plus_r_mac = c_m_mac + r_m_mac;

        // 6)b)
        let (e_mac, e_carry_mac) = self.bit_add_carry(channel, rng, c_mac, r_mac)?;

        // 6)c)
        let e_m_mac = self.convert_bit_2_field(channel, rng, b_mac, b_m_mac, e_carry_mac)?;

        // 6)d)
        let e1_mac = c_plus_r_mac - power_two::<FE>(NB_BITS) * e_m_mac;

        // 6)e)
        let mut ei = Vec::new();
        for i in 0..NB_BITS {
            let elm = self.fcom_f2.f_open(channel, e_mac[i])?;
            ei.push(elm);
        }

        let s = convert_f2_to_field(&ei);
        let b = self
            .fcom
            .f_check_zero(channel, e1_mac + self.fcom.get_delta() * s)?;

        if b {
            Ok(())
        } else {
            Err(Error::Other("conversion check failed".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{convert_f2_to_field, EdaBits, ReceiverConv, SenderConv, NB_BITS};
    use scuttlebutt::{
        field::{F61p, FiniteField, F2},
        AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_convert_bit_2_field<FE: FiniteField>() -> () {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = SenderConv::<FE>::init(&mut channel).unwrap();

            let mut res = Vec::new();
            for _ in 0..count {
                let (rb, rb_mac) = fconv.fcom_f2.f_random(&mut channel, &mut rng).unwrap();
                let rm = if rb == F2::ONE { FE::ONE } else { FE::ZERO };
                let rm_mac = fconv.fcom.f_input(&mut channel, &mut rng, rm).unwrap();
                let (x_f2, x_f2_mac) = fconv.fcom_f2.f_random(&mut channel, &mut rng).unwrap();

                let (x_m, x_m_mac) = fconv
                    .convert_bit_2_field(&mut channel, &mut rng, rb, rb_mac, rm_mac, x_f2, x_f2_mac)
                    .unwrap();

                let _ = fconv.fcom.f_open(&mut channel, x_m, x_m_mac).unwrap();
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
        for _ in 0..count {
            let rb_mac = fconv.fcom_f2.f_random(&mut channel, &mut rng).unwrap();
            let r_m_mac = fconv.fcom.f_input(&mut channel, &mut rng).unwrap();
            let x_f2_mac = fconv.fcom_f2.f_random(&mut channel, &mut rng).unwrap();

            let x_m_mac = fconv
                .convert_bit_2_field(&mut channel, &mut rng, rb_mac, r_m_mac, x_f2_mac)
                .unwrap();

            let x_m = fconv.fcom.f_open(&mut channel, x_m_mac).unwrap();
            res.push(x_m);
        }

        let resprover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(resprover[i].1, res[i]);
        }
    }

    fn test_bit_add_carry<FE: FiniteField>() -> () {
        let power = 6;
        let (sender, receiver) = UnixStream::pair().unwrap();

        // adding
        //   110101
        //   101110
        // --------
        //  1100011
        let x = vec![F2::ONE, F2::ZERO, F2::ONE, F2::ZERO, F2::ONE, F2::ONE];
        let y = vec![F2::ZERO, F2::ONE, F2::ONE, F2::ONE, F2::ZERO, F2::ONE];
        let expected = vec![F2::ONE, F2::ONE, F2::ZERO, F2::ZERO, F2::ZERO, F2::ONE];
        let carry = F2::ONE;

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = SenderConv::<FE>::init(&mut channel).unwrap();

            let mut x_mac = Vec::new();
            let mut y_mac = Vec::new();

            for i in 0..power {
                let xb_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng, x[i]).unwrap();
                x_mac.push(xb_mac);

                let yb_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng, y[i]).unwrap();
                y_mac.push(yb_mac);
            }

            let mut vx: Vec<(F2, F2)> = Vec::new();
            for i in 0..6 {
                vx.push((x[i], x_mac[i]));
            }

            let mut vy = Vec::new();
            for i in 0..6 {
                vy.push((y[i], y_mac[i]));
            }
            let (res, c) = fconv.bit_add_carry(&mut channel, &mut rng, vx, vy).unwrap();

            for i in 0..power {
                fconv
                    .fcom_f2
                    .f_open(&mut channel, res[i].0, res[i].1)
                    .unwrap();
            }
            fconv.fcom_f2.f_open(&mut channel, c.0, c.1).unwrap();
            (res, c)
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut x_mac = Vec::new();
        let mut y_mac = Vec::new();
        for _ in 0..power {
            let xb_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng).unwrap();
            x_mac.push(xb_mac);

            let yb_mac = fconv.fcom_f2.f_input(&mut channel, &mut rng).unwrap();
            y_mac.push(yb_mac);
        }
        let (res_mac, c_mac) = fconv
            .bit_add_carry(&mut channel, &mut rng, x_mac, y_mac)
            .unwrap();

        let mut res = Vec::new();
        for i in 0..power {
            let b = fconv.fcom_f2.f_open(&mut channel, res_mac[i]).unwrap();
            res.push(b);
        }

        let c = fconv.fcom_f2.f_open(&mut channel, c_mac).unwrap();

        let _resprover = handle.join().unwrap();

        for i in 0..power {
            assert_eq!(expected[i], res[i]);
        }
        assert_eq!(carry, c);
    }

    fn test_conv<FE: FiniteField>() -> () {
        let count = 1000;
        let (sender, receiver) = UnixStream::pair().unwrap();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fconv = SenderConv::<FE>::init(&mut channel).unwrap();

            //   110101
            let mut c = vec![F2::ONE, F2::ZERO, F2::ONE, F2::ZERO, F2::ONE, F2::ONE];
            let mut i = 0;
            let mut j = 0;
            let mut res = Vec::new();
            for _ in 0..count {
                i = (i + 1) % NB_BITS;
                j = (j * 5 + 3) % NB_BITS;

                c[i] = F2::random(&mut rng);
                let c_m: FE = convert_f2_to_field(&c);

                // Let's try a random mutation here
                let saved = c[j];
                c[j] = F2::random(&mut rng);

                let edabit_input = EdaBits {
                    bits: c.clone(),
                    value: c_m.clone(),
                };
                fconv.conv(&mut channel, &mut rng, edabit_input).unwrap();

                res.push(saved == c[j])
            }
            res
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fconv = ReceiverConv::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut res = Vec::new();
        for _ in 0..count {
            let r = fconv.conv(&mut channel, &mut rng);
            res.push(r);
        }

        let resprover = handle.join().unwrap();

        let mut i = 0;
        for b in resprover.iter() {
            let _ = match (b, res[i].as_ref()) {
                (true, Err(_)) => {
                    println!("Break at iteration #{}", i);
                    assert_eq!(true, false)
                }
                (false, Ok(())) => {
                    println!("Break at iteration #{}", i);
                    assert_eq!(true, false)
                }
                (_, _) => (),
            };
            // if *b {
            //     println!("true");
            // } else {
            //     println!("false");
            // }
            i += 1;
        }
    }

    #[test]
    fn test_convert_bit_2_field_f61p() {
        test_convert_bit_2_field::<F61p>();
    }

    #[test]
    fn test_bit_add_carry_f61p() {
        test_bit_add_carry::<F61p>();
    }

    #[test]
    fn test_conv_f61p() {
        test_conv::<F61p>();
    }
}
