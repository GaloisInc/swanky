// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This is the implementation of field conversion

use crate::errors::Error;
use crate::svole::wykw::{Receiver, Sender};
use crate::svole::{SVoleReceiver, SVoleSender};
use generic_array::{typenum::Unsigned, GenericArray};
use rand::{CryptoRng, Rng};
use scuttlebutt::{field::FiniteField, AbstractChannel};
use std::marker::PhantomData;

pub struct MacValue<FE: FiniteField>(pub FE::PrimeField, pub FE);

// F_com protocol
pub struct FComSender<FE: FiniteField> {
    phantom: PhantomData<FE>,
    svole_sender: Sender<FE>,
    voles: Vec<(FE::PrimeField, FE)>,
    pos: usize,
}

fn make_x_i<FE: FiniteField>(i: usize) -> FE {
    let mut v: GenericArray<FE::PrimeField, FE::PolynomialFormNumCoefficients> =
        GenericArray::default();
    for j in 0..FE::PolynomialFormNumCoefficients::USIZE {
        if i == j {
            v[i] = FE::PrimeField::ONE;
        } else {
            v[i] = FE::PrimeField::ZERO;
        }
    }
    FE::from_polynomial_coefficients(v)
}

impl<FE: FiniteField> FComSender<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let b = channel.read_bool()?;
        if b {
            Ok(Self {
                phantom: PhantomData,
                svole_sender: Sender::init(channel, rng)?,
                voles: Vec::new(),
                pos: 0,
            })
        } else {
            Err(Error::Other("Error in init".to_string()))
        }
    }

    pub fn f_svole<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let size_left = self.voles.len() - self.pos;
        if num > size_left {
            let mut v = Vec::new();
            self.svole_sender.send(channel, rng, &mut v)?;
            self.voles = v;
            self.pos = 0
        }

        let mut res = Vec::with_capacity(num);
        for i in 0..num {
            res.push(self.voles[self.pos + i]);
        }
        self.pos += num;
        Ok(res)
    }

    pub fn f_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(FE::PrimeField, FE), Error> {
        let v = self.f_svole(channel, rng, 1)?;
        Ok(v[0])
    }

    pub fn f_random_vec<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        let v = self.f_svole(channel, rng, num)?;
        Ok(v)
    }

    pub fn f_input<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: FE::PrimeField,
    ) -> Result<FE, Error> {
        let (r, r_mac) = self.f_random(channel, rng)?;

        let y = x - r;
        channel.write_fe::<FE::PrimeField>(y)?;
        channel.flush()?;

        Ok(r_mac)
    }

    pub fn f_input_vec<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: Vec<FE::PrimeField>,
    ) -> Result<Vec<FE>, Error> {
        let r = self.f_random_vec(channel, rng, x.len())?;

        for i in 0..x.len() {
            let y = x[i] - r[i].0;
            channel.write_fe::<FE::PrimeField>(y)?;
        }
        channel.flush()?;

        Ok(r.into_iter().map(|x| x.1).collect())
    }

    pub fn f_affine_add_cst(
        &self,
        cst: FE::PrimeField,
        x: FE::PrimeField,
        x_mac: FE,
    ) -> (FE::PrimeField, FE) {
        return (cst + x, x_mac);
    }

    pub fn f_affine_mult_cst(
        &self,
        cst: FE::PrimeField,
        x: FE::PrimeField,
        x_mac: FE,
    ) -> (FE::PrimeField, FE) {
        return (cst * x, x_mac.multiply_by_prime_subfield(cst));
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
        x: FE::PrimeField,
        x_mac: FE,
    ) -> Result<(), Error> {
        channel.write_fe::<FE::PrimeField>(x)?;
        channel.flush()?;

        self.f_check_zero(channel, x_mac)?;
        Ok(())
    }

    // TODO: dummy MultiplyCheck
    pub fn f_check_multiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        x: FE::PrimeField,
        x_mac: FE,
        y: FE::PrimeField,
        y_mac: FE,
        z: FE::PrimeField,
        z_mac: FE,
    ) -> Result<(), Error> {
        let _ = self.f_open(channel, x, x_mac)?;
        let _ = self.f_open(channel, y, y_mac)?;
        let _ = self.f_open(channel, z, z_mac)?;
        Ok(())
    }

    pub fn quicksilver_check_multiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        triples: &[(MacValue<FE>, MacValue<FE>, MacValue<FE>)],
    ) -> Result<(), Error> {
        let mut sum_a0 = FE::ZERO;
        let mut sum_a1 = FE::ZERO;

        let chi = channel.read_fe()?;
        let mut chi_power = chi;

        for triple in triples.iter() {
            let x = triple.0 .0;
            let x_mac = triple.0 .1;
            let y = triple.1 .0;
            let y_mac = triple.1 .1;
            let _z = triple.2 .0;
            let z_mac = triple.2 .1;

            let a0 = x_mac * y_mac;
            let a1 =
                x_mac.multiply_by_prime_subfield(y) + y_mac.multiply_by_prime_subfield(x) - z_mac;

            sum_a0 += a0 * chi_power;
            sum_a1 += a1 * chi_power;

            chi_power = chi_power * chi;
        }

        // The following block implements VOPE(1)
        let mut mask = FE::ZERO;
        let mut mask_mac = FE::ZERO;
        let u = self.f_random_vec(channel, rng, FE::PolynomialFormNumCoefficients::USIZE)?;
        for i in 0..FE::PolynomialFormNumCoefficients::USIZE {
            let x_i: FE = make_x_i(i);
            mask += x_i.multiply_by_prime_subfield(u[i].0);
            mask_mac += u[i].1 * x_i;
        }

        let u = sum_a0 + mask_mac;
        let v = sum_a1 + mask;

        channel.write_fe(u)?;
        channel.write_fe(v)?;
        channel.flush()?;

        Ok(())
    }
}

pub struct FComReceiver<FE: FiniteField> {
    delta: FE,
    svole_receiver: Receiver<FE>,
    voles: Vec<FE>,
    pos: usize,
}

impl<FE: FiniteField> FComReceiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        channel.write_bool(true)?;
        channel.flush()?;
        let recv = Receiver::init(channel, rng)?;
        Ok(Self {
            delta: recv.delta(),
            svole_receiver: recv,
            voles: Vec::new(),
            pos: 0,
        })
    }

    pub fn get_delta(&self) -> FE {
        self.delta
    }

    pub fn f_svole<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize,
    ) -> Result<Vec<FE>, Error> {
        let size_left = self.voles.len() - self.pos;
        if num > size_left {
            let mut v = Vec::new();
            self.svole_receiver.receive(channel, rng, &mut v)?;
            self.voles = v;
            self.pos = 0
        }

        let mut res = Vec::with_capacity(num);
        for i in 0..num {
            res.push(self.voles[self.pos + i]);
        }
        self.pos += num;
        Ok(res)
    }

    pub fn f_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<FE, Error> {
        let v = self.f_svole(channel, rng, 1)?;
        Ok(v[0])
    }

    pub fn f_random_vec<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize,
    ) -> Result<Vec<FE>, Error> {
        let v = self.f_svole(channel, rng, num)?;
        Ok(v)
    }

    pub fn f_input<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<FE, Error> {
        let r_mac = self.f_random(channel, rng)?;
        let y = channel.read_fe::<FE::PrimeField>()?;

        let v_mac = r_mac - self.delta.multiply_by_prime_subfield(y);
        Ok(v_mac)
    }

    pub fn f_input_vec<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize,
    ) -> Result<Vec<FE>, Error> {
        let r_mac = self.f_random_vec(channel, rng, num)?;

        let mut v_mac = Vec::with_capacity(num);
        for i in 0..num {
            let y = channel.read_fe::<FE::PrimeField>()?;

            v_mac.push(r_mac[i] - self.delta.multiply_by_prime_subfield(y));
        }
        Ok(v_mac)
    }

    pub fn f_affine_add_cst(&self, cst: FE::PrimeField, x_mac: FE) -> FE {
        return x_mac - self.delta.multiply_by_prime_subfield(cst);
    }

    pub fn f_affine_mult_cst(&self, cst: FE::PrimeField, x_mac: FE) -> FE {
        return x_mac.multiply_by_prime_subfield(cst);
    }

    pub fn f_check_zero<C: AbstractChannel>(
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

    pub fn f_open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        key: FE,
    ) -> Result<FE::PrimeField, Error> {
        let x = channel.read_fe::<FE::PrimeField>()?;
        let b = self.f_check_zero(channel, key + self.delta.multiply_by_prime_subfield(x))?;
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

    pub fn quicksilver_check_multiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        triples: &[(FE, FE, FE)],
    ) -> Result<(), Error> {
        let chi = FE::random(rng);
        channel.write_fe::<FE>(chi)?;
        channel.flush()?;

        let mut sum_b = FE::ZERO;
        let mut power_chi = chi;

        for triple in triples.iter() {
            let x_mac = triple.0;
            let y_mac = triple.1;
            let z_mac = triple.2;

            let b = x_mac * y_mac - (-self.delta) * z_mac; // -delta diff because
            sum_b += b * power_chi;
            power_chi = power_chi * chi;
        }

        // The following block implements VOPE(1)
        let mut mask_mac = FE::ZERO;
        let v_m = self.f_random_vec(channel, rng, FE::PolynomialFormNumCoefficients::USIZE)?;
        for i in 0..FE::PolynomialFormNumCoefficients::USIZE {
            let x_i: FE = make_x_i(i);
            mask_mac += v_m[i] * x_i;
        }

        let u = channel.read_fe::<FE>()?;
        let v = channel.read_fe::<FE>()?;

        let b_plus = sum_b + mask_mac;
        if b_plus == (u + (-self.delta) * v) {
            // - because of delta
            Ok(())
        } else {
            Err(Error::Other("checkMultiply fails".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{FComReceiver, FComSender, MacValue};
    use scuttlebutt::{
        field::{F61p, FiniteField, Gf40},
        AbstractChannel, AesRng, Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_fcom_random<FE: FiniteField>() -> () {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComSender::<FE>::init(&mut channel, &mut rng).unwrap();

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
    }

    fn test_fcom_affine() -> () {
        let count = 200;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComSender::<F61p>::init(&mut channel, &mut rng).unwrap();

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

    fn test_fcom_multiplication<FE: FiniteField>() -> () {
        let count = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FComSender::<FE>::init(&mut channel, &mut rng).unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let (x, xmac) = fcom.f_random(&mut channel, &mut rng).unwrap();
                let (y, ymac) = fcom.f_random(&mut channel, &mut rng).unwrap();
                let z = x * y;
                let zmac = fcom.f_input(&mut channel, &mut rng, z).unwrap();
                v.push((x, xmac, y, ymac, z, zmac));
            }
            let mut r = Vec::new();
            for i in 0..count {
                let b = fcom
                    .quicksilver_check_multiply(
                        &mut channel,
                        &mut rng,
                        &[(
                            MacValue(v[i].0, v[i].1),
                            MacValue(v[i].2, v[i].3),
                            MacValue(v[i].4, v[i].5),
                        )],
                    )
                    .unwrap();
                r.push(b);
            }
            (v, r)
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComReceiver::<FE>::init(&mut channel, &mut rng).unwrap();
        let mut v = Vec::new();

        for _ in 0..count {
            let xmac = fcom.f_random(&mut channel, &mut rng).unwrap();
            let ymac = fcom.f_random(&mut channel, &mut rng).unwrap();
            let zmac = fcom.f_input(&mut channel, &mut rng).unwrap();
            v.push((xmac, ymac, zmac));
        }
        let mut r = Vec::new();
        for i in 0..count {
            let b = fcom
                .quicksilver_check_multiply(&mut channel, &mut rng, &[(v[i].0, v[i].1, v[i].2)])
                .unwrap();
            r.push(b);
        }
        handle.join().unwrap();
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

    #[test]
    fn test_fcom_multiplication_check_f61p() {
        let _t = test_fcom_multiplication::<F61p>();
    }

    #[test]
    fn test_fcom_multiplication_check_gf40() {
        let _t = test_fcom_multiplication::<Gf40>();
    }
}
