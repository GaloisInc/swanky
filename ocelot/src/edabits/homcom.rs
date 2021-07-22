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

#[derive(Clone, Copy, Debug)]
pub struct MacProver<FE: FiniteField>(FE::PrimeField, FE);

impl<FE: FiniteField> MacProver<FE> {
    #[inline(always)]
    pub fn make_mac_pair(x: FE::PrimeField, x_mac: FE) -> Self {
        MacProver(x, x_mac)
    }

    #[inline(always)]
    pub fn extract_mac_pair(self) -> (FE::PrimeField, FE) {
        (self.0, self.1)
    }
}

// F_com protocol
pub struct FComSender<FE: FiniteField> {
    svole_sender: Sender<FE>,
    voles: Vec<(FE::PrimeField, FE)>,
}

fn make_x_i<FE: FiniteField>(i: usize) -> FE {
    let mut v: GenericArray<FE::PrimeField, FE::PolynomialFormNumCoefficients> =
        GenericArray::default();
    v[i] = FE::PrimeField::ONE;
    FE::from_polynomial_coefficients(v)
}

impl<FE: FiniteField> FComSender<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            svole_sender: Sender::init(channel, rng)?,
            voles: Vec::new(),
        })
    }

    pub fn random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<MacProver<FE>, Error> {
        match self.voles.pop() {
            Some(e) => {
                return Ok(MacProver::make_mac_pair(e.0, e.1));
            }
            None => {
                let mut voles = Vec::new();
                self.svole_sender.send(channel, rng, &mut voles)?;
                self.voles = voles;
                match self.voles.pop() {
                    Some(e) => {
                        return Ok(MacProver::make_mac_pair(e.0, e.1));
                    }
                    None => {
                        return Err(Error::Other("svole failed for random".to_string()));
                    }
                }
            }
        }
    }

    pub fn input<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        x: &[FE::PrimeField],
    ) -> Result<Vec<FE>, Error> {
        let mut r = Vec::with_capacity(x.len());
        for _ in 0..x.len() {
            r.push(self.random(channel, rng)?);
        }

        let mut out = Vec::with_capacity(x.len());
        self.input_low_level(channel, x, &r, &mut out)?;
        Ok(out)
    }

    /// lower level implementation of `input` with arguments for pre
    /// generated voles and out vector
    pub fn input_low_level<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x: &[FE::PrimeField],
        r: &[MacProver<FE>],
        out: &mut Vec<FE>,
    ) -> Result<(), Error> {
        for i in 0..x.len() {
            let y = x[i] - r[i].0;
            out.push(r[i].1);
            channel.write_fe::<FE::PrimeField>(y)?;
        }
        channel.flush()?;

        Ok(())
    }

    pub fn affine_add_cst(&self, cst: FE::PrimeField, x: MacProver<FE>) -> MacProver<FE> {
        return MacProver::make_mac_pair(cst + x.0, x.1);
    }

    pub fn affine_mult_cst(&self, cst: FE::PrimeField, x: MacProver<FE>) -> MacProver<FE> {
        return MacProver::make_mac_pair(cst * x.0, (x.1).multiply_by_prime_subfield(cst));
    }

    pub fn check_zero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x_mac_batch: Vec<FE>,
    ) -> Result<(), Error> {
        for x_mac in x_mac_batch.iter() {
            channel.write_fe::<FE>(*x_mac)?;
        }
        channel.flush()?;
        Ok(())
    }

    pub fn open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        batch: &[MacProver<FE>],
    ) -> Result<(), Error> {
        for e in batch.iter() {
            let x = e.0;
            let x_mac = e.1;
            channel.write_fe::<FE::PrimeField>(x)?;

            // inlining check_zero below
            channel.write_fe::<FE>(x_mac)?;
        }
        // flushing at the end
        channel.flush()?;

        Ok(())
    }

    pub fn quicksilver_check_multiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        triples: &[(MacProver<FE>, MacProver<FE>, MacProver<FE>)],
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

        for i in 0..FE::PolynomialFormNumCoefficients::USIZE {
            let (u, u_mac) = self.random(channel, rng)?.extract_mac_pair();
            let x_i: FE = make_x_i(i);
            mask += x_i.multiply_by_prime_subfield(u);
            mask_mac += u_mac * x_i;
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
}

impl<FE: FiniteField> FComReceiver<FE> {
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let recv = Receiver::init(channel, rng)?;
        Ok(Self {
            delta: recv.delta(),
            svole_receiver: recv,
            voles: Vec::new(),
        })
    }

    pub fn get_delta(&self) -> FE {
        self.delta
    }

    pub fn random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<FE, Error> {
        match self.voles.pop() {
            Some(e) => {
                return Ok(e);
            }
            None => {
                let mut voles = Vec::new();
                self.svole_receiver.receive(channel, rng, &mut voles)?;
                self.voles = voles;
                match self.voles.pop() {
                    Some(e) => {
                        return Ok(e);
                    }
                    None => {
                        return Err(Error::Other("svole failed for random".to_string()));
                    }
                }
            }
        }
    }

    pub fn input<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        num: usize,
    ) -> Result<Vec<FE>, Error> {
        let mut r_mac = Vec::with_capacity(num);
        for _ in 0..num {
            r_mac.push(self.random(channel, rng)?);
        }

        let mut out = Vec::with_capacity(num);
        self.input_low_level(channel, num, &r_mac, &mut out)?;
        Ok(out)
    }

    /// lower level implementation of `input` with arguments for pre
    /// generated voles and out vector
    pub fn input_low_level<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        num: usize,
        r_mac: &[FE],
        out: &mut Vec<FE>,
    ) -> Result<(), Error> {
        for i in 0..num {
            let y = channel.read_fe::<FE::PrimeField>()?;

            out.push(r_mac[i] - self.delta.multiply_by_prime_subfield(y));
        }
        Ok(())
    }

    pub fn affine_add_cst(&self, cst: FE::PrimeField, x_mac: FE) -> FE {
        return x_mac - self.delta.multiply_by_prime_subfield(cst);
    }

    pub fn affine_mult_cst(&self, cst: FE::PrimeField, x_mac: FE) -> FE {
        return x_mac.multiply_by_prime_subfield(cst);
    }

    pub fn check_zero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        key_batch: Vec<FE>,
    ) -> Result<bool, Error> {
        let mut m_batch = Vec::with_capacity(key_batch.len());

        for _ in 0..key_batch.len() {
            let m = channel.read_fe::<FE>()?;
            m_batch.push(m);
        }
        let mut b = true;
        for i in 0..key_batch.len() {
            if key_batch[i] != m_batch[i] {
                b = false;
            }
        }
        Ok(b)
    }

    pub fn open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        keys: &[FE],
    ) -> Result<Vec<FE::PrimeField>, Error> {
        let mut b = true;

        let mut res = Vec::with_capacity(keys.len());
        for key in keys.iter() {
            let x = channel.read_fe::<FE::PrimeField>()?;

            // inlining check_zero below
            let m = channel.read_fe::<FE>()?;
            if *key + self.delta.multiply_by_prime_subfield(x) != m {
                b = false;
            }
            res.push(x);
        }

        if b {
            Ok(res)
        } else {
            Err(Error::Other("open fails at checkzero".to_string()))
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
        for i in 0..FE::PolynomialFormNumCoefficients::USIZE {
            let v_m = self.random(channel, rng)?;
            let x_i: FE = make_x_i(i);
            mask_mac += v_m * x_i;
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

    use super::{FComReceiver, FComSender, MacProver};
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

            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(fcom.random(&mut channel, &mut rng).unwrap());
            }
            let _ = fcom.open(&mut channel, &v).unwrap();
            v
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComReceiver::<FE>::init(&mut channel, &mut rng).unwrap();
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            v.push(fcom.random(&mut channel, &mut rng).unwrap());
        }
        let r = fcom.open(&mut channel, &v).unwrap();

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
                let (x, x_mac) = fcom
                    .random(&mut channel, &mut rng)
                    .unwrap()
                    .extract_mac_pair();
                let cst = F61p::random(&mut rng);
                channel.write_fe::<F61p>(cst).unwrap();
                channel.flush().unwrap();
                let m = fcom.affine_mult_cst(cst, MacProver::make_mac_pair(x, x_mac));
                v.push(m);
                let a = fcom.affine_add_cst(cst, MacProver::make_mac_pair(x, x_mac));
                v.push(a);
            }
            let _ = fcom.open(&mut channel, &v).unwrap();
            v
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComReceiver::<F61p>::init(&mut channel, &mut rng).unwrap();

        let mut v = Vec::new();
        for _ in 0..count {
            let x_mac = fcom.random(&mut channel, &mut rng).unwrap();
            let cst = channel.read_fe().unwrap();
            let m_mac = fcom.affine_mult_cst(cst, x_mac);
            v.push(m_mac);
            let a_mac = fcom.affine_add_cst(cst, x_mac);
            v.push(a_mac);
        }

        let r = fcom.open(&mut channel, &v).unwrap();

        let batch_prover = handle.join().unwrap();

        for i in 0..count {
            assert_eq!(r[i], batch_prover[i].0);
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
                let (x, x_mac) = fcom
                    .random(&mut channel, &mut rng)
                    .unwrap()
                    .extract_mac_pair();
                let (y, y_mac) = fcom
                    .random(&mut channel, &mut rng)
                    .unwrap()
                    .extract_mac_pair();
                let z = x * y;
                let z_mac = fcom.input(&mut channel, &mut rng, &vec![z]).unwrap()[0];
                v.push((
                    MacProver::make_mac_pair(x, x_mac),
                    MacProver::make_mac_pair(y, y_mac),
                    MacProver::make_mac_pair(z, z_mac),
                ));
            }

            let b = fcom
                .quicksilver_check_multiply(&mut channel, &mut rng, &v)
                .unwrap();
            (v, b)
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FComReceiver::<FE>::init(&mut channel, &mut rng).unwrap();

        let mut v = Vec::new();
        for _ in 0..count {
            let xmac = fcom.random(&mut channel, &mut rng).unwrap();
            let ymac = fcom.random(&mut channel, &mut rng).unwrap();
            let zmac = fcom.input(&mut channel, &mut rng, 1).unwrap()[0];
            v.push((xmac, ymac, zmac));
        }
        let b = fcom
            .quicksilver_check_multiply(&mut channel, &mut rng, &v)
            .unwrap();

        let (_, bres) = handle.join().unwrap();
        assert_eq!(b, bres);
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
