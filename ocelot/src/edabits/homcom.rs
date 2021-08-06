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
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block};

#[derive(Clone, Copy, Debug)]
pub struct MacProver<FE: FiniteField>(pub FE::PrimeField, pub FE);

#[derive(Clone, Copy, Debug)]
pub struct MacVerifier<FE: FiniteField>(pub FE);

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

    pub fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            svole_sender: self.svole_sender.duplicate(channel, rng)?,
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
                return Ok(MacProver(e.0, e.1));
            }
            None => {
                self.svole_sender.send(channel, rng, &mut self.voles)?;
                match self.voles.pop() {
                    Some(e) => {
                        return Ok(MacProver(e.0, e.1));
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
        Ok(())
    }

    pub fn affine_add_cst(&self, cst: FE::PrimeField, x: MacProver<FE>) -> MacProver<FE> {
        return MacProver(cst + x.0, x.1);
    }

    pub fn affine_mult_cst(&self, cst: FE::PrimeField, x: MacProver<FE>) -> MacProver<FE> {
        return MacProver(cst * x.0, (x.1).multiply_by_prime_subfield(cst));
    }

    pub fn add(&self, a: MacProver<FE>, b: MacProver<FE>) -> MacProver<FE> {
        let MacProver(a, a_mac) = a;
        let MacProver(b, b_mac) = b;
        return MacProver(a + b, a_mac + b_mac);
    }

    pub fn minus(&self, a: MacProver<FE>, b: MacProver<FE>) -> MacProver<FE> {
        let MacProver(a, a_mac) = a;
        let MacProver(b, b_mac) = b;
        return MacProver(a - b, a_mac - b_mac);
    }

    pub fn check_zero<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        x_mac_batch: Vec<FE>,
    ) -> Result<(), Error> {
        let seed = channel.read_block()?;
        let mut rng = AesRng::from_seed(seed);

        let mut m = FE::ZERO;
        for x_mac in x_mac_batch.iter() {
            let chi = FE::random(&mut rng);
            m += chi * *x_mac;
        }
        channel.write_fe::<FE>(m)?;
        channel.flush()?;
        Ok(())
    }

    pub fn open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        batch: &[MacProver<FE>],
    ) -> Result<(), Error> {
        let mut hasher = blake3::Hasher::new();
        for MacProver(x, _) in batch.iter() {
            channel.write_fe::<FE::PrimeField>(*x)?;
            //hasher.update(&x.to_bytes());
        }
        channel.flush()?;

        for MacProver(x, _) in batch.iter() {
            hasher.update(&x.to_bytes());
        }

        let seed = Block::try_from_slice(&hasher.finalize().as_bytes()[0..16]).unwrap();
        let mut rng = AesRng::from_seed(seed);

        let mut m = FE::ZERO;
        for MacProver(_, x_mac) in batch.iter() {
            let chi = FE::random(&mut rng);
            m += chi * *x_mac;
        }
        channel.write_fe::<FE>(m)?;
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

        for (MacProver(x, x_mac), MacProver(y, y_mac), MacProver(_z, z_mac)) in triples.iter() {
            let a0 = *x_mac * *y_mac;
            let a1 = x_mac.multiply_by_prime_subfield(*y) + y_mac.multiply_by_prime_subfield(*x)
                - *z_mac;

            sum_a0 += a0 * chi_power;
            sum_a1 += a1 * chi_power;

            chi_power *= chi;
        }

        // The following block implements VOPE(1)
        let mut mask = FE::ZERO;
        let mut mask_mac = FE::ZERO;

        for i in 0..FE::PolynomialFormNumCoefficients::USIZE {
            let MacProver(u, u_mac) = self.random(channel, rng)?;
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

    pub fn wolverine_check_multiply<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        triples: &[(MacProver<FE>, MacProver<FE>, MacProver<FE>)],
        aux: &[(MacProver<FE>, MacProver<FE>, MacProver<FE>)],
    ) -> Result<(), Error> {
        let n = triples.len();

        let mut to_open = Vec::with_capacity(2 * n);
        for i in 0..n {
            let (a, b, _c) = triples[i];
            let (x, y, _z) = aux[i];

            let minus_x = self.affine_mult_cst(-FE::PrimeField::ONE, x);
            let minus_y = self.affine_mult_cst(-FE::PrimeField::ONE, y);
            let d = self.add(a, minus_x);
            let e = self.add(b, minus_y);

            to_open.push(d);
            to_open.push(e);
        }
        self.open(channel, &to_open)?;

        let mut to_check = Vec::with_capacity(n);
        for i in 0..n {
            let (_a, _b, c) = triples[i];
            let (x, y, z) = aux[i];
            let MacProver(d, _d_mac) = to_open[2 * i];
            let MacProver(e, _e_mac) = to_open[2 * i + 1];

            let d_e = d * e;

            let e_x = self.affine_mult_cst(e, x);
            let d_y = self.affine_mult_cst(d, y);

            let mut w: MacProver<FE> = z;
            w = self.minus(w, c);
            w = self.add(w, e_x);
            w = self.add(w, d_y);
            w = self.affine_add_cst(d_e, w);

            if w.0 != FE::PrimeField::ZERO {
                return Err(Error::Other("SDFSDF".to_string()));
            }
            to_check.push(w.1);
        }
        self.check_zero(channel, to_check)?;
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

    pub fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Self {
            delta: self.get_delta(),
            svole_receiver: self.svole_receiver.duplicate(channel, rng)?,
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
    ) -> Result<MacVerifier<FE>, Error> {
        match self.voles.pop() {
            Some(e) => {
                return Ok(MacVerifier(e));
            }
            None => {
                println!("SVOLE");
                self.svole_receiver.receive(channel, rng, &mut self.voles)?;
                match self.voles.pop() {
                    Some(e) => {
                        return Ok(MacVerifier(e));
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
    ) -> Result<Vec<MacVerifier<FE>>, Error> {
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
        r_mac: &[MacVerifier<FE>],
        out: &mut Vec<MacVerifier<FE>>,
    ) -> Result<(), Error> {
        for i in 0..num {
            let y = channel.read_fe::<FE::PrimeField>()?;

            out.push(MacVerifier(
                r_mac[i].0 - self.delta.multiply_by_prime_subfield(y),
            ));
        }
        Ok(())
    }

    pub fn affine_add_cst(&self, cst: FE::PrimeField, x_mac: MacVerifier<FE>) -> MacVerifier<FE> {
        return MacVerifier(x_mac.0 - self.delta.multiply_by_prime_subfield(cst));
    }

    pub fn affine_mult_cst(&self, cst: FE::PrimeField, x_mac: MacVerifier<FE>) -> MacVerifier<FE> {
        return MacVerifier(x_mac.0.multiply_by_prime_subfield(cst));
    }

    pub fn add(&self, a: MacVerifier<FE>, b: MacVerifier<FE>) -> MacVerifier<FE> {
        let MacVerifier(a_mac) = a;
        let MacVerifier(b_mac) = b;
        return MacVerifier(a_mac + b_mac);
    }

    pub fn minus(&self, a: MacVerifier<FE>, b: MacVerifier<FE>) -> MacVerifier<FE> {
        let MacVerifier(a_mac) = a;
        let MacVerifier(b_mac) = b;
        return MacVerifier(a_mac - b_mac);
    }

    pub fn check_zero<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        key_batch: &[MacVerifier<FE>],
    ) -> Result<bool, Error> {
        let seed = rng.gen::<Block>();
        channel.write_block(&seed)?;
        channel.flush()?;
        let mut rng = AesRng::from_seed(seed);

        let mut key_chi = FE::ZERO;
        for MacVerifier(key) in key_batch.iter() {
            let chi = FE::random(&mut rng);
            key_chi += chi * *key;
        }
        let m = channel.read_fe::<FE>()?;

        let b = key_chi == m;
        Ok(b)
    }

    pub fn open<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        keys: &[MacVerifier<FE>],
    ) -> Result<Vec<FE::PrimeField>, Error> {
        let mut hasher = blake3::Hasher::new();
        let mut res = Vec::with_capacity(keys.len());
        for _ in 0..keys.len() {
            let x = channel.read_fe::<FE::PrimeField>()?;
            res.push(x);
            hasher.update(&x.to_bytes());
        }
        let seed = Block::try_from_slice(&hasher.finalize().as_bytes()[0..16]).unwrap();
        let mut rng = AesRng::from_seed(seed);

        let mut key_chi = FE::ZERO;
        let mut x_chi = FE::ZERO;
        for i in 0..keys.len() {
            let chi = FE::random(&mut rng);
            let MacVerifier(key) = keys[i];
            let x = res[i];

            key_chi += chi * key;
            x_chi += chi.multiply_by_prime_subfield(x);
        }
        let m = channel.read_fe::<FE>()?;

        if key_chi + self.delta * x_chi == m {
            Ok(res)
        } else {
            Err(Error::Other("open fails".to_string()))
        }
    }

    pub fn quicksilver_check_multiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        triples: &[(MacVerifier<FE>, MacVerifier<FE>, MacVerifier<FE>)],
    ) -> Result<(), Error> {
        let chi = FE::random(rng);
        channel.write_fe::<FE>(chi)?;
        channel.flush()?;

        let mut sum_b = FE::ZERO;
        let mut power_chi = chi;

        for (MacVerifier(x_mac), MacVerifier(y_mac), MacVerifier(z_mac)) in triples.iter() {
            //  should be `- (-delta)` with our conventions compared to
            //  quicksilver but simplified out.
            let b = (*x_mac) * (*y_mac) + self.delta * *z_mac;

            sum_b += b * power_chi;
            power_chi = power_chi * chi;
        }

        // The following block implements VOPE(1)
        let mut mask_mac = FE::ZERO;
        for i in 0..FE::PolynomialFormNumCoefficients::USIZE {
            let MacVerifier(v_m) = self.random(channel, rng)?;
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

    pub fn wolverine_check_multiply<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        triples: &[(MacVerifier<FE>, MacVerifier<FE>, MacVerifier<FE>)],
        aux: &[(MacVerifier<FE>, MacVerifier<FE>, MacVerifier<FE>)],
    ) -> Result<(), Error> {
        let n = triples.len();
        let mut to_open = Vec::with_capacity(2 * n);

        for i in 0..n {
            let (a, b, _c) = triples[i];
            let (x, y, _z) = aux[i];

            let minus_x = self.affine_mult_cst(-FE::PrimeField::ONE, x);
            let minus_y = self.affine_mult_cst(-FE::PrimeField::ONE, y);
            let d = self.add(a, minus_x);
            let e = self.add(b, minus_y);

            to_open.push(d);
            to_open.push(e);
        }
        let opened = self.open(channel, &to_open)?;

        let mut to_check = Vec::with_capacity(n);
        for i in 0..n {
            let (_a, _b, c) = triples[i];
            let (x, y, z) = aux[i];
            let d = opened[2 * i];
            let e = opened[2 * i + 1];

            let d_e = d * e;

            let e_x = self.affine_mult_cst(e, x);
            let d_y = self.affine_mult_cst(d, y);

            let mut w: MacVerifier<FE> = z;
            w = self.minus(w, c);
            w = self.add(w, e_x);
            w = self.add(w, d_y);
            w = self.affine_add_cst(d_e, w);

            to_check.push(w);
        }
        self.check_zero(channel, rng, &to_check)?;
        Ok(())
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
                let MacProver(x, x_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let cst = F61p::random(&mut rng);
                channel.write_fe::<F61p>(cst).unwrap();
                channel.flush().unwrap();
                let m = fcom.affine_mult_cst(cst, MacProver(x, x_mac));
                v.push(m);
                let a = fcom.affine_add_cst(cst, MacProver(x, x_mac));
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
                let MacProver(x, x_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let MacProver(y, y_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let z = x * y;
                let z_mac = fcom.input(&mut channel, &mut rng, &vec![z]).unwrap()[0];
                v.push((
                    MacProver(x, x_mac),
                    MacProver(y, y_mac),
                    MacProver(z, z_mac),
                ));
            }
            channel.flush().unwrap();
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

    fn test_fcom_wolverine<FE: FiniteField>() -> () {
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
                let MacProver(x, x_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let MacProver(y, y_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let z = x * y;
                let z_mac = fcom.input(&mut channel, &mut rng, &vec![z]).unwrap()[0];
                v.push((
                    MacProver(x, x_mac),
                    MacProver(y, y_mac),
                    MacProver(z, z_mac),
                ));
            }

            let mut aux = Vec::new();
            for _ in 0..count {
                let MacProver(x, x_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let MacProver(y, y_mac) = fcom.random(&mut channel, &mut rng).unwrap();
                let z = x * y;
                let z_mac = fcom.input(&mut channel, &mut rng, &vec![z]).unwrap()[0];
                aux.push((
                    MacProver(x, x_mac),
                    MacProver(y, y_mac),
                    MacProver(z, z_mac),
                ));
            }

            let b = fcom
                .wolverine_check_multiply(&mut channel, &v, &aux)
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
        let mut aux = Vec::new();
        for _ in 0..count {
            let xmac = fcom.random(&mut channel, &mut rng).unwrap();
            let ymac = fcom.random(&mut channel, &mut rng).unwrap();
            let zmac = fcom.input(&mut channel, &mut rng, 1).unwrap()[0];
            aux.push((xmac, ymac, zmac));
        }
        let b = fcom
            .wolverine_check_multiply(&mut channel, &mut rng, &v, &aux)
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

    #[test]
    fn test_fcom_wolverine_f61p() {
        let _t = test_fcom_wolverine::<F61p>();
    }
}
