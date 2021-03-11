// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

//! LPN based Subfield Vector Oblivious Linear-function Evaluation (sVole)
//!
//! This module provides implementations of LPN sVole Traits.

use super::{
    base_svole::{Receiver as BaseReceiver, Sender as BaseSender},
    spsvole::{SpsReceiver, SpsSender},
};
use crate::{
    errors::Error,
    svole::{SVoleReceiver, SVoleSender},
};
use generic_array::typenum::Unsigned;
use rand::{
    distributions::{Distribution, Uniform},
    CryptoRng,
    Rng,
    SeedableRng,
};
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block};

/// Secure LPN parameters presented in (cf.
/// <https://eprint.iacr.org/2020/925>, Table 2).

/// LPN parameters for setup0 phase.
mod lpn_setup0_params {
    /// Hamming weight of the error vector `e` used in LPN assumption.
    pub const WEIGHT: usize = 600;
    /// Number of columns `n` in the LPN matrix.
    pub const COLS: usize = 9_600;
    /// Number of rows `k` in the LPN matrix.
    pub const ROWS: usize = 1_220;
}

/// LPN parameters for setup phase.
mod lpn_setup_params {
    /// Hamming weight of the error vector `e` used in LPN assumption.
    pub const WEIGHT: usize = 2_600;
    /// Number of columns `n` in the LPN matrix.
    pub const COLS: usize = 166_400;
    /// Number of rows `k` in the LPN matrix.
    pub const ROWS: usize = 5_060;
}

/// LPN parameters for extend phase.
mod lpn_extend_params {
    /// Hamming weight of the error vector `e` used in LPN assumption.
    pub const WEIGHT: usize = 4_965;
    /// Number of columns `n` in the LPN matrix.
    pub const COLS: usize = 10_168_320;
    /// Number of rows `k` in the LPN matrix.
    pub const ROWS: usize = 158_000;
}

/// Small constant `d` used in the `linear codes` useful in acheiving efficient matrix multiplication.
const LPN_PARAMS_D: usize = 10;

#[inline(always)]
fn lpn_mtx_indices<FE: FiniteField>(
    distribution: &Uniform<usize>,
    mut rng: &mut AesRng,
) -> [(usize, FE::PrimeField); LPN_PARAMS_D] {
    let mut indices = [(0usize, FE::PrimeField::ONE); LPN_PARAMS_D];
    for i in 0..LPN_PARAMS_D {
        let mut rand_idx = distribution.sample(&mut rng);
        while indices.iter().any(|&x| x.0 == rand_idx) {
            rand_idx = distribution.sample(&mut rng);
        }
        indices[i].0 = rand_idx;
        if FE::PrimeField::MODULUS != 2 {
            indices[i].1 = FE::PrimeField::random(&mut rng);
        }
    }
    indices
}

/// sVole Sender
pub struct Sender<FE: FiniteField> {
    spsvole: SpsSender<FE>,
    rows: usize,
    cols: usize,
    weight: usize,
    base_voles: Vec<(FE::PrimeField, FE)>,
    r: usize,
}

impl<FE: FiniteField> Sender<FE> {
    fn init_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let pows = super::utils::gen_pows();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut base_sender = BaseSender::<FE>::init(channel, &pows, rng)?;
        let base_voles = base_sender.send(channel, rows + weight + r, rng)?;
        let spsvole = SpsSender::<FE>::init(channel, pows, rng)?;
        Ok(Self {
            spsvole,
            rows,
            cols,
            weight,
            base_voles,
            r,
        })
    }

    fn init_internal2<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut sender: Self,
        rows: usize,
        cols: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let base_voles = sender.send_internal(channel, 0, rng)?;
        Ok(Self {
            spsvole: sender.spsvole,
            rows,
            cols,
            weight,
            base_voles,
            r: sender.r,
        })
    }

    fn send_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        num_saved: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        debug_assert!(
            self.base_voles.len() >= self.rows + self.weight + self.r,
            "{} < {} + {} + {}",
            self.base_voles.len(),
            self.rows,
            self.weight,
            self.r
        );
        let m = self.cols / self.weight;
        let uws = self.spsvole.send(
            channel,
            m,
            &self.base_voles[self.rows..self.rows + self.weight + self.r],
            rng,
        )?;
        debug_assert!(uws.len() == self.cols);
        let seed = rng.gen::<Block>();
        let mut lpn_rng = AesRng::from_seed(seed);
        channel.write_block(&seed)?;
        channel.flush()?;
        let distribution = Uniform::from(0..self.rows);
        let mut base_voles = Vec::with_capacity(num_saved);
        let mut svoles = Vec::with_capacity(self.cols - num_saved);
        for (i, (e, c)) in uws.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<FE>(&distribution, &mut lpn_rng);
            let mut x = e;
            let mut z = c;

            x += indices
                .iter()
                .map(|(j, a)| self.base_voles[*j].0 * *a)
                .sum();
            z += indices
                .iter()
                .map(|(j, a)| self.base_voles[*j].1.multiply_by_prime_subfield(*a))
                .sum();

            if i < num_saved {
                base_voles.push((x, z));
            } else {
                svoles.push((x, z));
            }
        }
        self.base_voles = base_voles;
        debug_assert!(svoles.len() == self.cols - num_saved);
        Ok(svoles)
    }
}

impl<FE: FiniteField> SVoleSender for Sender<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let sender = Self::init_internal(
            channel,
            lpn_setup0_params::ROWS,
            lpn_setup0_params::COLS,
            lpn_setup0_params::WEIGHT,
            rng,
        )?;
        let mut sender = Self::init_internal2(
            channel,
            sender,
            lpn_setup_params::ROWS,
            lpn_setup_params::COLS,
            lpn_setup_params::WEIGHT,
            rng,
        )?;
        let base_voles = sender.send_internal(channel, 0, rng)?;
        Ok(Self {
            spsvole: sender.spsvole,
            rows: lpn_extend_params::ROWS,
            cols: lpn_extend_params::COLS,
            weight: lpn_extend_params::WEIGHT,
            base_voles,
            r: sender.r,
        })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        self.send_internal(channel, self.rows + self.weight + self.r, rng)
    }
}

/// sVole Receiver
pub struct Receiver<FE: FiniteField> {
    spsvole: SpsReceiver<FE>,
    delta: FE,
    rows: usize,
    cols: usize,
    weight: usize,
    base_voles: Vec<FE>,
    r: usize,
}

impl<FE: FiniteField> Receiver<FE> {
    fn init_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rows: usize,
        cols: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let pows = super::utils::gen_pows();
        let mut base_receiver = BaseReceiver::<FE>::init(channel, &pows, rng)?;
        let base_voles = base_receiver.receive(channel, rows + weight + r, rng)?;
        let delta = base_receiver.delta();
        let spsvole = SpsReceiver::<FE>::init(channel, pows, delta, rng)?;
        debug_assert!(base_voles.len() == rows + weight + r);
        Ok(Self {
            spsvole,
            delta,
            rows,
            cols,
            base_voles,
            weight,
            r,
        })
    }

    fn init_internal2<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut receiver: Self,
        rows: usize,
        cols: usize,
        weight: usize,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let base_voles = receiver.receive_internal(channel, 0, rng)?;
        Ok(Self {
            spsvole: receiver.spsvole,
            delta: receiver.delta,
            rows,
            cols,
            weight,
            base_voles,
            r: receiver.r,
        })
    }

    fn receive_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        num_saved: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        debug_assert!(
            self.base_voles.len() >= self.rows + self.weight + self.r,
            "{} < {} + {} + {}",
            self.base_voles.len(),
            self.rows,
            self.weight,
            self.r
        );
        let m = self.cols / self.weight;
        let vs = self.spsvole.receive(
            channel,
            m,
            &self.base_voles[self.rows..self.rows + self.weight + self.r],
            rng,
        )?;
        debug_assert!(vs.len() == self.cols);
        let seed = channel.read_block()?;
        let mut lpn_rng = AesRng::from_seed(seed);
        let distribution = Uniform::from(0..self.rows);
        let mut base_voles = Vec::with_capacity(self.cols);
        let mut svoles = Vec::with_capacity(self.cols - num_saved);
        for (i, b) in vs.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<FE>(&distribution, &mut lpn_rng);
            let mut y = b;

            y += indices
                .iter()
                .map(|(j, a)| self.base_voles[*j].multiply_by_prime_subfield(*a))
                .sum();

            if i < num_saved {
                base_voles.push(y);
            } else {
                svoles.push(y);
            }
        }
        self.base_voles = base_voles;
        debug_assert!(svoles.len() == self.cols - num_saved);
        Ok(svoles)
    }
}

impl<FE: FiniteField> SVoleReceiver for Receiver<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let receiver = Self::init_internal(
            channel,
            lpn_setup0_params::ROWS,
            lpn_setup0_params::COLS,
            lpn_setup0_params::WEIGHT,
            rng,
        )?;
        let mut receiver = Self::init_internal2(
            channel,
            receiver,
            lpn_setup_params::ROWS,
            lpn_setup_params::COLS,
            lpn_setup_params::WEIGHT,
            rng,
        )?;
        let base_voles = receiver.receive_internal(channel, 0, rng)?;
        Ok(Self {
            spsvole: receiver.spsvole,
            delta: receiver.delta,
            rows: lpn_extend_params::ROWS,
            cols: lpn_extend_params::COLS,
            weight: lpn_extend_params::WEIGHT,
            base_voles,
            r: receiver.r,
        })
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        self.receive_internal(channel, self.rows + self.weight + self.r, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::{Receiver, SVoleReceiver, SVoleSender, Sender};
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Fp, Gf128, F2},
        AesRng,
        Channel,
    };
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    fn test_lpn_svole_<FE: FF, Sender: SVoleSender<Msg = FE>, Receiver: SVoleReceiver<Msg = FE>>() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = Sender::init(&mut channel, &mut rng).unwrap();
            vole.send(&mut channel, &mut rng).unwrap()
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = Receiver::init(&mut channel, &mut rng).unwrap();
        let vs = vole.receive(&mut channel, &mut rng).unwrap();
        let uws = handle.join().unwrap();
        for i in 0..uws.len() as usize {
            let right = vole.delta().multiply_by_prime_subfield(uws[i].0) + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    #[test]
    fn test_lpn_svole() {
        test_lpn_svole_::<F2, Sender<F2>, Receiver<F2>>();
        test_lpn_svole_::<Gf128, Sender<Gf128>, Receiver<Gf128>>();
        test_lpn_svole_::<Fp, Sender<Fp>, Receiver<Fp>>();
        test_lpn_svole_::<F61p, Sender<F61p>, Receiver<F61p>>();
    }
}
