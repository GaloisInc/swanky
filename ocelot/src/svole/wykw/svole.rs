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
    utils::Powers,
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

/// LPN parameters
#[derive(Clone, Copy, PartialEq, Eq)]
struct LpnParams {
    /// Hamming weight `t` of the error vector `e` used in LPN assumption.
    weight: usize,
    /// Number of columns `n` in the LPN matrix.
    cols: usize,
    /// Number of rows `k` in the LPN matrix.
    rows: usize,
}

/// LPN parameters for setup0 phase.
const LPN_SETUP0_PARAMS: LpnParams = LpnParams {
    weight: 600,
    cols: 9_600, // cols / weight = 16
    rows: 1_220,
};

/// LPN parameters for setup phase.
const LPN_SETUP_PARAMS: LpnParams = LpnParams {
    weight: 2_600,
    cols: 166_400, // cols / weight = 64
    rows: 5_060,
};

/// LPN parameters for extend phase.
const LPN_EXTEND_PARAMS: LpnParams = LpnParams {
    weight: 4_965,
    cols: 10_168_320, // cols / weight = 2_048
    rows: 158_000,
};

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
    setup_params: Option<LpnParams>,
    params: LpnParams,
    base_voles: Vec<(FE::PrimeField, FE)>,
    r: usize,
}

impl<FE: FiniteField> Sender<FE> {
    fn init_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        params: LpnParams,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let pows: Powers<FE> = <Powers<_> as Default>::default();
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let mut base_sender = BaseSender::<FE>::init(channel, pows.clone(), rng)?;
        let base_voles = base_sender.send(channel, params.rows + params.weight + r, rng)?;
        let spsvole = SpsSender::<FE>::init(channel, pows, rng)?;
        Ok(Self {
            spsvole,
            setup_params: None,
            params,
            base_voles,
            r,
        })
    }

    fn init_internal2<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut sender: Self,
        params: LpnParams,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let base_voles = sender.send_internal(channel, 0, rng)?;
        Ok(Self {
            spsvole: sender.spsvole,
            setup_params: Some(sender.params),
            params,
            base_voles,
            r: sender.r,
        })
    }

    fn _send_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        params: LpnParams, // should be the setup params
        num_saved: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        debug_assert!(
            params == self.params
                || self.setup_params.is_some() && params == self.setup_params.unwrap()
        );

        let rows = params.rows;
        let cols = params.cols;
        let weight = params.weight;

        debug_assert!(
            self.base_voles.len() >= rows + weight + self.r,
            "{} < {} + {} + {}",
            self.base_voles.len(),
            rows,
            weight,
            self.r
        );
        let m = cols / weight;
        let uws = self.spsvole.send(
            channel,
            m,
            &self.base_voles[rows..rows + weight + self.r],
            rng,
        )?;
        debug_assert!(uws.len() == cols);
        let seed = rng.gen::<Block>();
        let mut lpn_rng = AesRng::from_seed(seed);
        channel.write_block(&seed)?;
        channel.flush()?;
        let distribution = Uniform::from(0..rows);
        let mut base_voles = Vec::with_capacity(num_saved);
        let mut svoles = Vec::with_capacity(cols - num_saved);
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
        debug_assert!(svoles.len() == cols - num_saved);
        Ok(svoles)
    }

    fn set_base_voles(&mut self, base_voles: Vec<(FE::PrimeField, FE)>) -> () {
        self.base_voles = base_voles;
        return ();
    }

    fn send_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        num_saved: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        self._send_internal(channel, self.params, num_saved, rng)
    }

    fn send_internal_using_setup_params<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        match self.setup_params {
            Some(params) => {
                return self._send_internal(
                    channel,
                    params,
                    params.rows + params.weight + self.r,
                    rng,
                )
            }
            None => return Err(Error::MissingSetupParams),
        }
    }
}

impl<FE: FiniteField> SVoleSender for Sender<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let sender = Self::init_internal(channel, LPN_SETUP0_PARAMS, rng)?;
        let mut sender = Self::init_internal2(channel, sender, LPN_SETUP_PARAMS, rng)?;
        let base_voles = sender.send_internal(channel, 0, rng)?;
        Ok(Self {
            spsvole: sender.spsvole,
            setup_params: Some(sender.params),
            params: LPN_EXTEND_PARAMS,
            base_voles,
            r: sender.r,
        })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        self.send_internal(channel, self.params.rows + self.params.weight + self.r, rng)
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        // NOTE: We need to call 3 svoles with the lower setup
        // parameters, because the setup parameters are designed so
        // that the extension from one level is just big enough for
        // the next level if none is saved.
        let voles1 = self.send_internal_using_setup_params(channel, rng)?;
        let voles2 = self.send_internal_using_setup_params(channel, rng)?;
        let voles3 = self.send_internal_using_setup_params(channel, rng)?;

        let nb_voles = self.params.rows + self.params.weight + self.r;

        let mut base_voles = Vec::with_capacity(nb_voles);
        base_voles.extend(voles1.clone());
        let missing1 = nb_voles - voles1.len();
        for i in 0..missing1 {
            base_voles.push(voles2[i]);
        }

        let mut new_base_voles = Vec::with_capacity(nb_voles);
        for i in missing1..voles2.len() {
            new_base_voles.push(voles2[i]);
        }
        let missing2 = nb_voles - (voles2.len() - missing1);
        debug_assert!(missing2 < voles3.len());
        for i in 0..missing2 {
            new_base_voles.push(voles3[i]);
        }

        let spsvole = self.spsvole.duplicate(channel, rng)?;
        self.set_base_voles(base_voles);
        Ok(Self {
            spsvole,
            setup_params: self.setup_params,
            params: self.params,
            base_voles: new_base_voles,
            r: self.r,
        })
    }
}

/// sVole Receiver
pub struct Receiver<FE: FiniteField> {
    spsvole: SpsReceiver<FE>,
    delta: FE,
    setup_params: Option<LpnParams>,
    params: LpnParams,
    base_voles: Vec<FE>,
    r: usize,
}

impl<FE: FiniteField> Receiver<FE> {
    fn init_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        params: LpnParams,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let pows: Powers<FE> = <Powers<_> as Default>::default();
        let mut base_receiver = BaseReceiver::<FE>::init(channel, pows.clone(), rng)?;
        let base_voles = base_receiver.receive(channel, params.rows + params.weight + r, rng)?;
        let delta = base_receiver.delta();
        let spsvole = SpsReceiver::<FE>::init(channel, pows, delta, rng)?;
        debug_assert!(base_voles.len() == params.rows + params.weight + r);
        Ok(Self {
            spsvole,
            delta,
            setup_params: None,
            params,
            base_voles,
            r,
        })
    }

    fn init_internal2<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut receiver: Self,
        params: LpnParams,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let base_voles = receiver.receive_internal(channel, 0, rng)?;
        Ok(Self {
            spsvole: receiver.spsvole,
            delta: receiver.delta,
            setup_params: Some(receiver.params),
            params,
            base_voles,
            r: receiver.r,
        })
    }

    fn _receive_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        debug_assert!(
            params == self.params
                || self.setup_params.is_some() && params == self.setup_params.unwrap()
        );

        let rows = params.rows;
        let cols = params.cols;
        let weight = params.weight;

        debug_assert!(
            self.base_voles.len() >= rows + weight + self.r,
            "{} < {} + {} + {}",
            self.base_voles.len(),
            rows,
            weight,
            self.r
        );
        let m = cols / weight;
        let vs = self.spsvole.receive(
            channel,
            m,
            &self.base_voles[rows..rows + weight + self.r],
            rng,
        )?;
        debug_assert!(vs.len() == cols);
        let seed = channel.read_block()?;
        let mut lpn_rng = AesRng::from_seed(seed);
        let distribution = Uniform::from(0..rows);
        let mut base_voles = Vec::with_capacity(num_saved);
        let mut svoles = Vec::with_capacity(cols - num_saved);
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
        debug_assert!(svoles.len() == cols - num_saved);
        Ok(svoles)
    }

    fn set_base_voles(&mut self, base_voles: Vec<FE>) -> () {
        self.base_voles = base_voles;
    }

    fn receive_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        num_saved: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        self._receive_internal(channel, self.params, num_saved, rng)
    }

    fn receive_internal_using_setup_params<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        match self.setup_params {
            Some(params) => {
                return self._receive_internal(
                    channel,
                    params,
                    params.rows + params.weight + self.r,
                    rng,
                )
            }
            None => return Err(Error::MissingSetupParams),
        }
    }
}

impl<FE: FiniteField> SVoleReceiver for Receiver<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let receiver = Self::init_internal(channel, LPN_SETUP0_PARAMS, rng)?;
        let mut receiver = Self::init_internal2(channel, receiver, LPN_SETUP_PARAMS, rng)?;
        let base_voles = receiver.receive_internal(channel, 0, rng)?;
        Ok(Self {
            spsvole: receiver.spsvole,
            delta: receiver.delta,
            setup_params: Some(receiver.params),
            params: LPN_EXTEND_PARAMS,
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
        self.receive_internal(channel, self.params.rows + self.params.weight + self.r, rng)
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        // NOTE: We need to call 3 svoles with the lower setup
        // parameters, because the setup parameters are designed so
        // that the extension from one level is just big enough for
        // the next level if none is saved.
        let voles1 = self.receive_internal_using_setup_params(channel, rng)?;
        let voles2 = self.receive_internal_using_setup_params(channel, rng)?;
        let voles3 = self.receive_internal_using_setup_params(channel, rng)?;

        let nb_voles = self.params.rows + self.params.weight + self.r;

        let mut base_voles = Vec::with_capacity(nb_voles);
        base_voles.extend(voles1.clone());
        let missing1 = nb_voles - voles1.len();
        for i in 0..missing1 {
            base_voles.push(voles2[i]);
        }

        let mut new_base_voles = Vec::with_capacity(nb_voles);
        for i in missing1..voles2.len() {
            new_base_voles.push(voles2[i]);
        }
        let missing2 = nb_voles - (voles2.len() - missing1);
        debug_assert!(missing2 < voles3.len());
        for i in 0..missing2 {
            new_base_voles.push(voles3[i]);
        }

        let spsvole = self.spsvole.duplicate(channel, rng)?;
        self.set_base_voles(base_voles);
        Ok(Self {
            spsvole,
            delta: self.delta(),
            setup_params: self.setup_params,
            params: self.params,
            base_voles: new_base_voles,
            r: self.r,
        })
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

    fn test_duplicate_svole_<
        FE: FF,
        Sender: SVoleSender<Msg = FE>,
        Receiver: SVoleReceiver<Msg = FE>,
    >() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut vole = Sender::init(&mut channel, &mut rng).unwrap();
            let mut uws = vole.send(&mut channel, &mut rng).unwrap();
            let mut vole2 = vole.duplicate(&mut channel, &mut rng).unwrap();
            uws.extend(vole2.send(&mut channel, &mut rng).unwrap());
            uws
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = Receiver::init(&mut channel, &mut rng).unwrap();
        let mut vs = vole.receive(&mut channel, &mut rng).unwrap();
        let mut vole2 = vole.duplicate(&mut channel, &mut rng).unwrap();
        vs.extend(vole2.receive(&mut channel, &mut rng).unwrap());

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

    #[test]
    fn test_duplicate_svole() {
        test_duplicate_svole_::<F61p, Sender<F61p>, Receiver<F61p>>();
    }
}
