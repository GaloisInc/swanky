// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

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

use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block, Malicious, SemiHonest};

// LPN parameters used in the protocol. We use three stages, two sets of LPN
// parameters for setup, and one set of LPN parameters for the extend phase.
// This differs from what is done in the WYKW paper, but based on personal
// communication with one of the authors, is what is used in the implementation.

#[derive(Clone, Copy, PartialEq, Eq)]
struct LpnParams {
    /// Hamming weight `t` of the error vector `e` used in the LPN assumption.
    weight: usize,
    /// Number of columns `n` in the LPN matrix.
    cols: usize,
    /// Number of rows `k` in the LPN matrix.
    rows: usize,
}

// LPN parameters for setup0 phase.
const LPN_SETUP0_PARAMS: LpnParams = LpnParams {
    weight: 600,
    cols: 9_600, // cols / weight = 16
    rows: 1_220,
};

// LPN parameters for setup phase.
const LPN_SETUP_PARAMS: LpnParams = LpnParams {
    weight: 2_600,
    cols: 166_400, // cols / weight = 64
    rows: 5_060,
};

// LPN parameters for extend phase.
const LPN_EXTEND_PARAMS: LpnParams = LpnParams {
    weight: 4_965,
    cols: 10_168_320, // cols / weight = 2_048
    rows: 158_000,
};

// Constant `d` representing a `d`-local linear code, meaning that each column
// of the LPN matrix contains exactly `d` non-zero entries.
const LPN_PARAMS_D: usize = 10;

// Computes the number of saved VOLEs we need for specific LPN parameters.
fn compute_num_saved<FE: FiniteField>(params: LpnParams) -> usize {
    params.rows + params.weight + FE::PolynomialFormNumCoefficients::to_usize()
}

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

/// Subfield VOLE sender.
pub struct Sender<FE: FiniteField> {
    spsvole: SpsSender<FE>,
    base_voles: Vec<(FE::PrimeField, FE)>,
    // Shared RNG with the receiver for generating the LPN matrix.
    lpn_rng: AesRng,
}

impl<FE: FiniteField> Sender<FE> {
    fn init_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let pows: Powers<FE> = <Powers<_> as Default>::default();
        let mut base_sender = BaseSender::<FE>::init(channel, pows.clone(), rng)?;
        let base_voles_setup =
            base_sender.send(channel, compute_num_saved::<FE>(LPN_SETUP0_PARAMS), rng)?;
        let spsvole = SpsSender::<FE>::init(channel, pows, rng)?;
        let seed = rng.gen::<Block>();
        let seed = scuttlebutt::cointoss::receive(channel, &[seed])?[0];
        let lpn_rng = AesRng::from_seed(seed);
        let mut sender = Self {
            spsvole,
            base_voles: base_voles_setup,
            lpn_rng,
        };

        let base_voles_setup = sender.send_internal(channel, LPN_SETUP0_PARAMS, 0, rng)?;
        sender.base_voles = base_voles_setup;
        let base_voles_extend = sender.send_internal(channel, LPN_SETUP_PARAMS, 0, rng)?;
        sender.base_voles = base_voles_extend;
        Ok(sender)
    }

    fn send_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        debug_assert!(
            params == LPN_SETUP0_PARAMS
                || params == LPN_SETUP_PARAMS
                || params == LPN_EXTEND_PARAMS
        );

        let rows = params.rows;
        let cols = params.cols;
        let weight = params.weight;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let m = cols / weight;
        // The number of base VOLEs we need to use.
        let used = rows + weight + r;

        debug_assert!(
            self.base_voles.len() >= used,
            "Not enough base sVOLEs: {} < {} + {} + {}",
            self.base_voles.len(),
            rows,
            weight,
            r
        );

        let uws = self
            .spsvole
            .send(channel, m, &self.base_voles[rows..rows + weight + r], rng)?;
        debug_assert!(uws.len() == cols);

        let leftover = self.base_voles.len() - used;

        // The VOLEs we'll save for the next iteration.
        let mut base_voles = Vec::with_capacity(num_saved + leftover);
        // The VOLEs we'll return to the caller.
        let mut svoles = Vec::with_capacity(cols - num_saved);

        let distribution = Uniform::from(0..rows);
        for (i, (e, c)) in uws.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<FE>(&distribution, &mut self.lpn_rng);
            // Compute `x := u A + e` and `z := w A + c`, where `A` is the LPN matrix.
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
        base_voles.extend(self.base_voles[used..].iter());
        self.base_voles = base_voles;
        debug_assert!(self.base_voles.len() == num_saved + leftover);
        debug_assert!(svoles.len() == cols - num_saved);
        Ok(svoles)
    }
}

impl<FE: FiniteField> SVoleSender for Sender<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Self::init_internal(channel, rng)
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<(FE::PrimeField, FE)>, Error> {
        self.send_internal(
            channel,
            LPN_EXTEND_PARAMS,
            compute_num_saved::<FE>(LPN_EXTEND_PARAMS),
            rng,
        )
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut base_voles = self.send_internal(channel, LPN_SETUP0_PARAMS, 0, rng)?;
        let extras = self.send_internal(
            channel,
            LPN_SETUP_PARAMS,
            compute_num_saved::<FE>(LPN_SETUP_PARAMS),
            rng,
        )?;

        base_voles.extend(extras.iter());

        let spsvole = self.spsvole.duplicate(channel, rng)?;
        let lpn_rng = self.lpn_rng.fork();
        Ok(Self {
            spsvole,
            base_voles,
            lpn_rng,
        })
    }
}

/// Subfield VOLE receiver.
pub struct Receiver<FE: FiniteField> {
    spsvole: SpsReceiver<FE>,
    delta: FE,
    base_voles: Vec<FE>,
    // Shared RNG with the sender for generating the LPN matrix.
    lpn_rng: AesRng,
}

impl<FE: FiniteField> Receiver<FE> {
    fn init_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let pows: Powers<FE> = <Powers<_> as Default>::default();
        let mut base_receiver = BaseReceiver::<FE>::init(channel, pows.clone(), rng)?;
        let base_voles_setup =
            base_receiver.receive(channel, compute_num_saved::<FE>(LPN_SETUP0_PARAMS), rng)?;
        let delta = base_receiver.delta();
        let spsvole = SpsReceiver::<FE>::init(channel, pows, delta, rng)?;
        debug_assert!(base_voles_setup.len() == compute_num_saved::<FE>(LPN_SETUP0_PARAMS));
        let seed = rng.gen::<Block>();
        let seed = scuttlebutt::cointoss::send(channel, &[seed])?[0];
        let lpn_rng = AesRng::from_seed(seed);
        let mut receiver = Self {
            spsvole,
            delta,
            base_voles: base_voles_setup,
            lpn_rng,
        };
        let base_voles_setup = receiver.receive_internal(channel, LPN_SETUP0_PARAMS, 0, rng)?;
        receiver.base_voles = base_voles_setup;
        let base_voles_extend = receiver.receive_internal(channel, LPN_SETUP_PARAMS, 0, rng)?;
        receiver.base_voles = base_voles_extend;
        Ok(receiver)
    }

    fn receive_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        debug_assert!(
            params == LPN_SETUP0_PARAMS
                || params == LPN_SETUP_PARAMS
                || params == LPN_EXTEND_PARAMS
        );

        let rows = params.rows;
        let cols = params.cols;
        let weight = params.weight;
        let r = FE::PolynomialFormNumCoefficients::to_usize();
        let m = cols / weight;
        // The number of base VOLEs we need to use.
        let used = rows + weight + r;

        debug_assert!(
            self.base_voles.len() >= used,
            "{} < {} + {} + {}",
            self.base_voles.len(),
            rows,
            weight,
            r
        );

        let leftover = self.base_voles.len() - used;

        let vs =
            self.spsvole
                .receive(channel, m, &self.base_voles[rows..rows + weight + r], rng)?;
        debug_assert!(vs.len() == cols);
        let distribution = Uniform::from(0..rows);
        let mut base_voles = Vec::with_capacity(num_saved + leftover);
        let mut svoles = Vec::with_capacity(cols - num_saved);
        for (i, b) in vs.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<FE>(&distribution, &mut self.lpn_rng);
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
        base_voles.extend(self.base_voles[used..].iter());
        self.base_voles = base_voles;
        debug_assert!(svoles.len() == cols - num_saved);
        Ok(svoles)
    }
}

impl<FE: FiniteField> SVoleReceiver for Receiver<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Self::init_internal(channel, rng)
    }

    fn delta(&self) -> FE {
        self.delta
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Vec<FE>, Error> {
        self.receive_internal(
            channel,
            LPN_EXTEND_PARAMS,
            compute_num_saved::<FE>(LPN_EXTEND_PARAMS),
            rng,
        )
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut base_voles = self.receive_internal(channel, LPN_SETUP0_PARAMS, 0, rng)?;
        let extras = self.receive_internal(
            channel,
            LPN_SETUP_PARAMS,
            compute_num_saved::<FE>(LPN_SETUP_PARAMS),
            rng,
        )?;

        base_voles.extend(extras.iter());

        let spsvole = self.spsvole.duplicate(channel, rng)?;
        let lpn_rng = self.lpn_rng.fork();
        Ok(Self {
            spsvole,
            delta: self.delta(),
            base_voles,
            lpn_rng,
        })
    }
}

impl<FF: FiniteField> SemiHonest for Sender<FF> {}
impl<FF: FiniteField> SemiHonest for Receiver<FF> {}
impl<FF: FiniteField> Malicious for Sender<FF> {}
impl<FF: FiniteField> Malicious for Receiver<FF> {}

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
            let uws2 = vole2.send(&mut channel, &mut rng).unwrap();
            let uws3 = vole.send(&mut channel, &mut rng).unwrap();
            assert!(uws2 != uws3);
            uws.extend(uws2);
            uws.extend(uws3);
            uws
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = Receiver::init(&mut channel, &mut rng).unwrap();
        let mut vs = vole.receive(&mut channel, &mut rng).unwrap();
        let mut vole2 = vole.duplicate(&mut channel, &mut rng).unwrap();
        let vs2 = vole2.receive(&mut channel, &mut rng).unwrap();
        let vs3 = vole.receive(&mut channel, &mut rng).unwrap();
        assert!(vs2 != vs3);
        vs.extend(vs2);
        vs.extend(vs3);

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
