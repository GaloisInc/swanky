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
use crate::svole::wykw::specialization::{
    downcast, FiniteFieldSendSpecialization, FiniteFieldSpecialization, Gf40Specialization,
    NoSpecialization,
};
use crate::{
    errors::Error,
    svole::{SVoleReceiver, SVoleSender},
};
use generic_array::typenum::Unsigned;
use rand::{
    distributions::{Distribution, Uniform},
    CryptoRng, Rng, SeedableRng,
};
use scuttlebutt::field::{Gf40, F2};
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng, Block, Malicious, SemiHonest};
use std::any::TypeId;
use std::marker::PhantomData;

mod gf40;

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
// const LPN_SETUP0_PARAMS: LpnParams = LpnParams {
//     weight: 600,
//     cols: 9_600, // cols / weight = 16
//     rows: 1_220,
// };

// LPN parameters for setup phase.
const LPN_SETUP_PARAMS: LpnParams = LpnParams {
    rows: 19_870,
    cols: 642_048,
    weight: 2_508,
    // weight: 2_600,
    // cols: 166_400, // cols / weight = 64
    // rows: 5_060,
};

// LPN parameters for extend phase.
const LPN_EXTEND_PARAMS: LpnParams = LpnParams {
    rows: 589_760,
    cols: 10_805_248,
    weight: 1_319,
    // weight: 4_965,
    // cols: 10_168_320, // cols / weight = 2_048
    // rows: 158_000,
};

// Constant `d` representing a `d`-local linear code, meaning that each column
// of the LPN matrix contains exactly `d` non-zero entries.
const LPN_PARAMS_D: usize = 10;

// Computes the number of saved VOLEs we need for specific LPN parameters.
fn compute_num_saved<FE: FiniteField>(params: LpnParams) -> usize {
    params.rows + params.weight + FE::PolynomialFormNumCoefficients::to_usize()
}

trait SvoleSpecializationSend<FE: FiniteField>: FiniteFieldSendSpecialization<FE> {
    fn svole_send_internal_inner(
        svole: &mut SenderInternal<FE, Self>,
        num_saved: usize,
        rows: usize,
        uws: Vec<Self::SenderPairContents>,
        base_voles: &mut Vec<Self::SenderPairContents>,
        svoles: &mut Vec<Self::SenderPairContents>,
    );
}

trait SvoleSpecializationRecv<FE: FiniteField>: FiniteFieldSpecialization<FE> {
    fn svole_recv_internal_inner(
        svole: &mut ReceiverInternal<FE, Self>,
        num_saved: usize,
        rows: usize,
        vs: Vec<FE>,
        base_voles: &mut Vec<FE>,
        svoles: &mut Vec<FE>,
    );
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
        // TODO: use rejection sampling. indicies[i].1 shouldn't be zero, regardless of the prime
        // modulus.
        if FE::PrimeField::MODULUS != 2 {
            indices[i].1 = FE::PrimeField::random(&mut rng);
        }
    }
    indices
}

/// Subfield VOLE sender.
pub struct Sender<FE: FiniteField>(SenderContents<FE>);

enum SenderContents<FE: FiniteField> {
    Generic(SenderInternal<FE, NoSpecialization>),
    Gf40(SenderInternal<Gf40, Gf40Specialization>),
}

struct SenderInternal<FE: FiniteField, S: SvoleSpecializationSend<FE>> {
    spsvole: SpsSender<FE, S>,
    base_voles: Vec<S::SenderPairContents>,
    // Shared RNG with the receiver for generating the LPN matrix.
    lpn_rng: AesRng,
    phantom: PhantomData<S>,
}

impl<FE: FiniteField, S: SvoleSpecializationSend<FE>> SenderInternal<FE, S> {
    fn init_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let pows: Powers<FE> = Default::default();
        let mut base_sender = BaseSender::<FE, S>::init(channel, pows.clone(), rng)?;
        let base_voles_setup =
            base_sender.send(channel, compute_num_saved::<FE>(LPN_SETUP_PARAMS), rng)?;
        let spsvole = SpsSender::<FE, S>::init(channel, pows, rng)?;
        let seed = rng.gen::<Block>();
        let seed = scuttlebutt::cointoss::receive(channel, &[seed])?[0];
        let lpn_rng = AesRng::from_seed(seed);
        let mut sender = Self {
            spsvole,
            base_voles: base_voles_setup,
            lpn_rng,
            phantom: PhantomData,
        };

        let mut base_voles_setup = Vec::new();
        sender.send_internal(channel, LPN_SETUP_PARAMS, 0, rng, &mut base_voles_setup)?;
        sender.base_voles = base_voles_setup;
        // let mut base_voles_extend = Vec::new();
        // sender.send_internal(channel, LPN_SETUP_PARAMS, 0, rng, &mut base_voles_extend)?;
        // sender.base_voles = base_voles_extend;
        Ok(sender)
    }

    fn send_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut RNG,
        output: &mut Vec<S::SenderPairContents>,
    ) -> Result<(), Error> {
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
        debug_assert_eq!(uws.len(), cols);

        let leftover = self.base_voles.len() - used;

        // The VOLEs we'll save for the next iteration.
        let mut base_voles = Vec::with_capacity(num_saved + leftover);
        // The VOLEs we'll return to the caller.
        output.clear();
        let out_len = cols - num_saved;
        output.reserve(out_len);
        S::svole_send_internal_inner(self, num_saved, rows, uws, &mut base_voles, output);
        base_voles.extend(self.base_voles[used..].iter());
        self.base_voles = base_voles;
        debug_assert_eq!(self.base_voles.len(), num_saved + leftover);
        debug_assert_eq!(output.len(), cols - num_saved);
        Ok(())
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut base_voles = Vec::new();
        self.send_internal(
            channel,
            LPN_SETUP_PARAMS,
            compute_num_saved::<FE>(LPN_SETUP_PARAMS),
            rng,
            &mut base_voles,
        )?;
        // let mut extras = Vec::new();
        // self.send_internal(
        //     channel,
        //     LPN_SETUP_PARAMS,
        //     compute_num_saved::<FE>(LPN_SETUP_PARAMS),
        //     rng,
        //     &mut extras,
        // )?;
        // base_voles.extend(extras.into_iter());

        debug_assert!(base_voles.len() >= compute_num_saved::<FE>(LPN_EXTEND_PARAMS));
        debug_assert!(self.base_voles.len() >= compute_num_saved::<FE>(LPN_EXTEND_PARAMS));

        let spsvole = self.spsvole.duplicate(channel, rng)?;
        let lpn_rng = self.lpn_rng.fork();
        Ok(Self {
            spsvole,
            base_voles,
            lpn_rng,
            phantom: PhantomData,
        })
    }
}
impl<FE: FiniteField> SvoleSpecializationSend<FE> for NoSpecialization {
    fn svole_send_internal_inner(
        svole: &mut SenderInternal<FE, Self>,
        num_saved: usize,
        rows: usize,
        uws: Vec<(<FE as FiniteField>::PrimeField, FE)>,
        base_voles: &mut Vec<(<FE as FiniteField>::PrimeField, FE)>,
        svoles: &mut Vec<(<FE as FiniteField>::PrimeField, FE)>,
    ) {
        let distribution = Uniform::from(0..rows);
        for (i, (e, c)) in uws.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<FE>(&distribution, &mut svole.lpn_rng);
            // Compute `x := u A + e` and `z := w A + c`, where `A` is the LPN matrix.
            let mut x = e;
            let mut z = c;
            x += indices
                .iter()
                .map(|(j, a)| svole.base_voles[*j].0 * *a)
                .sum();
            z += indices
                .iter()
                .map(|(j, a)| svole.base_voles[*j].1.multiply_by_prime_subfield(*a))
                .sum();

            if i < num_saved {
                base_voles.push((x, z));
            } else {
                svoles.push((x, z));
            }
        }
    }
}

impl<FE: FiniteField> SVoleSender for Sender<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Sender(if TypeId::of::<FE>() == TypeId::of::<Gf40>() {
            SenderContents::Gf40(SenderInternal::<Gf40, Gf40Specialization>::init_internal(
                channel, rng,
            )?)
        } else {
            SenderContents::Generic(SenderInternal::<FE, NoSpecialization>::init_internal(
                channel, rng,
            )?)
        }))
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        output: &mut Vec<(FE::PrimeField, FE)>,
    ) -> Result<(), Error> {
        Ok(match &mut self.0 {
            SenderContents::Generic(internal) => internal.send_internal(
                channel,
                LPN_EXTEND_PARAMS,
                compute_num_saved::<FE>(LPN_EXTEND_PARAMS),
                rng,
                output,
            )?,
            SenderContents::Gf40(internal) => {
                let mut tmp = Vec::new();
                internal.send_internal(
                    channel,
                    LPN_EXTEND_PARAMS,
                    compute_num_saved::<FE>(LPN_EXTEND_PARAMS),
                    rng,
                    &mut tmp,
                )?;
                output.clear();
                output.extend(
                    tmp.into_iter()
                        .map(Gf40Specialization::extract_sender_pair)
                        .map(downcast::<(F2, Gf40), (FE::PrimeField, FE)>),
                );
            }
        })
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(match &mut self.0 {
            SenderContents::Generic(internal) => {
                Sender(SenderContents::Generic(internal.duplicate(channel, rng)?))
            }
            SenderContents::Gf40(internal) => {
                Sender(SenderContents::Gf40(internal.duplicate(channel, rng)?))
            }
        })
    }
}
impl Sender<Gf40> {
    /// This has the same functionality as `send`, except that it returns _packed_ `(F2, Gf40)`
    /// pairs.
    ///
    /// The `F2` is encoded in the most significant bit of the output word. The lower 40 bits
    /// contain the `Gf40` field element.
    pub fn send_fast<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        output: &mut Vec<u64>,
    ) -> Result<(), Error> {
        match &mut self.0 {
            SenderContents::Gf40(internal) => internal.send_internal(
                channel,
                LPN_EXTEND_PARAMS,
                compute_num_saved::<Gf40>(LPN_EXTEND_PARAMS),
                rng,
                output,
            ),
            _ => unreachable!(),
        }
    }
}

/// Subfield VOLE receiver.
pub struct Receiver<FE: FiniteField> {
    contents: ReceiverContents<FE>,
    delta_cache: FE,
}

enum ReceiverContents<FE: FiniteField> {
    Generic(ReceiverInternal<FE, NoSpecialization>),
    Gf40(ReceiverInternal<Gf40, Gf40Specialization>),
}

struct ReceiverInternal<FE: FiniteField, S: SvoleSpecializationRecv<FE>> {
    spsvole: SpsReceiver<FE, S>,
    delta: FE,
    base_voles: Vec<FE>,
    // Shared RNG with the sender for generating the LPN matrix.
    lpn_rng: AesRng,
    phantom: PhantomData<S>,
}

impl<FE: FiniteField, S: SvoleSpecializationRecv<FE>> ReceiverInternal<FE, S> {
    fn init_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let pows: Powers<FE> = Default::default();
        let mut base_receiver = BaseReceiver::<FE>::init(channel, pows.clone(), rng)?;
        let base_voles_setup =
            base_receiver.receive(channel, compute_num_saved::<FE>(LPN_SETUP_PARAMS), rng)?;
        let delta = base_receiver.delta();
        let spsvole = SpsReceiver::<FE, S>::init(channel, pows, delta, rng)?;
        let seed = rng.gen::<Block>();
        let seed = scuttlebutt::cointoss::send(channel, &[seed])?[0];
        let lpn_rng = AesRng::from_seed(seed);
        let mut receiver = Self {
            spsvole,
            delta,
            base_voles: base_voles_setup,
            lpn_rng,
            phantom: PhantomData,
        };
        let mut base_voles_setup = Vec::new();
        receiver.receive_internal(channel, LPN_SETUP_PARAMS, 0, rng, &mut base_voles_setup)?;
        receiver.base_voles = base_voles_setup;
        // let mut base_voles_extend = Vec::new();
        // receiver.receive_internal(channel, LPN_SETUP_PARAMS, 0, rng, &mut base_voles_extend)?;
        // receiver.base_voles = base_voles_extend;
        Ok(receiver)
    }

    fn receive_internal<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        params: LpnParams,
        num_saved: usize,
        rng: &mut RNG,
        output: &mut Vec<FE>,
    ) -> Result<(), Error> {
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
        let mut base_voles = Vec::with_capacity(num_saved + leftover);
        output.clear();
        output.reserve(cols - num_saved);
        S::svole_recv_internal_inner(self, num_saved, rows, vs, &mut base_voles, output);
        base_voles.extend(self.base_voles[used..].iter());
        self.base_voles = base_voles;
        debug_assert_eq!(output.len(), cols - num_saved);
        Ok(())
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut base_voles = Vec::new();
        self.receive_internal(
            channel,
            LPN_SETUP_PARAMS,
            compute_num_saved::<FE>(LPN_SETUP_PARAMS),
            rng,
            &mut base_voles,
        )?;
        // let mut extras = Vec::new();
        // self.receive_internal(
        //     channel,
        //     LPN_SETUP_PARAMS,
        //     compute_num_saved::<FE>(LPN_SETUP_PARAMS),
        //     rng,
        //     &mut extras,
        // )?;
        // base_voles.extend(extras.into_iter());

        debug_assert!(base_voles.len() >= compute_num_saved::<FE>(LPN_EXTEND_PARAMS));
        debug_assert!(self.base_voles.len() >= compute_num_saved::<FE>(LPN_EXTEND_PARAMS));

        let spsvole = self.spsvole.duplicate(channel, rng)?;
        let lpn_rng = self.lpn_rng.fork();
        Ok(Self {
            spsvole,
            delta: self.delta,
            base_voles,
            lpn_rng,
            phantom: PhantomData,
        })
    }
}

impl<FE: FiniteField> SvoleSpecializationRecv<FE> for NoSpecialization {
    fn svole_recv_internal_inner(
        svole: &mut ReceiverInternal<FE, Self>,
        num_saved: usize,
        rows: usize,
        vs: Vec<FE>,
        base_voles: &mut Vec<FE>,
        svoles: &mut Vec<FE>,
    ) {
        let distribution = Uniform::from(0..rows);
        for (i, b) in vs.into_iter().enumerate() {
            let indices = lpn_mtx_indices::<FE>(&distribution, &mut svole.lpn_rng);
            let mut y = b;

            y += indices
                .iter()
                .map(|(j, a)| svole.base_voles[*j].multiply_by_prime_subfield(*a))
                .sum();

            if i < num_saved {
                base_voles.push(y);
            } else {
                svoles.push(y);
            }
        }
    }
}

impl<FE: FiniteField> SVoleReceiver for Receiver<FE> {
    type Msg = FE;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let contents = if TypeId::of::<FE>() == TypeId::of::<Gf40>() {
            ReceiverContents::Gf40(ReceiverInternal::<Gf40, Gf40Specialization>::init_internal(
                channel, rng,
            )?)
        } else {
            ReceiverContents::Generic(ReceiverInternal::<FE, NoSpecialization>::init_internal(
                channel, rng,
            )?)
        };
        let delta_cache = match &contents {
            ReceiverContents::Generic(internal) => internal.delta,
            ReceiverContents::Gf40(internal) => downcast::<Gf40, FE>(internal.delta),
        };
        Ok(Receiver {
            contents,
            delta_cache,
        })
    }

    fn delta(&self) -> FE {
        self.delta_cache
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        output: &mut Vec<FE>,
    ) -> Result<(), Error> {
        Ok(match &mut self.contents {
            ReceiverContents::Generic(internal) => internal.receive_internal(
                channel,
                LPN_EXTEND_PARAMS,
                compute_num_saved::<FE>(LPN_EXTEND_PARAMS),
                rng,
                output,
            )?,
            ReceiverContents::Gf40(internal) => internal.receive_internal(
                channel,
                LPN_EXTEND_PARAMS,
                compute_num_saved::<FE>(LPN_EXTEND_PARAMS),
                rng,
                <dyn std::any::Any>::downcast_mut(output).expect("FE==Gf40"),
            )?,
        })
    }

    fn duplicate<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(Receiver {
            contents: match &mut self.contents {
                ReceiverContents::Generic(internal) => {
                    ReceiverContents::Generic(internal.duplicate(channel, rng)?)
                }
                ReceiverContents::Gf40(internal) => {
                    ReceiverContents::Gf40(internal.duplicate(channel, rng)?)
                }
            },
            delta_cache: self.delta_cache,
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
    use scuttlebutt::field::Gf40;
    use scuttlebutt::{
        field::{F61p, FiniteField as FF, Fp, Gf128},
        AesRng, Channel,
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
            let mut out = Vec::new();
            vole.send(&mut channel, &mut rng, &mut out).unwrap();
            out
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = Receiver::init(&mut channel, &mut rng).unwrap();
        let mut vs = Vec::new();
        vole.receive(&mut channel, &mut rng, &mut vs).unwrap();
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
            let mut uws = Vec::new();
            vole.send(&mut channel, &mut rng, &mut uws).unwrap();
            let mut vole2 = vole.duplicate(&mut channel, &mut rng).unwrap();
            let mut uws2 = Vec::new();
            vole2.send(&mut channel, &mut rng, &mut uws2).unwrap();
            let mut uws3 = Vec::new();
            vole.send(&mut channel, &mut rng, &mut uws3).unwrap();
            assert_ne!(uws2, uws3);
            uws.extend(uws2);
            uws.extend(uws3);
            uws
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut vole = Receiver::init(&mut channel, &mut rng).unwrap();
        let mut vs = Vec::new();
        vole.receive(&mut channel, &mut rng, &mut vs).unwrap();
        let mut vole2 = vole.duplicate(&mut channel, &mut rng).unwrap();
        let mut vs2 = Vec::new();
        vole2.receive(&mut channel, &mut rng, &mut vs2).unwrap();
        let mut vs3 = Vec::new();
        vole.receive(&mut channel, &mut rng, &mut vs3).unwrap();
        assert_ne!(vs2, vs3);
        vs.extend(vs2);
        vs.extend(vs3);

        let uws = handle.join().unwrap();
        for i in 0..uws.len() as usize {
            let right = vole.delta().multiply_by_prime_subfield(uws[i].0) + vs[i];
            assert_eq!(uws[i].1, right);
        }
    }

    #[test]
    fn test_lpn_svole_gf128() {
        test_lpn_svole_::<Gf128, Sender<Gf128>, Receiver<Gf128>>();
    }

    #[ignore]
    #[test]
    fn test_lpn_svole_fp() {
        test_lpn_svole_::<Fp, Sender<Fp>, Receiver<Fp>>();
    }

    #[test]
    fn test_lpn_svole_f61p() {
        test_lpn_svole_::<F61p, Sender<F61p>, Receiver<F61p>>();
    }

    #[test]
    fn test_lpn_svole_gf40() {
        test_lpn_svole_::<Gf40, Sender<Gf40>, Receiver<Gf40>>();
    }

    #[test]
    fn test_duplicate_svole() {
        test_duplicate_svole_::<F61p, Sender<F61p>, Receiver<F61p>>();
    }

    #[test]
    fn test_duplicate_svole_gf40() {
        test_duplicate_svole_::<Gf40, Sender<Gf40>, Receiver<Gf40>>();
    }
}
