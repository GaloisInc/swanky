//! Homomorphic commitment functionality.
//!
//! It includes `random`, `input`, affine operations,
//! `check_zero`, `open` and `check_multiply`.
//! These functionalities are used for diet Mac'n'Cheese and in the edabits
//! conversion protocol for field-switching.
use crate::{
    mac::Mac,
    party::{Party, Prover, Verifier, WhichParty},
    svole_trait::SvoleT,
};
use hybrid_array::Array;
use log::{debug, warn};
use rand::{RngExt, SeedableRng};
use swanky_block::Block;
use swanky_channel_legacy::AbstractChannel;
use swanky_error::{ErrorKind, Result, WrapErr, bail, ensure};
use swanky_field::{DegreeModulo, FiniteField, IsSubFieldOf};
use swanky_party::{
    either::PartyEither,
    private::{PartyPrivate, PartyPrivateCopy},
    ty_eq::{EqualityProposition, Witness},
};
use swanky_rng::SwankyRng;
use swanky_svole_wykw::LpnParams;

// Size of batches for multiplication / assert-zero
pub const BATCH_SIZE: usize = 3_000_000;

pub struct MultCheckState<P: Party, V: Copy, T: Copy> {
    triples: PartyPrivate<Prover, P, Vec<(Mac<P, V, T>, Mac<P, V, T>, Mac<P, V, T>)>>,
    sum_b: PartyPrivateCopy<Verifier, P, T>,
    chi_power: PartyPrivateCopy<Verifier, P, T>,
    chi: PartyPrivateCopy<Verifier, P, T>,
    count: usize,
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> MultCheckState<P, V, T> {
    /// Initialize the state.
    pub(crate) fn init(rng: &mut SwankyRng) -> Result<Self> {
        let chi = PartyPrivateCopy::new(T::random(rng));

        Ok(Self {
            triples: Default::default(),
            sum_b: PartyPrivateCopy::new(T::ZERO),
            chi_power: chi,
            chi,
            count: 0,
        })
    }

    /// Reset the state. Generates a new chi value (without communication).
    fn reset(&mut self, rng: PartyPrivate<Verifier, P, &mut SwankyRng>) -> Result<()> {
        self.triples = Default::default();
        self.sum_b = PartyPrivateCopy::new(T::ZERO);
        self.chi = rng.map(|rng| T::random(rng)).into();
        self.chi_power = self.chi;
        self.count = 0;

        Ok(())
    }

    pub(crate) fn accumulate(
        &mut self,
        &triple: &(Mac<P, V, T>, Mac<P, V, T>, Mac<P, V, T>),
        delta: PartyPrivateCopy<Verifier, P, T>,
    ) {
        match P::WHICH {
            WhichParty::Prover(ev) => {
                self.triples.as_mut().into_inner(ev).push(triple);
            }
            WhichParty::Verifier(ev) => {
                let (x, y, z) = triple;
                let b = x.mac() * y.mac() + delta.into_inner(ev) * z.mac();
                *self.sum_b.as_mut().into_inner(ev) += b * self.chi_power.into_inner(ev);
                *self.chi_power.as_mut().into_inner(ev) *= self.chi.into_inner(ev);
            }
        }

        self.count += 1;
    }

    pub(crate) fn finalize<C: AbstractChannel + Clone>(
        &mut self,
        mask: Mac<P, T, T>,
        channel: &mut C,
        rng: &mut SwankyRng,
        delta: PartyPrivateCopy<Verifier, P, T>,
    ) -> Result<usize> {
        match P::WHICH {
            WhichParty::Prover(ev) => {
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;
                let chi = channel
                    .read_serializable()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read chi.")?;
                let mut chi_power = chi;

                let mut sum_a0 = T::ZERO;
                let mut sum_a1 = T::ZERO;
                for &(x, y, z) in self.triples.as_ref().into_inner(ev) {
                    let a0 = x.mac() * y.mac();
                    let a1 = y.value().into_inner(ev) * x.mac()
                        + x.value().into_inner(ev) * y.mac()
                        - z.mac();

                    sum_a0 += a0 * chi_power;
                    sum_a1 += a1 * chi_power;

                    chi_power *= chi;
                }

                let u = sum_a0 + mask.mac();
                let v = sum_a1 + mask.value().into_inner(ev);

                channel
                    .write_serializable(&u)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write 'u'.")?;
                channel
                    .write_serializable(&v)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write 'v'.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;

                let c = self.count;
                self.reset(PartyPrivate::empty(ev))?;
                Ok(c)
            }
            WhichParty::Verifier(ev) => {
                channel
                    .write_serializable::<T>(&self.chi.into_inner(ev))
                    .wrap_err(ErrorKind::NetworkError, "Failed to write chi.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;

                let u = channel
                    .read_serializable::<T>()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read 'u'.")?;
                let v = channel
                    .read_serializable::<T>()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read 'v'.")?;

                let b_plus = self.sum_b.into_inner(ev) + mask.mac();
                if b_plus == (u + (-delta.into_inner(ev)) * v) {
                    let c = self.count;
                    self.reset(PartyPrivate::new(rng))?;
                    Ok(c)
                } else {
                    self.reset(PartyPrivate::new(rng))?;
                    bail!(
                        ErrorKind::OtherError,
                        "QuickSilver multiplication check failed."
                    )
                }
            }
        }
    }

    /// Return the number of checks accumulated.
    pub(crate) fn count(&self) -> usize {
        self.count
    }
}

impl<P: Party, V: Copy, T: Copy> Drop for MultCheckState<P, V, T> {
    fn drop(&mut self) {
        if self.count != 0 {
            warn!(
                "Quicksilver functionality dropped before check finished. Multiply count: {}",
                self.count,
            );
        }
    }
}

/// State to accumulate check zero.
pub struct ZeroCheckState<P: Party, V: Copy, T: Copy>(Vec<Mac<P, V, T>>);

impl<P: Party, V: Copy, T: Copy> Drop for ZeroCheckState<P, V, T> {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            warn!(
                "State for check_zero dropped before check finished. Count: {}",
                self.0.len()
            );
        }
    }
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> ZeroCheckState<P, V, T> {
    /// Initialize the state.
    pub(crate) fn init() -> Result<Self> {
        Ok(Self(vec![]))
    }

    /// Reset the state.
    fn reset(&mut self) {
        self.0.clear();
    }

    pub(crate) fn accumulate(&mut self, &mac: &Mac<P, V, T>) -> Result<()> {
        self.0.push(mac);
        Ok(())
    }

    pub(crate) fn finalize<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut SwankyRng,
    ) -> Result<usize> {
        let mut rng = match P::WHICH {
            WhichParty::Prover(_) => {
                let seed = channel
                    .read_block()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read seed block.")?;
                SwankyRng::from_seed(seed)
            }
            WhichParty::Verifier(_) => {
                let seed = rng.random::<Block>();
                channel
                    .write_block(&seed)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write seed.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;
                SwankyRng::from_seed(seed)
            }
        };

        let b = match P::WHICH {
            WhichParty::Prover(ev) => {
                let mut m = T::ZERO;
                let mut b = true;
                for mac in self.0.iter() {
                    b &= mac.value().into_inner(ev) == V::ZERO;
                    let chi = T::random(&mut rng);
                    m += chi * mac.mac();
                }
                channel
                    .write_serializable::<T>(&m)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write 'm'.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;

                b
            }
            WhichParty::Verifier(_) => {
                let mut key_chi = T::ZERO;
                for mac in self.0.iter() {
                    let chi = T::random(&mut rng);
                    key_chi += chi * mac.mac();
                }
                let m = channel
                    .read_serializable::<T>()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read 'm'.")?;

                key_chi == m
            }
        };

        let count = self.0.len();
        self.reset();
        ensure!(b, ErrorKind::OtherError, "check zero failed");
        Ok(count)
    }

    /// Return the number of checks accumulated.
    pub(crate) fn count(&self) -> usize {
        self.0.len()
    }
}

/// Homomorphic commitment scheme.
pub struct FCom<P: Party, V: Copy, T: Copy, SVOLE: SvoleT<P, V, T>> {
    delta: PartyPrivateCopy<Verifier, P, T>,
    svole: SVOLE,
    voles: PartyEither<P, Vec<(V, T)>, Vec<T>>,
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField, SVOLE: SvoleT<P, V, T>> FCom<P, V, T, SVOLE>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    /// Initialize the commitment scheme.
    pub fn init<C: AbstractChannel + Clone>(
        channel: &mut C,
        rng: &mut SwankyRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        let (svole, delta) = match P::WHICH {
            WhichParty::Prover(ev) => {
                let svole = SVOLE::init(channel, rng, lpn_setup, lpn_extend, None)?;
                (svole, PartyPrivateCopy::empty(ev))
            }
            WhichParty::Verifier(ev) => {
                let svole = SVOLE::init(channel, rng, lpn_setup, lpn_extend, None)?;
                let delta = svole.delta(ev);
                (svole, PartyPrivateCopy::new(delta))
            }
        };

        Ok(Self {
            delta,
            svole,
            voles: PartyEither::default(),
        })
    }

    pub fn init_with_vole(svole: SVOLE) -> Result<Self> {
        Ok(Self {
            delta: match P::WHICH {
                WhichParty::Prover(ev) => PartyPrivateCopy::empty(ev),
                WhichParty::Verifier(ev) => PartyPrivateCopy::new(svole.delta(ev)),
            },
            svole,
            voles: PartyEither::default(),
        })
    }

    pub fn init_with_delta<C: AbstractChannel + Clone>(
        channel: &mut C,
        rng: &mut SwankyRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        delta: T,
    ) -> Result<Self> {
        if let WhichParty::Verifier(_) = P::WHICH {
            Ok(Self {
                delta: PartyPrivateCopy::new(delta),
                svole: SVOLE::init(channel, rng, lpn_setup, lpn_extend, Some(delta))?,
                voles: PartyEither::default(),
            })
        } else {
            bail!(
                ErrorKind::InitializationError,
                "Should not init with delta for a prover"
            );
        }
    }

    /// Duplicate the commitment scheme.
    pub fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            delta: self.delta,
            svole: self.svole.duplicate(),
            voles: PartyEither::default(),
        })
    }

    /// Return the `Δ` value associated with the commitment scheme.
    #[inline]
    pub fn get_delta(&self) -> PartyPrivateCopy<Verifier, P, T> {
        self.delta
    }

    /// Return a random [`Mac`].
    pub fn random<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut SwankyRng,
    ) -> Result<Mac<P, V, T>> {
        match P::WHICH {
            WhichParty::Prover(ev) => match self.voles.as_mut().into_inner(ev).pop() {
                Some(e) => return Ok(Mac::new(PartyPrivateCopy::new(e.0), e.1)),
                None => {
                    self.svole.extend(channel, rng, &mut self.voles.as_mut())?;

                    assert_ne!(
                        self.voles.as_ref().into_inner(ev).len(),
                        0,
                        "VOLE extension should always produce VOLEs",
                    );
                }
            },
            WhichParty::Verifier(ev) => match self.voles.as_mut().into_inner(ev).pop() {
                Some(e) => return Ok(Mac::new(PartyPrivateCopy::empty(ev), e)),
                None => {
                    self.svole.extend(channel, rng, &mut self.voles.as_mut())?;

                    assert_ne!(
                        self.voles.as_ref().into_inner(ev).len(),
                        0,
                        "VOLE extension should always produce VOLEs",
                    );
                }
            },
        }
        self.random(channel, rng)
    }

    /// Input a slice and return the associated MACs.
    pub fn input_prover<C: AbstractChannel + Clone>(
        &mut self,
        ev: Witness<impl EqualityProposition<Prover, P>>,
        channel: &mut C,
        rng: &mut SwankyRng,
        source: &[V],
    ) -> Result<Vec<T>> {
        debug!("input");
        let capacity = source.len();
        let mut out = Vec::with_capacity(capacity);
        self.input_prover_low_level(ev, channel, rng, source, &mut out)?;
        Ok(out)
    }

    /// Input a number of commitment values and return the associated MACs.
    pub fn input_verifier<C: AbstractChannel + Clone>(
        &mut self,
        ev: Witness<impl EqualityProposition<Verifier, P>>,
        channel: &mut C,
        rng: &mut SwankyRng,
        source: usize,
    ) -> Result<Vec<Mac<P, V, T>>> {
        debug!("input");
        let mut out = Vec::with_capacity(source);
        self.input_verifier_low_level(ev, channel, rng, source, &mut out)?;
        Ok(out)
    }

    pub fn input_prover_low_level<C: AbstractChannel + Clone>(
        &mut self,
        ev: Witness<impl EqualityProposition<Prover, P>>,
        channel: &mut C,
        rng: &mut SwankyRng,
        source: &[V],
        out: &mut Vec<T>,
    ) -> Result<()> {
        debug!("input_low_level");
        for &x_i in source {
            let tag = self.input1_prover(ev, channel, rng, x_i)?;
            out.push(tag);
        }
        Ok(())
    }

    pub fn input_verifier_low_level<C: AbstractChannel + Clone>(
        &mut self,
        ev: Witness<impl EqualityProposition<Verifier, P>>,
        channel: &mut C,
        rng: &mut SwankyRng,
        source: usize,
        out: &mut Vec<Mac<P, V, T>>,
    ) -> Result<()> {
        debug!("input_low_level");
        for _ in 0..source {
            let r = self.random(channel, rng)?;
            let y = channel
                .read_serializable::<V>()
                .wrap_err(ErrorKind::NetworkError, "Failed to read 'y'.")?;
            out.push(Mac::new(
                PartyPrivateCopy::empty(ev),
                r.mac() - y * self.delta.into_inner(ev),
            ));
        }
        Ok(())
    }

    pub fn input1_prover<C: AbstractChannel + Clone>(
        &mut self,
        ev: Witness<impl EqualityProposition<Prover, P>>,
        channel: &mut C,
        rng: &mut SwankyRng,
        x: V,
    ) -> Result<T> {
        debug!("input1");
        let r = self.random(channel, rng)?;
        let y = x - r.value().into_inner(ev);
        channel
            .write_serializable(&y)
            .wrap_err(ErrorKind::NetworkError, "Failed to write 'y'.")?;
        Ok(r.mac())
    }

    pub fn input1_verifier<C: AbstractChannel + Clone>(
        &mut self,
        ev: Witness<impl EqualityProposition<Verifier, P>>,
        channel: &mut C,
        rng: &mut SwankyRng,
    ) -> Result<Mac<P, V, T>> {
        debug!("input1");
        let r = self.random(channel, rng)?;
        let y = channel
            .read_serializable::<V>()
            .wrap_err(ErrorKind::NetworkError, "Failed to read 'y'.")?;
        let out = Mac::new(
            PartyPrivateCopy::empty(ev),
            r.mac() - y * self.delta.into_inner(ev),
        );
        Ok(out)
    }

    /// Add a constant.
    #[inline]
    pub fn affine_add_cst(&self, cst: V, x: Mac<P, V, T>) -> Mac<P, V, T> {
        match P::WHICH {
            WhichParty::Prover(ev) => Mac::new(
                PartyPrivateCopy::new(cst + x.value().into_inner(ev)),
                x.mac(),
            ),
            WhichParty::Verifier(ev) => Mac::new(
                PartyPrivateCopy::empty(ev),
                x.mac() - cst * self.delta.into_inner(ev),
            ),
        }
    }

    /// Check that a batch of [`Mac`]s are zero.
    pub fn check_zero<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut SwankyRng,
        mac_batch: &[Mac<P, V, T>],
    ) -> Result<()> {
        debug!("check_zero");
        let seed = match P::WHICH {
            WhichParty::Prover(_) => channel
                .read_block()
                .wrap_err(ErrorKind::NetworkError, "Failed to read seed block.")?,
            WhichParty::Verifier(_) => {
                let seed = rng.random::<Block>();
                channel
                    .write_block(&seed)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write seed.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;
                seed
            }
        };
        let mut rng = SwankyRng::from_seed(seed);

        let b = match P::WHICH {
            WhichParty::Prover(ev) => {
                let mut m = T::ZERO;
                let mut b = true;
                for mac in mac_batch.iter() {
                    let chi = T::random(&mut rng);
                    m += chi * mac.mac();
                    b &= mac.value().into_inner(ev) == V::ZERO;
                }
                channel
                    .write_serializable::<T>(&m)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write 'm'.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;

                b
            }
            WhichParty::Verifier(_) => {
                let mut key_chi = T::ZERO;
                for key in mac_batch.iter() {
                    let chi = T::random(&mut rng);
                    key_chi += chi * key.mac();
                }
                let m = channel
                    .read_serializable::<T>()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read 'm'.")?;

                key_chi == m
            }
        };

        ensure!(b, ErrorKind::OtherError, "check zero failed");
        Ok(())
    }

    /// Open a batch of [`Mac`]s. Only verifiers write to `out`.
    pub fn open<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        batch: &[Mac<P, V, T>],
        out: &mut PartyPrivate<Verifier, P, &mut Vec<V>>,
    ) -> Result<()> {
        debug!("open");
        let mut hasher = blake3::Hasher::new();

        match P::WHICH {
            WhichParty::Prover(ev) => {
                for mac in batch.iter() {
                    channel
                        .write_serializable::<V>(&mac.value().into_inner(ev))
                        .wrap_err(ErrorKind::NetworkError, "Failed to write MAC.")?;
                    hasher.update(&mac.value().into_inner(ev).to_bytes());
                }
            }
            WhichParty::Verifier(ev) => {
                out.as_mut().into_inner(ev).clear();
                for _ in 0..batch.len() {
                    let x = channel
                        .read_serializable::<V>()
                        .wrap_err(ErrorKind::NetworkError, "Failed to read 'x'.")?;
                    out.as_mut().into_inner(ev).push(x);
                    hasher.update(&x.to_bytes());
                }
            }
        }

        let seed = Block::from(<[u8; 16]>::try_from(&hasher.finalize().as_bytes()[0..16]).unwrap());
        let mut rng = SwankyRng::from_seed(seed);

        match P::WHICH {
            WhichParty::Prover(_) => {
                let mut m = T::ZERO;
                for mac in batch.iter() {
                    let chi = T::random(&mut rng);
                    m += chi * mac.mac();
                }
                channel
                    .write_serializable::<T>(&m)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write 'm'.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;

                Ok(())
            }
            WhichParty::Verifier(ev) => {
                let mut key_chi = T::ZERO;
                let mut x_chi = T::ZERO;
                for (i, mac) in batch.iter().enumerate() {
                    let chi = T::random(&mut rng);

                    key_chi += chi * mac.mac();
                    x_chi += out.as_ref().into_inner(ev)[i] * chi;
                }
                let m = channel
                    .read_serializable::<T>()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read 'm'.")?;

                assert_eq!(out.as_ref().into_inner(ev).len(), batch.len());
                if key_chi + self.delta.into_inner(ev) * x_chi == m {
                    Ok(())
                } else {
                    warn!("check_zero fails");
                    bail!(ErrorKind::OtherError, "open fails")
                }
            }
        }
    }

    /// Quicksilver multiplication check.
    pub fn quicksilver_check_multiply<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut SwankyRng,
        triples: &[(Mac<P, V, T>, Mac<P, V, T>, Mac<P, V, T>)],
    ) -> Result<()> {
        match P::WHICH {
            WhichParty::Prover(ev) => {
                let mut sum_a0 = T::ZERO;
                let mut sum_a1 = T::ZERO;

                let chi = channel
                    .read_serializable()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read chi.")?;
                let mut chi_power = chi;

                for ((x, x_mac), (y, y_mac), (_, z_mac)) in triples
                    .iter()
                    .map(|(x, y, z)| (x.decompose(ev), y.decompose(ev), z.decompose(ev)))
                {
                    let a0 = x_mac * y_mac;
                    let a1 = y * x_mac + x * y_mac - z_mac;

                    sum_a0 += a0 * chi_power;
                    sum_a1 += a1 * chi_power;

                    chi_power *= chi;
                }

                let mut us = Array::<_, DegreeModulo<V, T>>::default();
                for u in us.iter_mut() {
                    *u = self.random(channel, rng)?;
                }
                let mask = Mac::lift(&us);

                let u = sum_a0 + mask.mac();
                let v = sum_a1 + mask.value().into_inner(ev);

                channel
                    .write_serializable(&u)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write 'u'.")?;
                channel
                    .write_serializable(&v)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write 'v'.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;

                Ok(())
            }
            WhichParty::Verifier(ev) => {
                let chi = T::random(rng);
                channel
                    .write_serializable::<T>(&chi)
                    .wrap_err(ErrorKind::NetworkError, "Failed to write chi.")?;
                channel
                    .flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;

                let mut sum_b = T::ZERO;
                let mut chi_power = chi;

                for (x, y, z) in triples.iter() {
                    let b = x.mac() * y.mac() + self.delta.into_inner(ev) * z.mac();

                    sum_b += b * chi_power;
                    chi_power *= chi;
                }

                let mut vs = Array::<_, DegreeModulo<V, T>>::default();
                for v in vs.iter_mut() {
                    *v = self.random(channel, rng)?;
                }
                let mask = Mac::lift(&vs);

                let u = channel
                    .read_serializable::<T>()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read 'u'.")?;
                let v = channel
                    .read_serializable::<T>()
                    .wrap_err(ErrorKind::NetworkError, "Failed to read 'v'.")?;

                let b_plus = sum_b + mask.mac();
                if b_plus == (u + (-self.delta.into_inner(ev)) * v) {
                    Ok(())
                } else {
                    bail!(
                        ErrorKind::OtherError,
                        "QuickSilver multiplication check failed."
                    )
                }
            }
        }
    }

    /// Finalize the multiplication check for a state.
    ///
    /// Return the number of triples checked.
    pub fn quicksilver_finalize<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut SwankyRng,
        state: &mut MultCheckState<P, V, T>,
    ) -> Result<usize> {
        debug!("FCom: quicksilver_finalize");

        state.finalize(self.gen_mask(channel, rng)?, channel, rng, self.delta)
    }

    /// Generate a random mask MAC over the tag field.
    pub fn gen_mask<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut SwankyRng,
    ) -> Result<Mac<P, T, T>> {
        let mut macs = Array::<_, DegreeModulo<V, T>>::default();
        for mac in macs.iter_mut() {
            *mac = self.random(channel, rng)?;
        }
        Ok(Mac::lift(&macs))
    }
}

#[cfg(test)]
mod tests {
    use super::{FCom, Mac};
    use crate::party::{Prover, Verifier};
    use crate::svole_thread::{SvoleAtomic, ThreadSvole};
    use crate::svole_trait::{Svole, SvoleT};
    use rand::SeedableRng;
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };
    use swanky_channel_legacy::{AbstractChannel, Channel, SyncChannel};
    use swanky_field::{FiniteField, IsSubFieldOf};
    use swanky_field_binary::{F2, F40b};
    use swanky_field_f61p::F61p;
    use swanky_party::{
        private::{PartyPrivate, PartyPrivateCopy},
        ty_eq::Witness,
    };
    use swanky_rng::SwankyRng;
    use swanky_svole_wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};

    fn test_fcom_random<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 100;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = SwankyRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FCom::<Prover, V, T, Svole<_, _, _>>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(fcom.random(&mut channel, &mut rng).unwrap());
            }
            fcom.open(
                &mut channel,
                &v,
                &mut PartyPrivate::empty(Witness::EQUAL_TYPES),
            )
            .unwrap();
            v
        });
        let mut rng = SwankyRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FCom::<Verifier, V, T, Svole<_, _, _>>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            v.push(fcom.random(&mut channel, &mut rng).unwrap());
        }

        let mut r = PartyPrivate::new(Vec::new());
        fcom.open(&mut channel, &v, &mut r.as_mut()).unwrap();

        let resprover = handle.join().unwrap();

        for (i, res) in resprover.iter().enumerate() {
            assert_eq!(
                r.as_ref().into_inner(Witness::EQUAL_TYPES)[i],
                res.value().into_inner(Witness::EQUAL_TYPES)
            );
        }
    }

    fn test_fcom_affine<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 200;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = SwankyRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FCom::<Prover, V, T, Svole<_, _, _>>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let x = fcom.random(&mut channel, &mut rng).unwrap();
                let cst = V::random(&mut rng);
                channel.write_serializable::<V>(&cst).unwrap();
                channel.flush().unwrap();
                let m = x * cst;
                v.push(m);
                let a = fcom.affine_add_cst(cst, x);
                v.push(a);
            }
            fcom.open(
                &mut channel,
                &v,
                &mut PartyPrivate::empty(Witness::EQUAL_TYPES),
            )
            .unwrap();
            v
        });
        let mut rng = SwankyRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FCom::<Verifier, V, T, Svole<_, _, _>>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();

        let mut v = Vec::new();
        for _ in 0..count {
            let x_mac = fcom.random(&mut channel, &mut rng).unwrap();
            let cst = channel.read_serializable::<V>().unwrap();
            let m_mac = x_mac * cst;
            v.push(m_mac);
            let a_mac = fcom.affine_add_cst(cst, x_mac);
            v.push(a_mac);
        }

        let mut r = PartyPrivate::new(Vec::new());
        fcom.open(&mut channel, &v, &mut r.as_mut()).unwrap();

        let batch_prover = handle.join().unwrap();

        for (i, res) in batch_prover.iter().enumerate() {
            assert_eq!(
                r.as_ref().into_inner(Witness::EQUAL_TYPES)[i],
                res.value().into_inner(Witness::EQUAL_TYPES)
            );
        }
    }

    fn test_fcom_multiplication<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = SwankyRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FCom::<Prover, V, T, Svole<_, _, _>>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let x = fcom.random(&mut channel, &mut rng).unwrap();
                let y = fcom.random(&mut channel, &mut rng).unwrap();
                let z = x.value().into_inner(Witness::EQUAL_TYPES)
                    * y.value().into_inner(Witness::EQUAL_TYPES);
                let z_mac = fcom
                    .input_prover(Witness::EQUAL_TYPES, &mut channel, &mut rng, &[z])
                    .unwrap()[0];
                v.push((x, y, Mac::new(PartyPrivateCopy::new(z), z_mac)));
            }
            channel.flush().unwrap();
            fcom.quicksilver_check_multiply(&mut channel, &mut rng, &v)
                .unwrap();
            v
        });
        let mut rng = SwankyRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FCom::<_, V, T, Svole<_, _, _>>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();

        let mut v = Vec::new();
        for _ in 0..count {
            let xmac = fcom.random(&mut channel, &mut rng).unwrap();
            let ymac = fcom.random(&mut channel, &mut rng).unwrap();
            let zmac = fcom
                .input_verifier(Witness::EQUAL_TYPES, &mut channel, &mut rng, 1)
                .unwrap()[0];
            v.push((xmac, ymac, zmac));
        }
        fcom.quicksilver_check_multiply(&mut channel, &mut rng, &v)
            .unwrap();

        handle.join().unwrap();
    }

    fn test_fcom_check_zero<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 50;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = SwankyRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut fcom = FCom::<Prover, V, T, Svole<_, _, _>>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )
            .unwrap();

            for n in 0..count {
                // ZEROs
                let mut v = Vec::new();
                for _ in 0..n {
                    let x = V::ZERO;
                    let xmac = fcom
                        .input1_prover(Witness::EQUAL_TYPES, &mut channel, &mut rng, x)
                        .unwrap();
                    v.push(Mac::new(PartyPrivateCopy::new(x), xmac));
                }
                channel.flush().unwrap();
                let r = fcom.check_zero(&mut channel, &mut rng, v.as_slice());
                assert!(r.is_ok());
            }

            for n in 1..count {
                // NON_ZERO
                let mut v = Vec::new();
                for _ in 0..n {
                    let x = V::random_nonzero(&mut rng);
                    let xmac = fcom
                        .input1_prover(Witness::EQUAL_TYPES, &mut channel, &mut rng, x)
                        .unwrap();
                    v.push(Mac::new(PartyPrivateCopy::new(x), xmac));
                }
                channel.flush().unwrap();
                let r = fcom.check_zero(&mut channel, &mut rng, v.as_slice());
                assert!(r.is_err());
            }
        });
        let mut rng = SwankyRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut fcom = FCom::<Verifier, V, T, Svole<_, _, _>>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )
        .unwrap();

        for n in 0..count {
            // ZEROs
            let mut v = Vec::new();
            for _ in 0..n {
                let xmac = fcom
                    .input1_verifier(Witness::EQUAL_TYPES, &mut channel, &mut rng)
                    .unwrap();
                v.push(xmac);
            }
            let r = fcom.check_zero(&mut channel, &mut rng, &v);
            assert!(r.is_ok());
        }

        for n in 1..count {
            // non ZERO
            let mut v = Vec::new();
            for _ in 0..n {
                let xmac = fcom
                    .input1_verifier(Witness::EQUAL_TYPES, &mut channel, &mut rng)
                    .unwrap();
                v.push(xmac);
            }
            let r = fcom.check_zero(&mut channel, &mut rng, &v);
            assert!(r.is_err());
        }

        handle.join().unwrap();
    }

    fn test_fcom_multiplication_multithreaded<V: IsSubFieldOf<T>, T: FiniteField>()
    where
        T::PrimeField: IsSubFieldOf<V>,
    {
        let count = 50;
        let (sender_vole, receiver_vole) = UnixStream::pair().unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();

        let handle = std::thread::spawn(move || {
            let mut rng = SwankyRng::from_seed(Default::default());
            let reader = BufReader::new(sender_vole.try_clone().unwrap());
            let writer = BufWriter::new(sender_vole);
            let mut channel_vole = SyncChannel::new(reader, writer);

            let svole_atomic = SvoleAtomic::<Prover, V, T>::create();
            let svole_atomic2 = svole_atomic.duplicate();

            let _svole_thread = std::thread::spawn(move || {
                let mut svole_prover = ThreadSvole::init(
                    &mut channel_vole,
                    &mut rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                    svole_atomic2,
                    None,
                )
                .unwrap();
                svole_prover.run(&mut channel_vole, &mut rng).unwrap();
            });

            let mut rng = SwankyRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut fcom =
                FCom::<Prover, V, T, SvoleAtomic<_, _, _>>::init_with_vole(svole_atomic).unwrap();

            let mut v = Vec::new();
            for _ in 0..count {
                let x = fcom.random(&mut channel, &mut rng).unwrap();
                let y = fcom.random(&mut channel, &mut rng).unwrap();
                let z = x.value().into_inner(Witness::EQUAL_TYPES)
                    * y.value().into_inner(Witness::EQUAL_TYPES);
                let z_mac = fcom
                    .input_prover(Witness::EQUAL_TYPES, &mut channel, &mut rng, &[z])
                    .unwrap()[0];
                v.push((x, y, Mac::new(PartyPrivateCopy::new(z), z_mac)));
            }
            channel.flush().unwrap();
            fcom.quicksilver_check_multiply(&mut channel, &mut rng, &v)
                .unwrap();
            v
        });
        let mut rng = SwankyRng::from_seed(Default::default());
        let reader = BufReader::new(receiver_vole.try_clone().unwrap());
        let writer = BufWriter::new(receiver_vole);
        let mut channel_vole = SyncChannel::new(reader, writer);

        let svole_atomic = SvoleAtomic::create();
        let svole_atomic2 = svole_atomic.duplicate();

        let _svole_thread = std::thread::spawn(move || {
            let mut svole_receiver = ThreadSvole::init(
                &mut channel_vole,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                svole_atomic2,
                None,
            )
            .unwrap();
            svole_receiver.run(&mut channel_vole, &mut rng).unwrap();
        });

        let mut rng = SwankyRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut fcom =
            FCom::<Verifier, V, T, SvoleAtomic<_, _, _>>::init_with_vole(svole_atomic).unwrap();

        let mut v = Vec::new();
        for _ in 0..count {
            let xmac = fcom.random(&mut channel, &mut rng).unwrap();
            let ymac = fcom.random(&mut channel, &mut rng).unwrap();
            let zmac = fcom
                .input_verifier(Witness::EQUAL_TYPES, &mut channel, &mut rng, 1)
                .unwrap()[0];
            v.push((xmac, ymac, zmac));
        }
        fcom.quicksilver_check_multiply(&mut channel, &mut rng, &v)
            .unwrap();

        handle.join().unwrap();
    }

    #[test]
    fn test_fcom_f61p() {
        test_fcom_random::<F61p, F61p>();
        test_fcom_affine::<F61p, F61p>();
        test_fcom_multiplication::<F61p, F61p>();
        test_fcom_check_zero::<F61p, F61p>();
    }

    #[test]
    fn test_fcom_f2_f40b() {
        test_fcom_random::<F2, F40b>();
        test_fcom_affine::<F2, F40b>();
        test_fcom_multiplication::<F2, F40b>();
        test_fcom_check_zero::<F2, F40b>();
    }

    #[test]
    fn test_fcom_f40b_f40b() {
        test_fcom_random::<F40b, F40b>();
        test_fcom_affine::<F40b, F40b>();
        test_fcom_multiplication::<F40b, F40b>();
        test_fcom_check_zero::<F40b, F40b>();
    }

    #[test]
    fn test_fcom_singlethread_multiplication() {
        test_fcom_multiplication::<F61p, F61p>();
    }

    #[test]
    fn test_fcom_multithreaded() {
        test_fcom_multiplication_multithreaded::<F61p, F61p>();
    }
}
