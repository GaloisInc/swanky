use std::{collections::hash_map::Entry, iter, marker::PhantomData};

use rustc_hash::FxHashMap;

use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr, ensure};
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::private::{PartyPrivate, PartyPrivateCopy};

use crate::{
    DietMacAndCheese,
    backend_trait::BackendT,
    dora::perm::permutation,
    mac::Mac,
    party::{Party, Prover, WhichParty},
    ram::collapse_vec,
    svole_trait::SvoleT,
    transcript::Transcript,
};

use super::MemorySpace;

/// The Dora RAM protocol state.
///
/// Values of this type represent RAMs in the Dora protocol. Rather than the
/// usual read/write interface to memory, `DoraRam` exposes the operations
/// required by the protocol: `remove`, `insert`, and a `finalize` method to
/// execute the final stages of the protocol (after all operations on the RAM
/// are complete.)
///
/// This is a low-level representation of RAM, generalized over the party,
/// address/value type, and representation of 'actual' RAM cells. See the
/// module-level documentation for structures providing convenient
/// instantiations exposing the more familiar read/write interface.
///
/// The actual RAM is private to the prover, and is represented as a map from
/// addresses (given as arrays of value-field elements) to values+challenges
/// (also given as arrays of value-field elements). For a given `DoraRam`, a
/// single read or write is given by a [`remove`] followed by an [`insert`].
/// The former is given as a commitment in the bag `rds`, the latter as a
/// commitment in the bag `wrs`. At the end of the protocol, a permutation check
/// is performed on `rds` and `wrs`.
///
/// This is a drastic over-simplification of the protocol; Dora is described in
/// detail here: https://eprint.iacr.org/2023/1749
pub struct DoraRam<
    P: Party,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    M: MemorySpace<V>,
    SVOLE: SvoleT<P, V, F>,
> where
    F::PrimeField: IsSubFieldOf<V>,
{
    init_value: Vec<Mac<P, V, F>>,
    challenge_size: usize,
    space: M,
    transcript: Transcript,
    memory: PartyPrivate<Prover, P, FxHashMap<Vec<V>, Vec<V>>>,
    rds: Vec<Vec<Mac<P, V, F>>>,
    wrs: Vec<Vec<Mac<P, V, F>>>,
    _ph: PhantomData<SVOLE>,
}

#[inline(always)]
fn commit_pub<P: Party, V: IsSubFieldOf<T>, T: FiniteField>(values: &[V]) -> Vec<Mac<P, V, T>>
where
    T::PrimeField: IsSubFieldOf<V>,
{
    values
        .iter()
        .map(|&x| Mac::new(PartyPrivateCopy::new(x), T::ZERO))
        .collect()
}

impl<P: Party, V: IsSubFieldOf<F>, F: FiniteField, M: MemorySpace<V>, SVOLE: SvoleT<P, V, F>>
    DoraRam<P, V, F, M, SVOLE>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    /// Create a new `DoraRam` using the Diet Mac'n'Cheese protocol, the initial
    /// memory value, the size of challenges, and the address space.
    pub fn new(mut init_value: Vec<Mac<P, V, F>>, challenge_size: usize, space: M) -> Self {
        // Extend the initial value with  challenge values
        // We pay a small price here for a very efficient copy when finalizing
        init_value.append(&mut commit_pub(&vec![V::default(); challenge_size]));
        debug_assert_eq!(init_value.len(), space.value_size() + challenge_size);

        Self {
            init_value,
            challenge_size,
            space,
            transcript: Transcript::new(),
            memory: Default::default(),
            rds: vec![],
            wrs: vec![],
            _ph: PhantomData,
        }
    }

    /// Read, remove, and return the value at `addr` in the underlying memory
    /// space, adding this read to the bag `rds`.
    ///
    /// This must always be called before [`insert`] for a given `addr`.
    pub fn remove(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, SVOLE>,
        addr: &[Mac<P, V, F>],
        channel: &mut Channel,
    ) -> Result<Vec<Mac<P, V, F>>> {
        ensure!(
            addr.len() == self.space.addr_size(),
            ErrorKind::OtherError,
            "Address should be {} elements, but got {}.",
            self.space.addr_size(),
            addr.len()
        );

        let stored_size = self.space.value_size() + self.challenge_size;
        let flattened_size = self.space.addr_size() + stored_size;

        let mut flat: Vec<Mac<P, V, F>> = Vec::with_capacity(flattened_size);

        match P::WHICH {
            WhichParty::Prover(ev) => {
                let val_addr: Vec<_> = addr.iter().map(|e| e.value().into_inner(ev)).collect();
                let old = self
                    .memory
                    .as_mut()
                    .into_inner(ev)
                    .remove(&val_addr)
                    .unwrap_or_else(|| {
                        self.init_value
                            .iter()
                            .map(|v| v.value().into_inner(ev))
                            .collect()
                    });

                let macs = dmc.fcom.input_prover_with_transcript(
                    ev,
                    channel,
                    &mut dmc.rng,
                    &old,
                    &mut self.transcript,
                )?;
                for elem in iter::empty().chain(addr.iter().copied()).chain(
                    old.into_iter()
                        .zip(macs)
                        .map(|(x, m)| Mac::new(PartyPrivateCopy::new(x), m)),
                ) {
                    flat.push(elem);
                }
            }
            WhichParty::Verifier(ev) => {
                let macs = dmc.fcom.input_verifier_with_transcript(
                    ev,
                    channel,
                    &mut dmc.rng,
                    stored_size,
                    &mut self.transcript,
                )?;
                for elem in iter::empty().chain(addr.iter().copied()).chain(macs) {
                    flat.push(elem);
                }
            }
        }

        self.rds.push(flat.clone());
        Ok(flat[self.space.addr_size()..self.space.addr_size() + self.space.value_size()].into())
    }

    /// Write `value` to `addr` in the underlying memory space, adding this
    /// write to the bag `wrs`.
    ///
    /// For a given `addr`, it is an error to call this method without first
    /// calling [`remove`].
    pub fn insert(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, SVOLE>,
        addr: &[Mac<P, V, F>],
        value: &[Mac<P, V, F>],
    ) -> Result<()> {
        ensure!(
            addr.len() == self.space.addr_size(),
            ErrorKind::OtherError,
            "Address should be {} elements, but got {}.",
            self.space.addr_size(),
            addr.len()
        );
        ensure!(
            value.len() == self.space.value_size(),
            ErrorKind::OtherError,
            "Value should be {} elements, but got {}.",
            self.space.value_size(),
            value.len()
        );

        let mut flat = Vec::with_capacity(
            self.space.addr_size() + self.space.value_size() + self.challenge_size,
        );

        match P::WHICH {
            WhichParty::Prover(ev) => {
                let val_addr: Vec<_> = addr.iter().map(|e| e.value().into_inner(ev)).collect();
                match self.memory.as_mut().into_inner(ev).entry(val_addr) {
                    Entry::Occupied(_) => {
                        unreachable!("Must remove entry first: this is a logic error!")
                    }
                    Entry::Vacant(entry) => {
                        for elem in iter::empty()
                            .chain(addr.iter().copied())
                            .chain(value.iter().copied())
                            .chain(commit_pub(&self.transcript.challenges(self.challenge_size)))
                        {
                            flat.push(elem);
                        }

                        entry.insert(
                            flat[self.space.addr_size()..]
                                .iter()
                                .map(|m| m.value().into_inner(ev))
                                .collect(),
                        );
                    }
                }
            }
            WhichParty::Verifier(_) => {
                for elem in iter::empty()
                    .chain(addr.iter().copied())
                    .chain(value.iter().copied())
                    .chain(
                        self.transcript
                            .challenges(self.challenge_size)
                            .iter()
                            .map(|&x| dmc.input_public(x).unwrap()),
                    )
                {
                    flat.push(elem);
                }
            }
        }

        self.wrs.push(flat);
        Ok(())
    }

    /// Finalize the RAM protocol (check that `rds` is a permutation of `wrs`).
    pub fn finalize(
        mut self,
        dmc: &mut DietMacAndCheese<P, V, F, SVOLE>,
        channel: &mut Channel,
    ) -> Result<()> {
        log::info!("finalizing ram: {} operations", self.wrs.len(),);

        let flattened_size = self.space.addr_size() + self.space.value_size() + self.challenge_size;
        let mut pre = match P::WHICH {
            WhichParty::Prover(_) => {
                let mut pre = commit_pub::<P, _, _>(&vec![V::default(); flattened_size]);
                pre[self.space.addr_size()..].copy_from_slice(&self.init_value);
                debug_assert_eq!(pre.len(), flattened_size);
                pre
            }
            WhichParty::Verifier(_) => {
                let mut pre: Vec<_> = vec![V::default(); flattened_size]
                    .into_iter()
                    .map(|x| dmc.input_public(x).unwrap())
                    .collect();
                pre[self.space.addr_size()..].copy_from_slice(&self.init_value);
                debug_assert_eq!(pre.len(), flattened_size);
                pre
            }
        };

        for addr in self.space.enumerate() {
            let addr = match P::WHICH {
                WhichParty::Prover(_) => commit_pub(addr.as_ref()),
                WhichParty::Verifier(_) => addr
                    .as_ref()
                    .iter()
                    .map(|&x| dmc.input_public(x).unwrap())
                    .collect(),
            };
            pre[..self.space.addr_size()].copy_from_slice(&addr);
            self.wrs.push(pre.clone());
            self.remove(dmc, &addr, channel)?;
        }

        debug_assert_eq!(self.rds.len(), self.wrs.len());

        let (chal_cmbn, chal_perm1) = match P::WHICH {
            WhichParty::Prover(_) => {
                channel
                    .force_flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;
                (channel.read::<V>()?, channel.read::<V>()?)
            }
            WhichParty::Verifier(_) => {
                let chals @ (chal_cmbn, chal_perm1) =
                    (V::random(&mut dmc.rng), V::random(&mut dmc.rng));

                channel.write(&chal_cmbn)?;
                channel.write(&chal_perm1)?;
                channel
                    .force_flush()
                    .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;

                chals
            }
        };

        log::debug!("collapse wrs");
        let wrs = collapse_vec(dmc, &self.wrs, chal_cmbn)?;

        log::debug!("collapse rds");
        let rds = collapse_vec(dmc, &self.rds, chal_cmbn)?;

        self.wrs.clear();
        self.wrs.shrink_to_fit();

        self.rds.clear();
        self.rds.shrink_to_fit();

        log::debug!("permutation check");
        permutation(dmc, chal_perm1, &wrs, &rds, channel)
    }
}
