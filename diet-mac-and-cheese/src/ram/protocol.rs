use std::{collections::hash_map::Entry, iter, marker::PhantomData};

use rustc_hash::FxHashMap;

use scuttlebutt::AbstractChannel;
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::{
    private::{ProverPrivate, ProverPrivateCopy},
    Party, WhichParty,
};

use crate::{
    backend_trait::BackendT,
    mac::Mac,
    ram::{collapse_vec, perm::permutation},
    svole_trait::SvoleT,
    DietMacAndCheese,
};

use super::{tx::TxChannel, MemorySpace, PRE_ALLOC_MEM, PRE_ALLOC_STEPS};

pub struct DoraRam<
    P: Party,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    C: AbstractChannel + Clone,
    M: MemorySpace<V>,
    SVOLE: SvoleT<P, V, F>,
> where
    F::PrimeField: IsSubFieldOf<V>,
{
    challenge_size: usize,
    space: M,
    ch: TxChannel<C>,
    memory: ProverPrivate<P, FxHashMap<Vec<V>, Vec<V>>>,
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
        .map(|&x| Mac::new(ProverPrivateCopy::new(x), T::ZERO))
        .collect()
}

impl<
        P: Party,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel + Clone,
        M: MemorySpace<V>,
        SVOLE: SvoleT<P, V, F>,
    > DoraRam<P, V, F, C, M, SVOLE>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn new(
        dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>,
        challenge_size: usize,
        space: M,
    ) -> Self {
        Self {
            challenge_size,
            space,
            ch: TxChannel::new(dmc.channel.clone(), Default::default()),
            memory: Default::default(),
            rds: Vec::with_capacity(PRE_ALLOC_MEM + PRE_ALLOC_STEPS),
            wrs: Vec::with_capacity(PRE_ALLOC_MEM + PRE_ALLOC_STEPS),
            _ph: PhantomData,
        }
    }

    pub fn remove(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>,
        addr: &[Mac<P, V, F>],
    ) -> eyre::Result<Vec<Mac<P, V, F>>> {
        debug_assert_eq!(addr.len(), self.space.addr_size());

        let mut flat: Vec<Mac<P, V, F>> = Vec::with_capacity(
            self.space.addr_size() + self.space.value_size() + self.challenge_size,
        );

        match P::WHICH {
            WhichParty::Prover(ev) => {
                let val_addr: Vec<_> = addr.iter().map(|e| e.value().into_inner(ev)).collect();
                let old = self
                    .memory
                    .as_mut()
                    .into_inner(ev)
                    .remove(&val_addr)
                    .unwrap_or(vec![
                        V::default();
                        self.space.value_size() + self.challenge_size
                    ]);

                for elem in iter::empty()
                    .chain(addr.iter().copied())
                    .chain(old.into_iter().map(|x| {
                        let m = dmc
                            .fcom
                            .input1_prover(ev, &mut self.ch, &mut dmc.rng, x)
                            .unwrap();
                        Mac::new(ProverPrivateCopy::new(x), m)
                    }))
                {
                    flat.push(elem);
                }
            }
            WhichParty::Verifier(ev) => {
                for elem in iter::empty().chain(addr.iter().copied()).chain(
                    dmc.fcom
                        .input_verifier(
                            ev,
                            &mut self.ch,
                            &mut dmc.rng,
                            self.space.value_size() + self.challenge_size,
                        )
                        .unwrap(),
                ) {
                    flat.push(elem);
                }
            }
        }

        self.rds.push(flat.clone());
        Ok(flat[self.space.addr_size()..self.space.addr_size() + self.space.value_size()].into())
    }

    pub fn insert(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>,
        addr: &[Mac<P, V, F>],
        value: &[Mac<P, V, F>],
    ) -> eyre::Result<()> {
        debug_assert_eq!(addr.len(), self.space.addr_size());
        debug_assert_eq!(value.len(), self.space.value_size());

        let mut flat = Vec::with_capacity(
            self.space.addr_size() + self.space.value_size() + self.challenge_size,
        );

        match P::WHICH {
            WhichParty::Prover(ev) => {
                let val_addr: Vec<_> = addr.iter().map(|e| e.value().into_inner(ev)).collect();
                match self.memory.as_mut().into_inner(ev).entry(val_addr) {
                    Entry::Occupied(_) => {
                        unreachable!("double entry, must remove entry first: this is a logic error")
                    }
                    Entry::Vacant(entry) => {
                        for elem in iter::empty()
                            .chain(addr.iter().copied())
                            .chain(value.iter().copied())
                            .chain(commit_pub(&self.ch.challenge(self.challenge_size)))
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
                        self.ch
                            .challenge(self.challenge_size)
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

    pub fn finalize(mut self, dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>) -> eyre::Result<()> {
        log::info!("finalizing ram: {} operations", self.wrs.len(),);

        let mut pre = match P::WHICH {
            WhichParty::Prover(_) => commit_pub::<P, _, _>(&vec![
                V::default();
                self.space.addr_size()
                    + self.space.value_size()
                    + self.challenge_size
            ]),
            WhichParty::Verifier(_) => {
                vec![
                    V::default();
                    self.space.addr_size() + self.space.value_size() + self.challenge_size
                ]
                .into_iter()
                .map(|x| dmc.input_public(x).unwrap())
                .collect()
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
            self.remove(dmc, &addr)?;
        }

        debug_assert_eq!(self.rds.len(), self.wrs.len());

        let (chal_cmbn, chal_perm1) = match P::WHICH {
            WhichParty::Prover(_) => {
                dmc.channel.flush()?;
                (
                    dmc.channel.read_serializable::<V>()?,
                    dmc.channel.read_serializable::<V>()?,
                )
            }
            WhichParty::Verifier(_) => {
                let chals @ (chal_cmbn, chal_perm1) =
                    (V::random(&mut dmc.rng), V::random(&mut dmc.rng));

                dmc.channel.write_serializable(&chal_cmbn)?;
                dmc.channel.write_serializable(&chal_perm1)?;
                dmc.channel.flush()?;

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
        permutation(dmc, chal_perm1, &wrs, &rds)
    }
}
