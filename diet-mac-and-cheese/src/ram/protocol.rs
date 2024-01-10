use std::{iter, marker::PhantomData};

use rustc_hash::FxHashMap;

use scuttlebutt::AbstractChannel;
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::{
    private::{ProverPrivate, ProverPrivateCopy},
    Party, WhichParty,
};

use crate::{mac::Mac, svole_trait::SvoleT, DietMacAndCheese};

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
                    .unwrap_or_else(|| {
                        vec![V::default(); self.space.value_size() + self.challenge_size]
                    });

                for (i, elem) in iter::empty()
                    .chain(addr.iter().copied())
                    .chain(old.into_iter().map(|x| {
                        let m = dmc
                            .fcom
                            .input1_prover(ev, &mut self.ch, &mut dmc.rng, x)
                            .unwrap();
                        Mac::new(ProverPrivateCopy::new(x), m)
                    }))
                    .enumerate()
                {
                    flat[i] = elem;
                }
            }
            WhichParty::Verifier(ev) => {
                for (i, elem) in iter::empty()
                    .chain(
                        dmc.fcom
                            .input_verifier(
                                ev,
                                &mut self.ch,
                                &mut dmc.rng,
                                self.space.value_size() + self.challenge_size,
                            )
                            .unwrap(),
                    )
                    .enumerate()
                {
                    flat[i] = elem;
                }
            }
        }

        self.rds.push(flat.clone());
        Ok(
            flat[self.space.addr_size()..self.space.addr_size() + self.space.value_size()]
                .try_into()
                .unwrap(),
        )
    }
}
