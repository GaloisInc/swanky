use std::marker::PhantomData;

use rustc_hash::FxHashMap;

use scuttlebutt::AbstractChannel;
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::{private::ProverPrivate, Party};

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
    pub fn new(dmc: &mut DietMacAndCheese<P, V, F, C, SVOLE>, space: M) -> Self {
        Self {
            space,
            ch: TxChannel::new(dmc.channel.clone(), Default::default()),
            memory: Default::default(),
            rds: Vec::with_capacity(PRE_ALLOC_MEM + PRE_ALLOC_STEPS),
            wrs: Vec::with_capacity(PRE_ALLOC_MEM + PRE_ALLOC_STEPS),
            _ph: PhantomData,
        }
    }
}
