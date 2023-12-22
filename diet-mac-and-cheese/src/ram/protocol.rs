use rustc_hash::FxHashMap;

use scuttlebutt::AbstractChannel;
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::{private::ProverPrivate, Party};

use crate::mac::Mac;

use super::{tx::TxChannel, MemorySpace};

pub struct DoraRam<
    P: Party,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    C: AbstractChannel,
    M: MemorySpace<V>,
> where
    F::PrimeField: IsSubFieldOf<V>,
{
    space: M,
    ch: TxChannel<C>,
    memory: ProverPrivate<P, FxHashMap<Vec<V>, Vec<V>>>,
    rds: Vec<Vec<Mac<P, V, F>>>,
    wrs: Vec<Vec<Mac<P, V, F>>>,
}
