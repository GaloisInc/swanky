use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

mod is_party {
    use super::*;
    #[derive(Clone, Copy)]
    pub struct IsParty<P1: Party, P2: Party>(PhantomData<(P1, P2)>);
    pub const IS_PROVER: IsParty<Prover, Prover> = IsParty(PhantomData);
    pub const IS_VERIFIER: IsParty<Verifier, Verifier> = IsParty(PhantomData);
}
use bytemuck::{Pod, Zeroable};
pub use is_party::{IsParty, IS_PROVER, IS_VERIFIER};

#[derive(Clone, Copy)]
pub enum WhichParty<P: Party> {
    Prover(IsParty<P, Prover>),
    Verifier(IsParty<P, Verifier>),
}

/// # Safety
/// `WHICH` must be accurate.
pub unsafe trait Party:
    'static
    + Clone
    + Copy
    + Send
    + Sync
    + Default
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Debug
    + Hash
    + Sized
    + Pod
    + Zeroable
    + either::internal::PartyEitherInternal
{
    const WHICH: WhichParty<Self>;
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default, Pod, Zeroable)]
pub struct Prover(());

unsafe impl Party for Prover {
    const WHICH: WhichParty<Self> = WhichParty::Prover(is_party::IS_PROVER);
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default, Pod, Zeroable)]
pub struct Verifier(());
unsafe impl Party for Verifier {
    const WHICH: WhichParty<Self> = WhichParty::Verifier(is_party::IS_VERIFIER);
}

pub mod either;
pub mod private;
