//! Support for types indexed by a _party_.
//!
//! The aim of this crate is code de-duplication in the context of multi-party
//! protocols. In particular, it introduces the `Party` trait and `PartyEither`
//! type, which may be used to distinguish data/code specific to the particular
//! parties.
//!
//! NOTE: As of this writing, the crate is specifically intendeed for use in
//! a zero-knowledge context. The two parties are named [`Prover`] and
//! [`Verifier`], and the types exposed by the [`private`] module are named
//! accordingly for the specific context in which the `Prover` party has
//! access to privileged information. We are exploring generalizations of this
//! that would allow, for example, use in contexts where there are > 2 parties
//! (and more control over naming.)
//!
//! As a brief example of usage, consider the following types:
//!
//! ```
//! struct ProverSpecificData;
//! struct VerifierSpecificData;
//! ```
//!
//! Using `Party` and `PartyEither`, we can then define a structure that
//! contains all of the common data, _plus_ a field that is either a
//! `ProverSpecificData` or `VerifierSpecificData` depending on context:
//!
//! ```
//! struct Info<P: Party> {
//!     // ... other fields common to both parties ...
//!     party_specific_data: PartyEither<P, ProverSpecificData, VerifierSpecificData>,
//! }
//!
//! We can make party-specific decisions at any time by inspecting `P::WHICH`:
//!
//! ```
//! match P::WHICH {
//!     WhichParty::Prover(e) => ...,
//!     WhichParty::Verifier(e) => ...,
//! }
//! ```
//!
//! The `e` values are evidence used to maintain type-safety: Prover code that
//! attempts to access verifier-only data (and vice-versa) will not compile.
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
