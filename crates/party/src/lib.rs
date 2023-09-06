//! Support for types indexed by a _party_.
//!
//! The aim of this crate is code de-duplication in the context of multi-party
//! protocols. In particular, it introduces the [`Party`] trait and
//! [`either::PartyEither`] type, which may be used to build types and
//! functions that are generic over the party (while still maintaining the
//! ability to write party-specific code when necessary.) As a bonus, this
//! abstraction comes at no additional cost thanks to compile-time
//! specialization and some clever type-system tricks.
//!
//! NOTE: As of this writing, the crate is specifically intendeed for use in
//! a zero-knowledge context. The two parties are named [`Prover`] and
//! [`Verifier`], and the types exposed by the [`private`] module are named
//! accordingly. We are exploring generalizations of this that would allow, for
//! example, use in contexts where there are > 2 parties, with the ability to
//! specify the names of those parties.
//!
//! As a contrived example of usage, consider the following types:
//!
//! ```
//! struct ProverSpecificData;
//! struct VerifierSpecificData;
//! ```
//!
//! Using `Party` and `PartyEither`, we can then define a structure that
//! contains data common to both parties, _plus_ a field that is either a
//! `ProverSpecificData` or `VerifierSpecificData`, depending on context:
//!
//! ```
//! struct Info<P: Party> {
//!     // ... other fields common to both parties ...
//!
//!     // A field that is `ProverSpecificData` when `P ~ Prover`, and
//!     // `VerifierSpecificData` when `P ~ Verifier`. The `PartyEither` type
//!     // incurs no additional memory cost.
//!     party_specific_data: PartyEither<P, ProverSpecificData, VerifierSpecificData>,
//! }
//! ```
//!
//! The [`either`] module defines the `PartyEither` type and goes into more
//! detail on the API it provides.
//!
//! We can similarly define functions that are generic over a party:
//!
//! ```
//! fn do_something<P: Party>(info: Info<P>) { /* ... */ }
//! ```
//!
//! If part of the function definition is party-specific, we can inspect
//! [`Party::WHICH`]:
//!
//! ```
//! match P::WHICH {
//!     WhichParty::Prover(e) => { /* ... */ }
//!     WhichParty::Verifier(e) => { /* ... */ }
//! }
//! ```
//!
//! The `e` values here are _evidence_ that `P` is indeed the party named by
//! the [`WhichParty`] variant. These values are at the heart of the
//! compile-time benefits of the crate, and may indeed be useful in your own
//! code (besides their required use in the `either` and `private` modules.)
//! For this reason, evidence is exposed via the [`IsParty`] type and its
//! associated constants [`IS_PROVER`] and [`IS_VERIFIER`].
//!
//! Suppose that we know `do_something` in the example above is actually
//! specific to provers. We can change its type to:
//!
//! ```
//! fn do_something<P: Party>(info: Info<P>, ev: IsParty<P, Prover>)
//! ```
//!
//! The value `ev` can be used to invoke prover-specific functionality, such as
//! safely casting to the underlying type associated with `Prover` via
//! `PartyEither`.
//!
//! Since this library was intended for use specifically in zero-knowledge
//! contexts, the `private` module exposes the types [`private::ProverPrivate`]
//! and [`private::ProverPrivateCopy`], which describe (as the names suggest)
//! values that only meaningfully exist from the prover's point of view (e.g.
//! the witness the prover is trying to prove knowledge of.) See the module
//! documentation for further details.

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
