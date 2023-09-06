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
//! compile-time benefits of the crate.
//!
//! Evidence is represented by the [`IsParty`] type, which expresses the
//! type relation "Party `P1` is the same as party `P2`". The only sound
//! instantiations of this type are given by the constants [`IS_PROVER`] and
//! [`IS_VERIFIER`], which are associated with the types [`Prover`] and
//! [`Verifier`] by the `Party` trait, closing the loop on reflecting the
//! type-level party equality at the value-level.
//!
//! We can leverage these evidence values to write party-specific functions
//! in a party-generic context.
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
//! `PartyEither`. Of course, if instead the behavior is verifier-specific, one
//! can use `IsParty<P, Verifier>` instead. There are many examples of this in
//! the API of `PartyEither`.
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

    /// Value-level representation of evidence that two [`Party`] are the same.
    ///
    /// By definition, the only sound instantiations of this type are
    /// `IsParty<Prover, Prover>` and `IsParty<Verifier, Verifier>`. These are
    /// provided as compile-time constants [`IS_PROVER`] and [`IS_VERIFIER`].
    ///
    /// In your own code, values of this type will show up in a few places:
    ///
    /// - As evidence when matching on [`Party::WHICH`]
    /// - As the type of an evidence parameter to party-specific functions
    ///
    /// The former enables the use of party-specific APIs, and the latter is
    /// how party-specific APIs are defined. In general, writing a function of
    /// the form:
    ///
    /// ```
    /// fn f_prover<P: Party>(ev: IsParty<P, Prover>, ...) -> ...
    /// ```
    ///
    /// makes it prover-specific, and dually the form:
    ///
    /// ```
    /// fn f_verifier<P: Party>(ev: IsParty<P, Verifier>, ...) -> ...
    /// ```
    ///
    /// makes it verifier-specific.
    ///
    /// ## Examples
    ///
    /// The variants of [`WhichParty`] distinguish parties at the value-level
    /// by name, but also carry value-level evidence of a type-level equality:
    ///
    /// ```
    /// match P::WHICH {
    ///     WhichParty::Prover(ev_p) => {
    ///         // ...
    ///     }
    ///     WhichParty::Verifier(ev_v) => {
    ///         // ...
    ///     }
    /// }
    /// ```
    ///
    /// `ev_p` in the first arm could be used to call a function of the
    /// following type. Trying to call the same function with `ev_v` would be a
    /// type error:
    ///
    /// ```
    /// fn prover_do_something<P: Party>(ev: IsParty<P, Prover>) { /* ... */ }
    /// ```
    #[derive(Clone, Copy)]
    pub struct IsParty<P1: Party, P2: Party>(PhantomData<(P1, P2)>);

    /// Value-level representation of the type equality `Prover ~ Prover`.
    pub const IS_PROVER: IsParty<Prover, Prover> = IsParty(PhantomData);

    /// Value-level representation of the type equality `Verifier ~ Verifier`.
    pub const IS_VERIFIER: IsParty<Verifier, Verifier> = IsParty(PhantomData);
}
use bytemuck::{Pod, Zeroable};
pub use is_party::{IsParty, IS_PROVER, IS_VERIFIER};

/// Distinguish between type-level parties, with evidence.
///
/// Values of this type should almost never be constructed explicitly. The
/// constant [`Party::WHICH`] exposes a value of this type for any `P: Party`
/// that allows for safe value-level inspection of the type `P`. The evidence
/// carried may be used to safely call party-specific functions/methods.
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
