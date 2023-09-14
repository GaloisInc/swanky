//! Zero-cost representation of party-private data.
//!
//! It is often the case that in a multi-party protocol, one of the two parties
//! has access to information that the other does not.
//!
//! This module implements the [`ProverPrivate`] and [`VerifierPrivate`] types,
//! specializations of [`PartyEither`] for this case of privileged information.
//!
//! Note that because these types are symmetric, we focus on `ProverPrivate`
//! in the following examples.
//!
//! The type `ProverPrivate<P: Party, T>` collapses to `T` when `P` is `Prover`
//! and a unit/"do nothing" type when `P` is `Verifier`. Like with
//! `PartyEither`, we provide a separate `ProverPrivateCopy<P: Party, T: Copy>`
//! with the same API (and conveniences to convert between these types where
//! appropriate.)
//!
//! Using this type is straightforward:
//!
//! ```rust,ignore
//! // Some secrets only the prover knows
//! struct ProverSecrets;
//!
//! // A party-generic structure with access to secrets in the prover context
//! struct PartyManager<P: Party> {
//!     secrets: ProverPrivate<P, ProverSecrets>
//! }
//!
//! // Do something with the secrets if they're available
//! fn foo<P: Party>(x: PartyManager<P>) {
//!     // ...
//!     x.secrets.map(|ps| /* ... ps is a ProverSecrets ... */)
//!     // ...
//! }
//! ```
//!
//! The API provides methods to combine/split party secrets, safely cast to
//! the inner type in known-party contexts, and operate in a "monadic chain"
//! of operations via `and_then` (analogous to the same method on e.g.
//! `Option`.) See the relevant method documentation for details.

use super::either::*;
use super::*;

#[derive(Debug, Clone, Copy)]
pub struct UnknownProverSecret;

macro_rules! make_prover_private_type {
    ($ProverPrivate:ident $PartyEither:ident $(: $Copy:ident)?) => {
        #[derive(Clone $(, $Copy)?)]
        pub struct $ProverPrivate<P: Party, T $(: $Copy)?>($PartyEither<P, T, UnknownProverSecret>);
        impl<P: Party, T $(: $Copy)?> $ProverPrivate<P, T> {
            /// Given evidence that `P = Verifier`, create an empty
            /// `ProverPrivate(Copy)` value.
            pub fn empty(e: IsParty<P, Verifier>) -> Self {
                Self($PartyEither::verifier_new(e, UnknownProverSecret))
            }

            /// Given a `T`, create a new `ProverPrivate(Copy)<P, T>`. This
            /// is equivalent to `ProverPrivate(Copy)::empty()` in verifier
            /// contexts.
            pub fn new(t: T) -> Self {
                match P::WHICH {
                    WhichParty::Prover(e) => Self($PartyEither::prover_new(e, t)),
                    WhichParty::Verifier(e) => Self::empty(e),
                }
            }

            /// Given evidence that `P = Prover`, cast to the underlying type.
            pub fn into_inner(self, e: IsParty<P, Prover>) -> T {
                self.0.prover_into(e)
            }

            /// Convert from `ProverPrivate(Copy)<P, T>` to
            /// `ProverPrivate(Copy)<P, &T>`.
            pub fn as_ref(&self) -> $ProverPrivate<P, &T> {
                match P::WHICH {
                    WhichParty::Prover(e) => $ProverPrivate::new(self.0.as_ref().prover_into(e)),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                }
            }

            /// Convert from `ProverPrivate(Copy)<P, T>` to
            /// `ProverPrivate(Copy)<P, &mut T>`.
            pub fn as_mut(&mut self) -> ProverPrivate<P, &mut T> {
                match P::WHICH {
                    WhichParty::Prover(e) => ProverPrivate::new(self.0.as_mut().prover_into(e)),
                    WhichParty::Verifier(e) => ProverPrivate::empty(e),
                }
            }

            /// Zip two `ProverPrivate(Copy)` in the natural way.
            pub fn zip<U$(: $Copy)?>(self, other: $ProverPrivate<P, U>) -> $ProverPrivate<P, (T, U)> {
                match P::WHICH {
                    WhichParty::Prover(e) =>
                        $ProverPrivate::new((self.into_inner(e), other.into_inner(e))),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                }
            }

            /// Given a function from the prover-private type, map over a
            /// `ProverPrivate(Copy)` in the natural way.
            ///
            /// Note that in verifier contexts, the function will never be
            /// called.
            pub fn map<U$(: $Copy)?, F: FnOnce(T) -> U>(self, f: F) -> $ProverPrivate<P, U> {
                match P::WHICH {
                    WhichParty::Prover(e) =>
                        $ProverPrivate::new(f(self.into_inner(e))),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                }
            }

            /// Return `ProverPrivate(Copy)::empty()` in a verifier context,
            /// otherwise call `f` on the prover-private value and return the
            /// result.
            ///
            /// This is analogous to `and_then` as defined on `Option`.
            pub fn and_then<U$(: $Copy)?, F: FnOnce(T) -> $ProverPrivate<P, U>>(self, f: F) -> $ProverPrivate<P, U> {
                match P::WHICH {
                    WhichParty::Prover(e) =>
                        f(self.into_inner(e)),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                }
            }

            /// Return the prover-private value, or compute it from the given
            /// closure (in a verifier context.)
            pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
                match P::WHICH {
                    WhichParty::Prover(e) => self.into_inner(e),
                    WhichParty::Verifier(_) => f(),
                }
            }
        }
        impl<P: Party, T $(: $Copy)?, U $(: $Copy)?> $ProverPrivate<P, (T, U)> {
            /// Convert a `ProverPrivate(Copy)<P, (T, U)>` to a
            /// `(ProverPrivate(Copy)<P, T>, ProverPrivate(Copy)<P, U>)`.
            pub fn unzip(self) -> ($ProverPrivate<P, T>, $ProverPrivate<P, U>) {
                match P::WHICH {
                    WhichParty::Prover(e) => {
                        let (a, b) = self.into_inner(e);
                        ($ProverPrivate::new(a), $ProverPrivate::new(b))
                    }
                    WhichParty::Verifier(e) => {
                        ($ProverPrivate::empty(e), $ProverPrivate::empty(e))
                    }
                }
            }
        }
        impl<P: Party, T: Default $(+ $Copy)?> Default for $ProverPrivate<P, T> {
            fn default() -> Self {
                match P::WHICH {
                    WhichParty::Prover(_) => Self::new(T::default()),
                    WhichParty::Verifier(e) => Self::empty(e),
                }
            }
        }
        impl<P: Party, T: std::fmt::Debug $(+ $Copy)?> std::fmt::Debug for $ProverPrivate<P, T> {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match P::WHICH {
                    WhichParty::Prover(e) => write!(f, "{:?}", self.as_ref().into_inner(e)),
                    WhichParty::Verifier(_) => write!(f, "ProverSecret"),
                }
            }
        }
        impl<P: Party, T $(: $Copy)?, E $(: $Copy)?> $ProverPrivate<P, Result<T, E>>
        {
            /// Convert a `ProverPrivate(Copy)<P, Result<T, E>>` to a
            /// `Result<ProverPrivate(Copy)<P, T>, E>` in the natural way.
            pub fn lift_result(self) -> Result<$ProverPrivate<P, T>, E> {
                Ok(match P::WHICH {
                    WhichParty::Prover(e) => $ProverPrivate::new(self.into_inner(e)?),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                })
            }
        }
    };
}
make_prover_private_type!(ProverPrivate PartyEither);
make_prover_private_type!(ProverPrivateCopy PartyEitherCopy: Copy);

impl<P: Party, T: Copy> From<ProverPrivate<P, T>> for ProverPrivateCopy<P, T> {
    fn from(x: ProverPrivate<P, T>) -> Self {
        Self(x.0.into())
    }
}
impl<P: Party, T: Copy> From<ProverPrivateCopy<P, T>> for ProverPrivate<P, T> {
    fn from(x: ProverPrivateCopy<P, T>) -> Self {
        Self(x.0.into())
    }
}
impl<P: Party, T: PartialEq> PartialEq for ProverPrivate<P, T> {
    fn eq(&self, other: &Self) -> bool {
        match P::WHICH {
            WhichParty::Prover(ev) => self.as_ref().into_inner(ev) == other.as_ref().into_inner(ev),
            WhichParty::Verifier(_) => true,
        }
    }
}

impl<P: Party, T: Copy + PartialEq> PartialEq for ProverPrivateCopy<P, T> {
    fn eq(&self, other: &Self) -> bool {
        match P::WHICH {
            WhichParty::Prover(ev) => self.into_inner(ev) == other.into_inner(ev),
            WhichParty::Verifier(_) => true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UnknownVerifierSecret;

macro_rules! make_verifier_private_type {
    ($VerifierPrivate:ident $PartyEither:ident $(: $Copy:ident)?) => {
        #[derive(Clone $(, $Copy)?)]
        pub struct $VerifierPrivate<P: Party, T $(: $Copy)?>($PartyEither<P, UnknownVerifierSecret, T>);
        impl<P: Party, T $(: $Copy)?> $VerifierPrivate<P, T> {
            /// Given evidence that `P = Prover`, create an empty
            /// `VerifierPrivate(Copy)` value.
            pub fn empty(e: IsParty<P, Prover>) -> Self {
                Self($PartyEither::prover_new(e, UnknownVerifierSecret))
            }

            /// Given a `T`, create a new `VerifierPrivate(Copy)<P, T>`. This
            /// is equivalent to `VerifierPrivate(Copy)::empty()` in prover
            /// contexts.
            pub fn new(t: T) -> Self {
                match P::WHICH {
                    WhichParty::Prover(e) => Self::empty(e),
                    WhichParty::Verifier(e) => Self($PartyEither::verifier_new(e, t)),
                }
            }

            /// Given evidence that `P = Verifier`, cast to the underlying
            /// type.
            pub fn into_inner(self, e: IsParty<P, Verifier>) -> T {
                self.0.verifier_into(e)
            }

            /// Convert from `ProverPrivate(Copy)<P, T>` to
            /// `ProverPrivate(Copy)<P, &T>`.
            pub fn as_ref(&self) -> $VerifierPrivate<P, &T> {
                match P::WHICH {
                    WhichParty::Prover(e) => $VerifierPrivate::empty(e),
                    WhichParty::Verifier(e) => $VerifierPrivate::new(self.0.as_ref().verifier_into(e)),
                }
            }

            /// Convert from `VerifierPrivate(Copy)<P, T>` to
            /// `VerifierPrivate<P, &mut T>`.
            pub fn as_mut(&mut self) -> VerifierPrivate<P, &mut T> {
                match P::WHICH {
                    WhichParty::Prover(e) => VerifierPrivate::empty(e),
                    WhichParty::Verifier(e) => VerifierPrivate::new(self.0.as_mut().verifier_into(e)),
                }
            }

            /// Zip two `VerifierPrivate(Copy)` in the natural way.
            pub fn zip<U$(: $Copy)?>(self, other: $VerifierPrivate<P, U>) -> $VerifierPrivate<P, (T, U)> {
                match P::WHICH {
                    WhichParty::Prover(e) => $VerifierPrivate::empty(e),
                    WhichParty::Verifier(e) =>
                        $VerifierPrivate::new((self.into_inner(e), other.into_inner(e))),
                }
            }

            /// Given a function from the verifier-private type, map over a
            /// `VerifierPrivate(Copy)` in the natural way.
            ///
            /// Note that in prover contexts, the function will never be
            /// called.
            pub fn map<U$(: $Copy)?, F: FnOnce(T) -> U>(self, f: F) -> $VerifierPrivate<P, U> {
                match P::WHICH {
                    WhichParty::Prover(e) => $VerifierPrivate::empty(e),
                    WhichParty::Verifier(e) =>
                        $VerifierPrivate::new(f(self.into_inner(e))),
                }
            }

            /// Return `VerifierPrivate(Copy)::empty()` in a prover context,
            /// otherwise call `f` on the verifier-private value and return the
            /// result.
            ///
            /// This is analogous to `and_then` as defined on `Option`.
            pub fn and_then<U$(: $Copy)?, F: FnOnce(T) -> $VerifierPrivate<P, U>>(self, f: F) -> $VerifierPrivate<P, U> {
                match P::WHICH {
                    WhichParty::Prover(e) => $VerifierPrivate::empty(e),
                    WhichParty::Verifier(e) =>
                        f(self.into_inner(e)),
                }
            }

            /// Return the verifier-private value, or compute it form the given
            /// closure (in a prover context).
            pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
                match P::WHICH {
                    WhichParty::Prover(_) => f(),
                    WhichParty::Verifier(e) => self.into_inner(e),
                }
            }
        }
        impl<P: Party, T $(: $Copy)?, U $(: $Copy)?> $VerifierPrivate<P, (T, U)> {
            /// Convert a `VerifierPrivate(Copy)<P, (T, U)>` to a
            /// `(VerifierPrivate(Copy)<P, T>, VerifierPrivate(Copy)<P, U>).
            pub fn unzip(self) -> ($VerifierPrivate<P, T>, $VerifierPrivate<P, U>) {
                match P::WHICH {
                    WhichParty::Prover(e) => {
                        ($VerifierPrivate::empty(e), $VerifierPrivate::empty(e))
                    }
                    WhichParty::Verifier(e) => {
                        let (a, b) = self.into_inner(e);
                        ($VerifierPrivate::new(a), $VerifierPrivate::new(b))
                    }
                }
            }
        }
        impl<P: Party, T: Default $(+ $Copy)?> Default for $VerifierPrivate<P, T> {
            fn default() -> Self {
                match P::WHICH {
                    WhichParty::Prover(e) => Self::empty(e),
                    WhichParty::Verifier(_) => Self::new(T::default()),
                }
            }
        }
        impl<P: Party, T $(: $Copy)?, E $(: $Copy)?> $VerifierPrivate<P, Result<T, E>>
        {
            /// Convert a `VerifierPrivate(Copy)<P, Result<T, E>>` to a
            /// `Result<VerifierPrivate(Copy)<P, T>, E>` in the natural way.
            pub fn lift_result(self) -> Result<$VerifierPrivate<P, T>, E> {
                Ok(match P::WHICH {
                    WhichParty::Prover(e) => $VerifierPrivate::empty(e),
                    WhichParty::Verifier(e) => $VerifierPrivate::new(self.into_inner(e)?),
                })
            }
        }
    };
}
make_verifier_private_type!(VerifierPrivate PartyEither);
make_verifier_private_type!(VerifierPrivateCopy PartyEitherCopy: Copy);

impl<P: Party, T: Copy> From<VerifierPrivate<P, T>> for VerifierPrivateCopy<P, T> {
    fn from(x: VerifierPrivate<P, T>) -> Self {
        Self(x.0.into())
    }
}
impl<P: Party, T: Copy> From<VerifierPrivateCopy<P, T>> for VerifierPrivate<P, T> {
    fn from(x: VerifierPrivateCopy<P, T>) -> Self {
        Self(x.0.into())
    }
}
