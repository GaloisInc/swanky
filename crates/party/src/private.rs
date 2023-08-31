use super::either::*;
use super::*;

#[derive(Debug, Clone, Copy)]
pub struct UnknownProverSecret;

macro_rules! make_prover_private_type {
    ($ProverPrivate:ident $PartyEither:ident $(: $Copy:ident)?) => {
        #[derive(Clone $(, $Copy)?)]
        pub struct $ProverPrivate<P: Party, T $(: $Copy)?>($PartyEither<P, T, UnknownProverSecret>);
        impl<P: Party, T $(: $Copy)?> $ProverPrivate<P, T> {
            pub fn empty(e: IsParty<P, Verifier>) -> Self {
                Self($PartyEither::verifier_new(e, UnknownProverSecret))
            }
            pub fn new(t: T) -> Self {
                match P::WHICH {
                    WhichParty::Prover(e) => Self($PartyEither::prover_new(e, t)),
                    WhichParty::Verifier(e) => Self::empty(e),
                }
            }
            pub fn into_inner(self, e: IsParty<P, Prover>) -> T {
                self.0.prover_into(e)
            }
            pub fn as_ref(&self) -> $ProverPrivate<P, &T> {
                match P::WHICH {
                    WhichParty::Prover(e) => $ProverPrivate::new(self.0.as_ref().prover_into(e)),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                }
            }
            pub fn as_mut(&mut self) -> ProverPrivate<P, &mut T> {
                match P::WHICH {
                    WhichParty::Prover(e) => ProverPrivate::new(self.0.as_mut().prover_into(e)),
                    WhichParty::Verifier(e) => ProverPrivate::empty(e),
                }
            }
            pub fn zip<U$(: $Copy)?>(self, other: $ProverPrivate<P, U>) -> $ProverPrivate<P, (T, U)> {
                match P::WHICH {
                    WhichParty::Prover(e) =>
                        $ProverPrivate::new((self.into_inner(e), other.into_inner(e))),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                }
            }
            pub fn map<U$(: $Copy)?, F: FnOnce(T) -> U>(self, f: F) -> $ProverPrivate<P, U> {
                match P::WHICH {
                    WhichParty::Prover(e) =>
                        $ProverPrivate::new(f(self.into_inner(e))),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                }
            }
            pub fn and_then<U$(: $Copy)?, F: FnOnce(T) -> $ProverPrivate<P, U>>(self, f: F) -> $ProverPrivate<P, U> {
                match P::WHICH {
                    WhichParty::Prover(e) =>
                        f(self.into_inner(e)),
                    WhichParty::Verifier(e) => $ProverPrivate::empty(e),
                }
            }
            pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
                match P::WHICH {
                    WhichParty::Prover(e) => self.into_inner(e),
                    WhichParty::Verifier(_) => f(),
                }
            }
        }
        impl<P: Party, T $(: $Copy)?, U $(: $Copy)?> $ProverPrivate<P, (T, U)> {
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
