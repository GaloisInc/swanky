use bytemuck::{TransparentWrapper, Zeroable};
use mac_n_cheese_party as party;
use mac_n_cheese_party::either::PartyEitherCopy;
use mac_n_cheese_party::private::ProverPrivateCopy;
use mac_n_cheese_party::{IsParty, Party, Prover, Verifier, WhichParty};
use party::IS_PROVER;
use scuttlebutt::field::{FiniteField, IsSubFieldOf, SmallBinaryField, F2};
use scuttlebutt::ring::FiniteRing;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use crate::specialization::{FiniteFieldSpecialization, SmallBinaryFieldSpecialization};

pub type MacConstantContext<P, FE> = PartyEitherCopy<P, (), FE>;

pub trait MacTypes: 'static + Sized + Clone + Copy + Send + Sync {
    type VF: FiniteField + IsSubFieldOf<Self::TF>;
    type TF: FiniteField;
    type S: FiniteFieldSpecialization<Self::VF, Self::TF>;
}
impl<VF: FiniteField + IsSubFieldOf<TF>, TF: FiniteField, S: FiniteFieldSpecialization<VF, TF>>
    MacTypes for (VF, TF, S)
{
    type VF = VF;
    type TF = TF;
    type S = S;
}

// See https://github.com/rust-lang/rust/issues/104918
#[allow(type_alias_bounds)]
pub type SenderPairContents<T: MacTypes> =
    <<T as MacTypes>::S as FiniteFieldSpecialization<T::VF, T::TF>>::SenderPairContents;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Mac<P: Party, T: MacTypes> {
    contents: PartyEitherCopy<P, SenderPairContents<T>, T::TF>,
}
unsafe impl<P: Party, T: MacTypes>
    TransparentWrapper<PartyEitherCopy<P, SenderPairContents<T>, T::TF>> for Mac<P, T>
{
}
impl<P: Party, T: MacTypes> Mac<P, T> {
    pub fn cast_slice<P2: Party>(_e: IsParty<P, P2>, macs: &[Self]) -> &[Mac<P2, T>] {
        unsafe { std::slice::from_raw_parts(macs.as_ptr() as *const _, macs.len()) }
    }
    pub fn cast_slice_mut<P2: Party>(_e: IsParty<P, P2>, macs: &mut [Self]) -> &mut [Mac<P2, T>] {
        unsafe { std::slice::from_raw_parts_mut(macs.as_mut_ptr() as *mut _, macs.len()) }
    }
    pub fn zero() -> Self {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    PartyEitherCopy::prover_new(e, T::S::new_sender_pair(T::VF::ZERO, T::TF::ZERO))
                }
                WhichParty::Verifier(e) => PartyEitherCopy::verifier_new(e, T::TF::ZERO),
            },
        }
    }
    pub fn constant(ctx: &MacConstantContext<P, T::TF>, value: T::VF) -> Self {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    PartyEitherCopy::prover_new(e, T::S::new_sender_pair(value, T::TF::ZERO))
                }
                WhichParty::Verifier(e) => {
                    PartyEitherCopy::verifier_new(e, value * ctx.verifier_into(e))
                }
            },
        }
    }
    pub fn prover_new(e: IsParty<P, Prover>, x: T::VF, beta: T::TF) -> Self {
        Mac {
            contents: PartyEitherCopy::prover_new(e, T::S::new_sender_pair(x, beta)),
        }
    }
    pub fn verifier_new(e: IsParty<P, Verifier>, tag: T::TF) -> Self {
        Mac {
            contents: PartyEitherCopy::verifier_new(e, tag),
        }
    }
    pub fn prover_extract(&self, e: IsParty<P, Prover>) -> (T::VF, T::TF) {
        T::S::extract_sender_pair(self.contents.prover_into(e))
    }
    pub fn tag(&self, e: IsParty<P, Verifier>) -> T::TF {
        self.contents.verifier_into(e)
    }
    pub fn mac_value(&self) -> ProverPrivateCopy<P, T::VF> {
        match P::WHICH {
            WhichParty::Prover(e) => ProverPrivateCopy::new(self.prover_extract(e).0),
            WhichParty::Verifier(e) => ProverPrivateCopy::empty(e),
        }
    }
    pub fn beta(&self) -> ProverPrivateCopy<P, T::TF> {
        match P::WHICH {
            WhichParty::Prover(e) => ProverPrivateCopy::new(self.prover_extract(e).1),
            WhichParty::Verifier(e) => ProverPrivateCopy::empty(e),
        }
    }
}
impl<P: Party, T: MacTypes> Mul<T::VF> for Mac<P, T> {
    type Output = Self;

    fn mul(self, rhs: T::VF) -> Self::Output {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    let (x, beta) = self.prover_extract(e);
                    PartyEitherCopy::prover_new(e, T::S::new_sender_pair(x * rhs, rhs * beta))
                }
                WhichParty::Verifier(e) => {
                    PartyEitherCopy::verifier_new(e, rhs * self.contents.verifier_into(e))
                }
            },
        }
    }
}
impl<P: Party, T: MacTypes> MulAssign<T::VF> for Mac<P, T> {
    fn mul_assign(&mut self, rhs: T::VF) {
        *self = *self * rhs;
    }
}
impl<P: Party, T: MacTypes> Add<Mac<P, T>> for Mac<P, T> {
    type Output = Self;

    fn add(self, rhs: Mac<P, T>) -> Self::Output {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    let (x, beta) = self.prover_extract(e);
                    let (x2, beta2) = rhs.prover_extract(e);
                    PartyEitherCopy::prover_new(e, T::S::new_sender_pair(x + x2, beta + beta2))
                }
                WhichParty::Verifier(e) => PartyEitherCopy::verifier_new(
                    e,
                    self.contents.verifier_into(e) + rhs.contents.verifier_into(e),
                ),
            },
        }
    }
}
impl<P: Party, T: MacTypes> AddAssign<Mac<P, T>> for Mac<P, T> {
    fn add_assign(&mut self, rhs: Mac<P, T>) {
        *self = *self + rhs;
    }
}
impl<P: Party, T: MacTypes> Sub<Mac<P, T>> for Mac<P, T> {
    type Output = Self;

    fn sub(self, rhs: Mac<P, T>) -> Self::Output {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    let (x, beta) = self.prover_extract(e);
                    let (x2, beta2) = rhs.prover_extract(e);
                    PartyEitherCopy::prover_new(e, T::S::new_sender_pair(x - x2, beta - beta2))
                }
                WhichParty::Verifier(e) => PartyEitherCopy::verifier_new(
                    e,
                    self.contents.verifier_into(e) - rhs.contents.verifier_into(e),
                ),
            },
        }
    }
}
impl<P: Party, T: MacTypes> SubAssign<Mac<P, T>> for Mac<P, T> {
    fn sub_assign(&mut self, rhs: Mac<P, T>) {
        *self = *self - rhs;
    }
}
impl<P: Party, T: MacTypes> Default for Mac<P, T> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<T: MacTypes> From<(T::VF, T::TF)> for Mac<party::Prover, T> {
    fn from(value: (T::VF, T::TF)) -> Self {
        Mac::prover_new(IS_PROVER, value.0, value.1)
    }
}
impl<T: MacTypes> Into<(T::VF, T::TF)> for Mac<party::Prover, T> {
    fn into(self) -> (T::VF, T::TF) {
        self.prover_extract(IS_PROVER)
    }
}
impl<P: Party, T: MacTypes> std::fmt::Debug for Mac<P, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match P::WHICH {
            WhichParty::Prover(e) => {
                let (x, beta) = self.prover_extract(e);
                write!(
                    f,
                    "Mac<Prover, {}> {{ x: {x:?}, beta: {beta:?} }}",
                    std::any::type_name::<T>()
                )
            }
            WhichParty::Verifier(e) => write!(
                f,
                "Mac<Verifier, {}> {{ tag: {:?} }}",
                std::any::type_name::<T>(),
                self.tag(e)
            ),
        }
    }
}

unsafe impl<P: Party, TF: SmallBinaryField> Zeroable
    for Mac<P, (F2, TF, SmallBinaryFieldSpecialization)>
where
    F2: IsSubFieldOf<TF>,
{
}
