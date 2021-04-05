use scuttlebutt::field::{FiniteField, Gf40, F2};
use std::any::{Any, TypeId};

pub(crate) trait FiniteFieldSpecialization<FE: FiniteField>:
    'static + Send + Sync + Sized
{
}

pub(crate) trait FiniteFieldSendSpecialization<FE: FiniteField>:
    FiniteFieldSpecialization<FE>
{
    type SenderPairContents: 'static + Sized + Send + Sync + Clone + Copy;
    fn new_sender_pair(u: FE::PrimeField, w: FE) -> Self::SenderPairContents;
    fn extract_sender_pair(pair: Self::SenderPairContents) -> (FE::PrimeField, FE);
}

pub(super) enum NoSpecialization {}
impl<FE: FiniteField> FiniteFieldSpecialization<FE> for NoSpecialization {}
impl<FE: FiniteField> FiniteFieldSendSpecialization<FE> for NoSpecialization {
    type SenderPairContents = (FE::PrimeField, FE);

    #[inline(always)]
    fn new_sender_pair(u: <FE as FiniteField>::PrimeField, w: FE) -> Self::SenderPairContents {
        (u, w)
    }

    #[inline(always)]
    fn extract_sender_pair(
        pair: Self::SenderPairContents,
    ) -> (<FE as FiniteField>::PrimeField, FE) {
        pair
    }
}

#[inline(always)]
/// This will panic if, at runtime T != U. If T == U, then this function will be optimized away.
pub(super) fn downcast<T: Any + Sized + 'static, U: Any + Sized + 'static>(t: T) -> U {
    if TypeId::of::<T>() == TypeId::of::<U>() {
        unsafe {
            // SAFETY: T == U, including lifetimes (since both are 'static).
            // We need to use transmute_copy, since the rust compiler doesn't know that
            // sizeof(T) == sizeof(U)
            // See https://docs.rs/refl/0.2.1/src/refl/lib.rs.html#167-180
            let out = std::mem::transmute_copy::<T, U>(&t);
            std::mem::forget(t);
            out
        }
    } else {
        panic!("Type {:?} != {:?}", TypeId::of::<T>(), TypeId::of::<U>())
    }
}

pub(crate) enum Gf40Specialization {}
impl FiniteFieldSpecialization<Gf40> for Gf40Specialization {}
impl FiniteFieldSendSpecialization<Gf40> for Gf40Specialization {
    type SenderPairContents = u64;

    #[inline(always)]
    fn new_sender_pair(u: F2, w: Gf40) -> u64 {
        ((bool::from(u) as u64) << 63) | w.extract_raw()
    }

    #[inline(always)]
    fn extract_sender_pair(pair: u64) -> (F2, Gf40) {
        debug_assert_eq!(pair & ((u64::MAX >> 1) & (!((1 << 40) - 1))), 0);
        (F2::from((pair >> 63) != 0), Gf40::from_lower_40(pair))
    }
}
