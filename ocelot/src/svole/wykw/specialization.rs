use scuttlebutt::field::FiniteField;

pub(crate) trait FiniteFieldSpecialization<FE: FiniteField>:
    'static + Send + Sync + Sized
{
    type SenderPairContents: 'static + Sized + Send + Sync + Clone + Copy;
    fn new_sender_pair(u: FE::PrimeField, w: FE) -> Self::SenderPairContents;
    fn extract_sender_pair(pair: Self::SenderPairContents) -> (FE::PrimeField, FE);
}

pub(super) enum NoSpecialization {}
impl<FE: FiniteField> FiniteFieldSpecialization<FE> for NoSpecialization {
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
