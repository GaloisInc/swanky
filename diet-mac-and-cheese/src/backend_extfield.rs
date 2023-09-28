use eyre::Result;
use ocelot::svole::LpnParams;
use scuttlebutt::{AbstractChannel, AesRng};
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_field_binary::{F40b, F2};

use crate::{
    backend_multifield::{BackendConvT, BackendDisjunctionT, BackendLiftT, MacBitGeneric},
    backend_trait::{BackendT, Party},
    homcom::{FComProver, FComVerifier},
    plugins::DisjunctionBody,
    svole_trait::SvoleT,
    DietMacAndCheeseProver, DietMacAndCheeseVerifier,
};

pub(crate) struct DietMacAndCheeseExtFieldProver<
    T: FiniteField<PrimeField = F2>,
    C: AbstractChannel,
    SVOLE1: SvoleT<(F2, T)>,
    SVOLE2: SvoleT<(T, T)>,
> where
    F2: IsSubFieldOf<T>,
{
    dmc: DietMacAndCheeseProver<F2, T, C, SVOLE1>,
    lifted_dmc: DietMacAndCheeseProver<T, T, C, SVOLE2>,
}

impl<
        T: FiniteField<PrimeField = F2>,
        C: AbstractChannel,
        SVOLE1: SvoleT<(F2, T)>,
        SVOLE2: SvoleT<(T, T)>,
    > DietMacAndCheeseExtFieldProver<T, C, SVOLE1, SVOLE2>
where
    F2: IsSubFieldOf<T>,
{
    pub(crate) fn init_with_fcom(
        channel: &mut C,
        rng: AesRng,
        fcom: &FComProver<F2, T, SVOLE1>,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let mut dmc = DietMacAndCheeseProver::init_with_fcom(channel, rng, fcom, no_batching)?;
        let lifted_dmc = dmc.lift(lpn_setup, lpn_extend)?;
        Ok(Self { dmc, lifted_dmc })
    }
}

impl<
        T: FiniteField<PrimeField = F2>,
        C: AbstractChannel,
        SVOLE1: SvoleT<(F2, T)>,
        SVOLE2: SvoleT<(T, T)>,
    > BackendT for DietMacAndCheeseExtFieldProver<T, C, SVOLE1, SVOLE2>
where
    F2: IsSubFieldOf<T>,
{
    type Wire = <DietMacAndCheeseProver<F2, T, C, SVOLE1> as BackendT>::Wire;
    type FieldElement = <DietMacAndCheeseProver<F2, T, C, SVOLE1> as BackendT>::FieldElement;

    fn party(&self) -> Party {
        Party::Prover
    }

    fn wire_value(&self, wire: &Self::Wire) -> Option<Self::FieldElement> {
        self.dmc.wire_value(wire)
    }

    fn one(&self) -> Result<Self::FieldElement> {
        self.dmc.one()
    }
    fn zero(&self) -> Result<Self::FieldElement> {
        self.dmc.zero()
    }
    fn random(&mut self) -> Result<Self::FieldElement> {
        self.dmc.random()
    }
    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.copy(wire)
    }
    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.constant(val)
    }
    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.dmc.assert_zero(wire)
    }
    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.add(a, b)
    }
    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.sub(a, b)
    }
    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.mul(a, b)
    }
    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.add_constant(a, b)
    }
    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.mul_constant(a, b)
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.input_public(val)
    }
    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        self.dmc.input_private(val)
    }
    fn finalize(&mut self) -> Result<()> {
        self.dmc.finalize()?;
        self.lifted_dmc.finalize()?;
        Ok(())
    }
}

impl<C: AbstractChannel, SVOLE1: SvoleT<(F2, F40b)>, SVOLE2: SvoleT<(F40b, F40b)>> BackendConvT
    for DietMacAndCheeseExtFieldProver<F40b, C, SVOLE1, SVOLE2>
{
    fn assert_conv_to_bits(&mut self, w: &Self::Wire) -> Result<Vec<MacBitGeneric>> {
        self.dmc.assert_conv_to_bits(w)
    }

    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire> {
        self.dmc.assert_conv_from_bits(x)
    }

    fn finalize_conv(&mut self) -> Result<()> {
        self.dmc.finalize_conv()
    }
}

impl<C: AbstractChannel, SVOLE1: SvoleT<(F2, F40b)>, SVOLE2: SvoleT<(F40b, F40b)>>
    BackendDisjunctionT for DietMacAndCheeseExtFieldProver<F40b, C, SVOLE1, SVOLE2>
{
    fn disjunction(
        &mut self,
        _inputs: &[Self::Wire],
        _disj: &DisjunctionBody,
    ) -> Result<Vec<Self::Wire>> {
        unimplemented!("disjunction plugin is not sound for GF(2)")
    }

    fn finalize_disj(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<C: AbstractChannel, SVOLE1: SvoleT<(F2, F40b)>, SVOLE2: SvoleT<(F40b, F40b)>> BackendLiftT
    for DietMacAndCheeseExtFieldProver<F40b, C, SVOLE1, SVOLE2>
{
    type LiftedBackend = DietMacAndCheeseProver<F40b, F40b, C, SVOLE2>;

    fn lift(&mut self) -> &mut Self::LiftedBackend {
        &mut self.lifted_dmc
    }
}

//////////////////////////////////////

pub(crate) struct DietMacAndCheeseExtFieldVerifier<
    T: FiniteField<PrimeField = F2>,
    C: AbstractChannel,
    SVOLE1: SvoleT<T>,
    SVOLE2: SvoleT<T>,
> where
    F2: IsSubFieldOf<T>,
{
    dmc: DietMacAndCheeseVerifier<F2, T, C, SVOLE1>,
    lifted_dmc: DietMacAndCheeseVerifier<T, T, C, SVOLE2>,
}

impl<T: FiniteField<PrimeField = F2>, C: AbstractChannel, SVOLE1: SvoleT<T>, SVOLE2: SvoleT<T>>
    DietMacAndCheeseExtFieldVerifier<T, C, SVOLE1, SVOLE2>
where
    F2: IsSubFieldOf<T>,
{
    pub(crate) fn init_with_fcom(
        channel: &mut C,
        rng: AesRng,
        fcom: &FComVerifier<F2, T, SVOLE1>,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let mut dmc = DietMacAndCheeseVerifier::init_with_fcom(channel, rng, fcom, no_batching)?;
        let lifted_dmc = dmc.lift::<SVOLE2>(lpn_setup, lpn_extend)?;
        Ok(Self { dmc, lifted_dmc })
    }
}

impl<T: FiniteField<PrimeField = F2>, C: AbstractChannel, SVOLE1: SvoleT<T>, SVOLE2: SvoleT<T>>
    BackendT for DietMacAndCheeseExtFieldVerifier<T, C, SVOLE1, SVOLE2>
where
    F2: IsSubFieldOf<T>,
{
    type Wire = <DietMacAndCheeseVerifier<F2, T, C, SVOLE1> as BackendT>::Wire;
    type FieldElement = <DietMacAndCheeseVerifier<F2, T, C, SVOLE1> as BackendT>::FieldElement;

    fn party(&self) -> Party {
        Party::Prover
    }

    fn wire_value(&self, wire: &Self::Wire) -> Option<Self::FieldElement> {
        self.dmc.wire_value(wire)
    }

    fn one(&self) -> Result<Self::FieldElement> {
        self.dmc.one()
    }
    fn zero(&self) -> Result<Self::FieldElement> {
        self.dmc.zero()
    }
    fn random(&mut self) -> Result<Self::FieldElement> {
        self.dmc.random()
    }
    fn copy(&mut self, wire: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.copy(wire)
    }
    fn constant(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.constant(val)
    }
    fn assert_zero(&mut self, wire: &Self::Wire) -> Result<()> {
        self.dmc.assert_zero(wire)
    }
    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.add(a, b)
    }
    fn sub(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.sub(a, b)
    }
    fn mul(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<Self::Wire> {
        self.dmc.mul(a, b)
    }
    fn add_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.add_constant(a, b)
    }
    fn mul_constant(&mut self, a: &Self::Wire, b: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.mul_constant(a, b)
    }

    fn input_public(&mut self, val: Self::FieldElement) -> Result<Self::Wire> {
        self.dmc.input_public(val)
    }
    fn input_private(&mut self, val: Option<Self::FieldElement>) -> Result<Self::Wire> {
        self.dmc.input_private(val)
    }
    fn finalize(&mut self) -> Result<()> {
        self.dmc.finalize()?;
        self.lifted_dmc.finalize()?;
        Ok(())
    }
}

impl<C: AbstractChannel, SVOLE1: SvoleT<F40b>, SVOLE2: SvoleT<F40b>> BackendConvT
    for DietMacAndCheeseExtFieldVerifier<F40b, C, SVOLE1, SVOLE2>
{
    fn assert_conv_to_bits(&mut self, a: &Self::Wire) -> Result<Vec<MacBitGeneric>> {
        self.dmc.assert_conv_to_bits(a)
    }

    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire> {
        self.dmc.assert_conv_from_bits(x)
    }

    fn finalize_conv(&mut self) -> Result<()> {
        self.dmc.finalize_conv()
    }
}

impl<T: FiniteField<PrimeField = F2>, C: AbstractChannel, SVOLE1: SvoleT<T>, SVOLE2: SvoleT<T>>
    BackendDisjunctionT for DietMacAndCheeseExtFieldVerifier<T, C, SVOLE1, SVOLE2>
where
    F2: IsSubFieldOf<T>,
{
    fn finalize_disj(&mut self) -> Result<()> {
        Ok(())
    }

    fn disjunction(
        &mut self,
        _inputs: &[Self::Wire],
        _disj: &DisjunctionBody,
    ) -> Result<Vec<Self::Wire>> {
        unimplemented!()
    }
}

impl<C: AbstractChannel, SVOLE1: SvoleT<F40b>, SVOLE2: SvoleT<F40b>> BackendLiftT
    for DietMacAndCheeseExtFieldVerifier<F40b, C, SVOLE1, SVOLE2>
{
    type LiftedBackend = DietMacAndCheeseVerifier<F40b, F40b, C, SVOLE2>;

    fn lift(&mut self) -> &mut Self::LiftedBackend {
        &mut self.lifted_dmc
    }
}

//////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::{DietMacAndCheeseExtFieldProver, DietMacAndCheeseExtFieldVerifier};
    use crate::backend_trait::BackendT;
    use crate::homcom::{FComProver, FComVerifier};
    use crate::svole_trait::{SvoleReceiver, SvoleSender};
    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::SeedableRng;
    #[allow(unused_imports)]
    use scuttlebutt::field::{F40b, F2};
    use scuttlebutt::{AesRng, Channel};
    use std::thread::JoinHandle;
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    #[test]
    fn test_backend_ext_field() -> Result<(), eyre::Error> {
        let (sender, receiver) = UnixStream::pair()?;
        let handle: JoinHandle<eyre::Result<()>> = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let fcom = FComProver::<F2, F40b, SvoleSender<F40b>>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )?;

            let mut eval = DietMacAndCheeseExtFieldProver::<
                F40b,
                _,
                SvoleSender<F40b>,
                SvoleSender<F40b>,
            >::init_with_fcom(
                &mut channel,
                rng,
                &fcom,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                false,
            )?;
            eval.finalize().unwrap();
            eyre::Result::Ok(())
        });

        let mut rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let fcom = FComVerifier::<F2, F40b, SvoleReceiver<F2, F40b>>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )?;

        let mut eval = DietMacAndCheeseExtFieldVerifier::<
            F40b,
            _,
            SvoleReceiver<F2, F40b>,
            SvoleReceiver<F40b, F40b>,
        >::init_with_fcom(
            &mut channel,
            rng,
            &fcom,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
            false,
        )?;
        eval.finalize().unwrap();

        handle.join().unwrap()
    }
}
