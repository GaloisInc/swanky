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
        unimplemented!()
    }

    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire> {
        unimplemented!()
    }

    fn finalize_conv(&mut self) -> Result<()> {
        unimplemented!()
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
    SVOLE: SvoleT<T>,
> where
    F2: IsSubFieldOf<T>,
{
    dmc: DietMacAndCheeseVerifier<F2, T, C, SVOLE>,
    lifted_dmc: DietMacAndCheeseVerifier<T, T, C, SVOLE>,
}

impl<T: FiniteField<PrimeField = F2>, C: AbstractChannel, SVOLE: SvoleT<T>>
    DietMacAndCheeseExtFieldVerifier<T, C, SVOLE>
where
    F2: IsSubFieldOf<T>,
{
    pub(crate) fn init_with_fcom(
        channel: &mut C,
        rng: AesRng,
        fcom: &FComVerifier<F2, T, SVOLE>,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let mut dmc = DietMacAndCheeseVerifier::init_with_fcom(channel, rng, fcom, no_batching)?;
        let lifted_dmc = dmc.lift(lpn_setup, lpn_extend)?;
        Ok(Self { dmc, lifted_dmc })
    }
}

impl<T: FiniteField<PrimeField = F2>, C: AbstractChannel, SVOLE: SvoleT<T>> BackendT
    for DietMacAndCheeseExtFieldVerifier<T, C, SVOLE>
where
    F2: IsSubFieldOf<T>,
{
    type Wire = <DietMacAndCheeseVerifier<F2, T, C, SVOLE> as BackendT>::Wire;
    type FieldElement = <DietMacAndCheeseVerifier<F2, T, C, SVOLE> as BackendT>::FieldElement;

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

impl<T: FiniteField<PrimeField = F2>, C: AbstractChannel, SVOLE: SvoleT<T>> BackendConvT
    for DietMacAndCheeseExtFieldVerifier<T, C, SVOLE>
where
    F2: IsSubFieldOf<T>,
{
    fn assert_conv_to_bits(&mut self, a: &Self::Wire) -> Result<Vec<MacBitGeneric>> {
        unimplemented!()
    }

    fn assert_conv_from_bits(&mut self, x: &[MacBitGeneric]) -> Result<Self::Wire> {
        unimplemented!()
    }

    fn finalize_conv(&mut self) -> Result<()> {
        unimplemented!()
    }
}

impl<T: FiniteField<PrimeField = F2>, C: AbstractChannel, SVOLE: SvoleT<T>> BackendDisjunctionT
    for DietMacAndCheeseExtFieldVerifier<T, C, SVOLE>
where
    F2: IsSubFieldOf<T>,
{
    fn finalize_disj(&mut self) -> Result<()> {
        unimplemented!()
    }

    fn disjunction(
        &mut self,
        inputs: &[Self::Wire],
        disj: &DisjunctionBody,
    ) -> Result<Vec<Self::Wire>> {
        unimplemented!()
    }
}

impl<C: AbstractChannel, SVOLE: SvoleT<F40b>> BackendLiftT
    for DietMacAndCheeseExtFieldVerifier<F40b, C, SVOLE>
{
    type LiftedBackend = DietMacAndCheeseVerifier<F40b, F40b, C, SVOLE>;

    fn lift(&mut self) -> &mut Self::LiftedBackend {
        &mut self.lifted_dmc
    }
}

//////////////////////////////////////////
