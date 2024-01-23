use crate::{
    backend_multifield::{BackendConvT, BackendDisjunctionT, BackendLiftT},
    backend_trait::BackendT,
    circuit_ir::FieldInputs,
    homcom::FCom,
    mac::Mac,
    plugins::DisjunctionBody,
    svole_trait::SvoleT,
    DietMacAndCheese,
};
use eyre::Result;
use ocelot::svole::LpnParams;
use scuttlebutt::{AbstractChannel, AesRng};
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_field_binary::{F40b, F2};
use swanky_party::Party;

pub(crate) struct DietMacAndCheeseExtField<
    P: Party,
    T: FiniteField<PrimeField = F2>,
    C: AbstractChannel + Clone,
    SVOLE1: SvoleT<P, F2, T>,
    SVOLE2: SvoleT<P, T, T>,
> where
    F2: IsSubFieldOf<T>,
{
    dmc: DietMacAndCheese<P, F2, T, C, SVOLE1>,
    lifted_dmc: DietMacAndCheese<P, T, T, C, SVOLE2>,
}

impl<
        P: Party,
        T: FiniteField<PrimeField = F2>,
        C: AbstractChannel + Clone,
        SVOLE1: SvoleT<P, F2, T>,
        SVOLE2: SvoleT<P, T, T>,
    > DietMacAndCheeseExtField<P, T, C, SVOLE1, SVOLE2>
where
    F2: IsSubFieldOf<T>,
{
    pub(crate) fn init_with_fcom(
        channel: &mut C,
        rng: AesRng,
        fcom: &FCom<P, F2, T, SVOLE1>,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        no_batching: bool,
    ) -> Result<Self> {
        let mut dmc = DietMacAndCheese::init_with_fcom(channel, rng, fcom, no_batching)?;
        let lifted_dmc = dmc.lift(lpn_setup, lpn_extend)?;
        Ok(Self { dmc, lifted_dmc })
    }
}

impl<
        P: Party,
        T: FiniteField<PrimeField = F2>,
        C: AbstractChannel + Clone,
        SVOLE1: SvoleT<P, F2, T>,
        SVOLE2: SvoleT<P, T, T>,
    > BackendT for DietMacAndCheeseExtField<P, T, C, SVOLE1, SVOLE2>
where
    F2: IsSubFieldOf<T>,
{
    type Wire = <DietMacAndCheese<P, F2, T, C, SVOLE1> as BackendT>::Wire;
    type FieldElement = <DietMacAndCheese<P, F2, T, C, SVOLE1> as BackendT>::FieldElement;

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

impl<
        P: Party,
        C: AbstractChannel + Clone,
        SVOLE1: SvoleT<P, F2, F40b>,
        SVOLE2: SvoleT<P, F40b, F40b>,
    > BackendConvT<P> for DietMacAndCheeseExtField<P, F40b, C, SVOLE1, SVOLE2>
{
    fn assert_conv_to_bits(&mut self, w: &Self::Wire) -> Result<Vec<Mac<P, F2, F40b>>> {
        self.dmc.assert_conv_to_bits(w)
    }

    fn assert_conv_from_bits(&mut self, x: &[Mac<P, F2, F40b>]) -> Result<Self::Wire> {
        self.dmc.assert_conv_from_bits(x)
    }

    fn finalize_conv(&mut self) -> Result<()> {
        self.dmc.finalize_conv()
    }
}

impl<
        P: Party,
        C: AbstractChannel + Clone,
        SVOLE1: SvoleT<P, F2, F40b>,
        SVOLE2: SvoleT<P, F40b, F40b>,
    > BackendDisjunctionT for DietMacAndCheeseExtField<P, F40b, C, SVOLE1, SVOLE2>
{
    fn disjunction(
        &mut self,
        _inswit: &mut FieldInputs,
        _inputs: &[Self::Wire],
        _disj: &DisjunctionBody,
    ) -> Result<Vec<Self::Wire>> {
        unimplemented!("disjunction plugin is not sound for GF(2)")
    }

    fn finalize_disj(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<
        P: Party,
        C: AbstractChannel + Clone,
        SVOLE1: SvoleT<P, F2, F40b>,
        SVOLE2: SvoleT<P, F40b, F40b>,
    > BackendLiftT for DietMacAndCheeseExtField<P, F40b, C, SVOLE1, SVOLE2>
{
    type LiftedBackend = DietMacAndCheese<P, F40b, F40b, C, SVOLE2>;

    fn lift(&mut self) -> &mut Self::LiftedBackend {
        &mut self.lifted_dmc
    }
}

#[cfg(test)]
mod test {
    use super::DietMacAndCheeseExtField;
    use crate::backend_trait::BackendT;
    use crate::homcom::FCom;
    use crate::svole_trait::Svole;
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
    use swanky_party::{Prover, Verifier};

    #[test]
    fn test_backend_ext_field() -> Result<(), eyre::Error> {
        let (sender, receiver) = UnixStream::pair()?;
        let handle: JoinHandle<eyre::Result<()>> = std::thread::spawn(move || {
            let mut rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let fcom = FCom::<Prover, F2, F40b, Svole<Prover, F2, F40b>>::init(
                &mut channel,
                &mut rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
            )?;

            let mut eval = DietMacAndCheeseExtField::<
                Prover,
                F40b,
                _,
                Svole<Prover, F2, F40b>,
                Svole<Prover, F40b, F40b>,
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

        let fcom = FCom::<Verifier, F2, F40b, Svole<Verifier, F2, F40b>>::init(
            &mut channel,
            &mut rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
        )?;

        let mut eval = DietMacAndCheeseExtField::<
            Verifier,
            F40b,
            _,
            Svole<Verifier, F2, F40b>,
            Svole<Verifier, F40b, F40b>,
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
