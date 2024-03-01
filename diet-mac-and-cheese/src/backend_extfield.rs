use std::{
    collections::{hash_map::Entry, HashMap},
    iter,
};

use crate::{
    backend_multifield::{BackendConvT, BackendDisjunctionT, BackendLiftT, BackendRamT, RamId},
    backend_trait::BackendT,
    circuit_ir::{FieldInputs, FunStore},
    dora::{Disjunction, Dora, DoraState},
    fields::SieveIrDeserialize,
    homcom::FCom,
    mac::Mac,
    plugins::DisjunctionBody,
    ram::BooleanRam,
    svole_trait::SvoleT,
    DietMacAndCheese,
};
use eyre::Result;
use generic_array::GenericArray;
use ocelot::svole::LpnParams;
use scuttlebutt::{AbstractChannel, AesRng};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F40b, F2};
use swanky_party::{private::ProverPrivate, Party, WhichParty};

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
    dora_states: HashMap<usize, DoraState<P, T, T, C, SVOLE2>>,
    ram_states: Vec<BooleanRam<P, T, C, SVOLE1>>,
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
        Ok(Self {
            dmc,
            lifted_dmc,
            dora_states: Default::default(),
            ram_states: Default::default(),
        })
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
        inswit: &mut FieldInputs,
        fun_store: &FunStore,
        inputs: &[Self::Wire],
        disj: &DisjunctionBody,
    ) -> Result<Vec<Self::Wire>> {
        // Assumes `inputs` is in the expected input format (input wires in
        // their proper order, then big-endian condition wires).
        fn lift_guard<P: Party, C: AbstractChannel + Clone, SVOLE: SvoleT<P, F2, F40b>>(
            dmc: &mut DietMacAndCheese<P, F2, F40b, C, SVOLE>,
            inputs: &[Mac<P, F2, F40b>],
            num_cond: usize,
        ) -> Mac<P, F40b, F40b> {
            Mac::lift(&GenericArray::from_iter(
                inputs[inputs.len() - num_cond..]
                    .iter()
                    .copied()
                    .rev()
                    .chain(iter::repeat(dmc.input_public(F2::ZERO).unwrap()).take(40 - num_cond)),
            ))
        }

        // Assumes `inputs` is in the expected input format.
        fn adjust_inputs<P: Party>(
            inputs: &[Mac<P, F2, F40b>],
            num_cond: usize,
            guard: Mac<P, F40b, F40b>,
        ) -> Vec<Mac<P, F40b, F40b>> {
            inputs[..inputs.len() - num_cond]
                .iter()
                .copied()
                .map(|x| x.into())
                .chain(iter::once(guard))
                .collect()
        }

        fn execute_branch<
            I: Iterator<Item = F2>,
            P: Party,
            C: AbstractChannel + Clone,
            SVOLE1: SvoleT<P, F2, F40b>,
            SVOLE2: SvoleT<P, F40b, F40b>,
        >(
            dmcf2: &mut DietMacAndCheese<P, F2, F40b, C, SVOLE1>,
            dmc: &mut DietMacAndCheese<P, F40b, F40b, C, SVOLE2>,
            wit_tape: I,
            inputs: &[<DietMacAndCheese<P, F2, F40b, C, SVOLE1> as BackendT>::Wire],
            cond: usize,
            st: &mut DoraState<P, F40b, F40b, C, SVOLE2>,
        ) -> Result<Vec<<DietMacAndCheese<P, F2, F40b, C, SVOLE1> as BackendT>::Wire>> {
            // Must have at least one condition wire
            debug_assert!(cond > 0);

            // But no more than 40!
            debug_assert!(cond <= 40);

            // The guard is given by the last `cond` inputs.
            // These are F2 values in big-endian order, so we reverse and append
            // zeroes to pad to 40 bits, lifting to F40b.
            let guard_val: Mac<P, F40b, F40b> = lift_guard(dmcf2, inputs, cond);

            // Look up the clause based on the guard
            let opt = st
                .clause_resolver
                .as_ref()
                .zip(guard_val.value().into())
                .map(|(resolver, guard)| {
                    *resolver.get(&guard).expect("no clause guard is satisfied")
                })
                .into();

            // Need to adjust the inputs to use exactly one condition wire
            let adjusted_inputs = adjust_inputs(inputs, cond, guard_val);

            st.dora
                .mux(dmc, wit_tape.map(|x| x.into()), &adjusted_inputs, opt)?
                .iter()
                .copied()
                .map(<Mac<P, F2, F40b>>::try_from)
                .collect()
        }

        match self.dora_states.entry(disj.id()) {
            Entry::Occupied(mut entry) => execute_branch::<_, _, _, SVOLE1, _>(
                &mut self.dmc,
                &mut self.lifted_dmc,
                inswit.wit_iter::<F2>(),
                inputs,
                disj.cond() as usize,
                entry.get_mut(),
            ),
            Entry::Vacant(entry) => {
                // Compile disjunction to F40b
                // Note that this uses 1 condition wire!
                let disjunction = Disjunction::compile(disj, 1, fun_store);

                let mut resolver: ProverPrivate<P, HashMap<F40b, _>> = ProverPrivate::default();
                if let WhichParty::Prover(ev) = P::WHICH {
                    for (i, guard) in disj.guards().enumerate() {
                        let guard = F40b::from_number(guard).unwrap();
                        resolver.as_mut().into_inner(ev).insert(guard, i);
                    }
                }

                // Create a new Dora instance
                let dora = entry.insert(DoraState {
                    dora: Dora::new(disjunction),
                    clause_resolver: resolver,
                });

                // Compute opt
                execute_branch::<_, _, _, SVOLE1, _>(
                    &mut self.dmc,
                    &mut self.lifted_dmc,
                    inswit.wit_iter::<F2>(),
                    inputs,
                    disj.cond() as usize,
                    dora,
                )
            }
        }
    }

    fn finalize_disj(&mut self) -> Result<()> {
        for (_, disj) in std::mem::take(&mut self.dora_states) {
            disj.dora.finalize(&mut self.lifted_dmc)?;
        }
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

impl<
        P: Party,
        C: AbstractChannel + Clone,
        SVOLE1: SvoleT<P, F2, F40b>,
        SVOLE2: SvoleT<P, F40b, F40b>,
    > BackendRamT for DietMacAndCheeseExtField<P, F40b, C, SVOLE1, SVOLE2>
{
    fn init_ram(
        &mut self,
        _size: usize,
        _addr_count: usize,
        _value_count: usize,
        _init_value: &[Self::Wire],
    ) -> Result<RamId> {
        todo!("Create and store a BinaryRam state, returning its position in the store.")
    }

    fn ram_read(&mut self, _ram: RamId, _addr: &[Self::Wire]) -> Result<Vec<Self::Wire>> {
        todo!("Read from the BinaryRam with ID ram.")
    }

    fn ram_write(&mut self, _ram: RamId, _addr: &[Self::Wire], _new: &[Self::Wire]) -> Result<()> {
        todo!("Write to the BinaryRam with ID ram.")
    }

    fn finalize_rams(&mut self) -> Result<()> {
        Ok(())
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
