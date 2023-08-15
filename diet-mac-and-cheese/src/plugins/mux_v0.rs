use super::{Plugin, PluginExecution};
use crate::backend_trait::{BackendT, Party};
use crate::circuit_ir::{FunStore, TypeId, TypeStore, WireCount};
use crate::memory::Memory;
use eyre::{bail, ensure, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use swanky_field::FiniteRing;

#[derive(Clone, Debug)]
pub(crate) struct MuxV0 {
    /// The [`TypeId`] associated with this mux.
    type_id: TypeId,
    /// The range of the selector
    selector_range: usize,
    // The shape of branches. It is derived from the wire ranges in outputs.
    branch_shape: Vec<WireCount>,
    // Boolean indicating if the plugin is permissive or strict.
    is_permissive: bool,
}

// The mux_v1 plugin is a conservative extension of the mux_v0 plugin.
// Currently we only implement some features of mux_v0, and mux_v1
// is simply defined by wrapping mux_v0.
#[repr(transparent)]
#[derive(Clone, Debug)]
pub(crate) struct MuxV1(MuxV0);

#[derive(Clone, Debug)]
pub(crate) enum MuxVersion {
    MuxVerV0(MuxV0),
    MuxVerV1(MuxV1),
}

impl MuxVersion {
    /// Return the [`TypeId`] of this instantiation.
    pub(crate) fn type_id(&self) -> TypeId {
        match self {
            MuxVersion::MuxVerV0(p) => p.type_id(),
            MuxVersion::MuxVerV1(p) => p.0.type_id(),
        }
    }

    /// Run the mux on the memory and the backend
    pub(crate) fn execute<B: BackendT>(
        &self,
        backend: &mut B,
        memory: &mut Memory<B::Wire>,
    ) -> Result<()> {
        match self {
            MuxVersion::MuxVerV0(p) => p.execute(backend, memory),
            MuxVersion::MuxVerV1(p) => p.0.execute(backend, memory),
        }
    }
}

impl MuxV0 {
    /// Create a new [`Mux`] instantiation for the field
    /// associated with the provided [`TypeId`], the provided number the size of the wire range,
    /// and a boolean indicating if the mux is permissive.
    pub(crate) fn new(
        type_id: TypeId,
        selector_range: usize,
        branch_shape: Vec<WireCount>,
        is_permissive: bool,
    ) -> Self {
        MuxV0 {
            type_id,
            selector_range,
            branch_shape,
            is_permissive,
        }
    }

    /// Return the [`TypeId`] of this instantiation.
    fn type_id(&self) -> TypeId {
        self.type_id
    }

    fn decode<B: BackendT>(&self, cond: &B::Wire, backend: &mut B) -> Result<Vec<B::Wire>> {
        // decode `cond` into a vector ys of 0s or 1s such that ys[i] == 1 <=> cond == i
        // The steps are basically:
        // 1) Input(y_i)  for i in 0..n
        // 2) Check that y_i is 0 or 1
        //    (done with CheckZero(y_i * (1 - y_i)))
        // 3) exactly one y_i is 1
        //    (done with Sum y_i = 1)
        // 4) a) strict: Check that If y_i == 1 then cond == i
        //       (done with CheckZero(y_i * (cond-i)))
        // 4) b) permissive: same as strict for i = 1..n,

        // 1) Input(y_i)  for i in 0..n
        let mut ys = Vec::with_capacity(self.selector_range);
        let cond_value = backend.wire_value(cond);
        let mut i_f = B::FieldElement::ZERO;

        let mut has_been_set: u8 = 0; // used as a boolean
        let mut inputs = Vec::with_capacity(self.selector_range);
        for _ in 0..self.selector_range {
            // depending on the party running, if it is the prover and the index is matching then
            // it fixes the private input to 1, otherwise it fixes the private input to 0
            let what_to_input = if backend.party() == Party::Prover {
                let cond_eq_i_f = cond_value.as_ref().unwrap().ct_eq(&i_f);
                has_been_set =
                    <u8>::conditional_select(&has_been_set, &(has_been_set | 1), cond_eq_i_f);
                Some(<B as BackendT>::FieldElement::conditional_select(
                    &B::FieldElement::ZERO,
                    &B::FieldElement::ONE,
                    cond_eq_i_f,
                ))
            } else {
                None
            };
            inputs.push(what_to_input);

            if backend.party() == Party::Prover {
                i_f += B::FieldElement::ONE;
            }
        }

        if backend.party() == Party::Prover && self.is_permissive && has_been_set == 0 {
            inputs[0] = Some(B::FieldElement::ONE);
        }
        for inp in inputs.iter() {
            let t = backend.input_private(*inp)?;
            ys.push(t);
        }

        // 2) Check that y_i is 0 or 1                (done with CheckZero(y_i * (1 - y_i)))
        let one = backend.constant(B::FieldElement::ONE)?;
        for y_i in ys.iter() {
            let tmp1 = backend.sub(&one, y_i)?;
            let tmp2 = backend.mul(y_i, &tmp1)?;
            backend.assert_zero(&tmp2)?;
        }

        // 3) exactly one y_i is 0 or 1. done Sum y_i = 1
        let mut sum_ys = ys[0];
        for y_i in ys[1..].iter() {
            sum_ys = backend.add(&sum_ys, y_i)?;
        }
        let sum_ys_minus_one = backend.sub(&one, &sum_ys)?;
        backend.assert_zero(&sum_ys_minus_one)?;

        // 4)
        if !self.is_permissive {
            // 4) a) strict
            //      Check that If y_i == 1 then cond == i   (done with CheckZero(y_i * (cond-i)))
            let mut minus_i = B::FieldElement::ZERO;
            for y_i in ys.iter() {
                let tmp1 = backend.add_constant(cond, minus_i)?;
                let tmp2 = backend.mul(y_i, &tmp1)?;
                backend.assert_zero(&tmp2)?;
                minus_i -= B::FieldElement::ONE;
            }
        } else {
            // 4) b) permissive
            //       For i!=0, check that If y_i == 1 then cond == i   (done with CheckZero(y_i * (cond-i)))
            let mut minus_i = B::FieldElement::ONE; // starting at 1, and not 0
            for y_i in ys[1..].iter() {
                let tmp1 = backend.add_constant(cond, minus_i)?;
                let tmp2 = backend.mul(y_i, &tmp1)?;
                backend.assert_zero(&tmp2)?;
                minus_i -= B::FieldElement::ONE;
            }
        }
        Ok(ys)
    }

    /// Run the mux on the memory and the backend
    pub(crate) fn execute<B: BackendT>(
        &self,
        backend: &mut B,
        memory: &mut Memory<B::Wire>,
    ) -> Result<()> {
        // The general idea for how the mux plugin works is the following.
        // Let's consider the following example:
        // r <- mux(cond, x_0, ..., x_n)
        // 1) decode cond into a vector ys of 0s or 1s such that ys[i] == 1 <=> cond == i
        // 2) r = Sum_i y_i * x_i

        // NOTE: this algorithm works for any field, but there is a more direct algorithm for F2,
        // on a single wire condition:
        // r <- mux(cond, x_0, x_1)
        // cond_neg = cond + 1
        // r = x_0 * cond_neg + x_1 * cond
        // And the number of multiplication gates could be minimized further.
        // So we keep as a TODO to specialize this code for F2 and improve the performance of mux

        // First find where the condition wire is:
        let mut cond_wire = 0;
        for branch_size in self.branch_shape.iter() {
            cond_wire += branch_size;
        }

        // 1) decode cond to get ys
        let cond = memory.get(cond_wire);
        let ys = self.decode(cond, backend)?;

        // The shape of `r` will match the self.branch_shape
        let mut r = Vec::with_capacity(self.branch_shape.len());

        let mut wire = cond_wire + 1; //  this is where the first branch wire is

        // 2) a) first we set r with the y_1 * x_1 for a branch shape
        for wirerange_size in self.branch_shape.iter() {
            let mut r1 = Vec::with_capacity(*wirerange_size as usize);

            for i in 0..*wirerange_size {
                let x = memory.get(wire + i);
                r1.push(backend.mul(&ys[0], x)?);
            }
            r.push(r1);

            // moving by `wirerange_size` on the inputs
            wire += wirerange_size;
        }

        // 2) b) iterate the summation updating r
        let mut wire = cond_wire + 1 + cond_wire;
        for y_i in ys[1..].iter() {
            for (branch, wirerange_size) in self.branch_shape.iter().enumerate() {
                for i in 0..*wirerange_size {
                    let x_i = memory.get(wire + i);
                    let t = backend.mul(y_i, x_i)?;
                    r[branch][i as usize] = backend.add(&r[branch][i as usize], &t)?;
                }
                // moving by `wirerange_size` on the inputs
                wire += wirerange_size;
            }
        }

        // Finally, the result of r is stored in the output wires
        let mut wire = 0;
        for branch_values in r.iter() {
            for (i, value) in branch_values.iter().enumerate() {
                memory.set(wire + (i as WireCount), value);
            }

            // moving by `wirerange_size` on the outputs
            wire += branch_values.len() as WireCount;
        }
        Ok(())
    }
}

impl Plugin for MuxV0 {
    const NAME: &'static str = "mux_v0";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> Result<PluginExecution> {
        ensure! {
            input_counts[0].1 == 1,
            "Only wire count equal to 1 is supported for the selector, not {}",
            input_counts[0].1
        }

        let branch_shape: Vec<WireCount> = output_counts.iter().map(|x| x.1).collect();

        ensure!(
            params.is_empty(),
            "{}: Invalid number of params (must be zero): {}",
            Self::NAME,
            params.len()
        );

        let is_permissive = if operation == "permissive" {
            true
        } else if operation == "strict" {
            false
        } else {
            bail!(
                "unknown operation (should be strict or permissive), found:{}",
                operation
            );
        };

        // The selector range is function of the shape of the output and the input.
        let selector_range = (input_counts.len() - 1) / output_counts.len();

        let type_id = input_counts[0].0;

        let mut i = 0;
        for (ty_inputs, inp) in input_counts[1..].iter() {
            ensure!(
                *ty_inputs == type_id,
                "only homogeneous type is currently supported: {} != {}",
                ty_inputs,
                type_id
            );
            ensure!(
                *inp == branch_shape[i],
                "input branch has different range than expected output: {} != {}",
                *inp,
                branch_shape[i]
            );
            i = (i + 1) % branch_shape.len();
        }

        Ok(PluginExecution::Mux(MuxVersion::MuxVerV0(MuxV0::new(
            type_id,
            selector_range,
            branch_shape,
            is_permissive,
        ))))
    }
}

impl Plugin for MuxV1 {
    const NAME: &'static str = "mux_v1";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> Result<PluginExecution> {
        match MuxV0::instantiate(
            operation,
            params,
            output_counts,
            input_counts,
            _type_store,
            _fun_store,
        )? {
            PluginExecution::Mux(p) => match p {
                MuxVersion::MuxVerV0(m) => Ok(PluginExecution::Mux(MuxVersion::MuxVerV1(MuxV1(m)))),
                _ => panic!("Should return a MuxV0"),
            },
            _ => panic!("Should return a Mux"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MuxV0;
    use crate::{
        backend_multifield::tests::FF0,
        fields::{F2_MODULUS, F61P_MODULUS},
        plugins::Plugin,
    };
    use crate::{
        backend_multifield::tests::{
            four, minus_one, minus_two, one, test_circuit, three, two, zero,
        },
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
    };
    use scuttlebutt::{
        field::{F61p, PrimeFiniteField, F2},
        ring::FiniteRing,
    };

    // Simplest test for mux on f2
    #[test]
    fn test_f2_mux() {
        let fields = vec![F2_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 1), (FF0, 1), (FF0, 1)],
            MuxV0::NAME.into(),
            "strict".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mux".into(), func);

        let gates = vec![
            GateM::New(FF0, 4, 14),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Instance(FF0, 6),
            GateM::Instance(FF0, 7),
            GateM::Instance(FF0, 8),
            GateM::Instance(FF0, 9),
            GateM::Instance(FF0, 10),
            GateM::Instance(FF0, 11),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(12, 12)],
                vec![(0, 0), (4, 4), (8, 8)],
            ))),
            GateM::AssertZero(FF0, 12),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(13, 13)],
                vec![(1, 1), (4, 4), (8, 8)],
            ))),
            GateM::AddConstant(FF0, 14, 13, Box::from((-F2::ONE).into_int())),
            GateM::AssertZero(FF0, 14),
        ];

        let instances = vec![vec![
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            one::<F2>(),
            one::<F2>(),
            one::<F2>(),
            one::<F2>(),
        ]];
        let witnesses = vec![vec![zero::<F2>(), one::<F2>(), zero::<F2>(), one::<F2>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    // More complicated test of mux selecting a triple and a unique element
    #[test]
    fn test_f2_mux_on_slices() {
        let fields = vec![F2_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3), (FF0, 1)],
            vec![(FF0, 1), (FF0, 3), (FF0, 1), (FF0, 3), (FF0, 1)],
            MuxV0::NAME.into(),
            "strict".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mux".into(), func);

        let gates = vec![
            GateM::New(FF0, 4, 11),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            // NOTE: there is a gap with 2 unused wires here
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Instance(FF0, 6),
            GateM::Instance(FF0, 7),
            GateM::Instance(FF0, 8),
            GateM::Instance(FF0, 9),
            GateM::Instance(FF0, 10),
            GateM::Instance(FF0, 11),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(12, 14), (15, 15)],
                vec![(0, 0), (4, 6), (7, 7), (8, 10), (11, 11)],
            ))),
            GateM::AssertZero(FF0, 12),
            GateM::AssertZero(FF0, 13),
            GateM::AssertZero(FF0, 14),
            GateM::AssertZero(FF0, 15),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(16, 18), (19, 19)],
                vec![(1, 1), (4, 6), (7, 7), (8, 10), (11, 11)],
            ))),
            GateM::AddConstant(FF0, 20, 16, Box::from(minus_one::<F2>())),
            GateM::AddConstant(FF0, 21, 17, Box::from(minus_one::<F2>())),
            GateM::AddConstant(FF0, 22, 18, Box::from(minus_one::<F2>())),
            GateM::AddConstant(FF0, 23, 19, Box::from(minus_one::<F2>())),
            GateM::AssertZero(FF0, 20),
            GateM::AssertZero(FF0, 21),
            GateM::AssertZero(FF0, 22),
            GateM::AssertZero(FF0, 23),
        ];

        let instances = vec![vec![
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            one::<F2>(),
            one::<F2>(),
            one::<F2>(),
            one::<F2>(),
        ]];
        let witnesses = vec![vec![zero::<F2>(), one::<F2>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    // Simplest test for mux on f61p
    #[test]
    fn test_f61p_mux_simple() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 1), (FF0, 3), (FF0, 3), (FF0, 3), (FF0, 3)],
            MuxV0::NAME.into(),
            "strict".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mux".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 100),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Instance(FF0, 10),
            GateM::Instance(FF0, 11),
            GateM::Instance(FF0, 12),
            GateM::Instance(FF0, 13),
            GateM::Instance(FF0, 14),
            GateM::Instance(FF0, 15),
            GateM::Instance(FF0, 16),
            GateM::Instance(FF0, 17),
            GateM::Instance(FF0, 18),
            GateM::Instance(FF0, 19),
            GateM::Instance(FF0, 20),
            GateM::Instance(FF0, 21),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(30, 32)],
                vec![(0, 0), (10, 12), (13, 15), (16, 18), (19, 21)],
            ))),
            GateM::AssertZero(FF0, 30),
            GateM::AssertZero(FF0, 31),
            GateM::AssertZero(FF0, 32),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(40, 42)],
                vec![(1, 1), (10, 12), (13, 15), (16, 18), (19, 21)],
            ))),
            GateM::AddConstant(FF0, 50, 40, Box::from(minus_one::<F61p>())),
            GateM::AddConstant(FF0, 51, 41, Box::from(minus_one::<F61p>())),
            GateM::AddConstant(FF0, 52, 42, Box::from(minus_one::<F61p>())),
            GateM::AssertZero(FF0, 50),
            GateM::AssertZero(FF0, 51),
            GateM::AssertZero(FF0, 52),
        ];

        let instances = vec![vec![
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
        ]];
        let witnesses = vec![vec![zero::<F61p>(), three::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    // More complicated test of mux selecting a triple and a unique element.
    // Same test as `test_f2_mux_on_slices()` but on F61p
    #[test]
    fn test_f61p_mux_on_slices() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3), (FF0, 1)],
            vec![(FF0, 1), (FF0, 3), (FF0, 1), (FF0, 3), (FF0, 1)],
            MuxV0::NAME.into(),
            "strict".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mux".into(), func);

        let gates = vec![
            GateM::New(FF0, 4, 11),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            // NOTE: there is a gap with 2 unused wires here
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Instance(FF0, 6),
            GateM::Instance(FF0, 7),
            GateM::Instance(FF0, 8),
            GateM::Instance(FF0, 9),
            GateM::Instance(FF0, 10),
            GateM::Instance(FF0, 11),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(12, 14), (15, 15)],
                vec![(0, 0), (4, 6), (7, 7), (8, 10), (11, 11)],
            ))),
            GateM::AssertZero(FF0, 12),
            GateM::AssertZero(FF0, 13),
            GateM::AssertZero(FF0, 14),
            GateM::AssertZero(FF0, 15),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(16, 18), (19, 19)],
                vec![(1, 1), (4, 6), (7, 7), (8, 10), (11, 11)],
            ))),
            GateM::AddConstant(FF0, 20, 16, Box::from(minus_one::<F61p>())),
            GateM::AddConstant(FF0, 21, 17, Box::from(minus_one::<F61p>())),
            GateM::AddConstant(FF0, 22, 18, Box::from(minus_one::<F61p>())),
            GateM::AddConstant(FF0, 23, 19, Box::from(minus_one::<F61p>())),
            GateM::AssertZero(FF0, 20),
            GateM::AssertZero(FF0, 21),
            GateM::AssertZero(FF0, 22),
            GateM::AssertZero(FF0, 23),
        ];

        let instances = vec![vec![
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
        ]];
        let witnesses = vec![vec![zero::<F61p>(), one::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    // test that a simple mux fails because of strictness, where the condition is out of range
    #[test]
    fn test_f61p_mux_simple_strict_fails() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 1), (FF0, 3), (FF0, 3), (FF0, 3), (FF0, 3)],
            MuxV0::NAME.into(),
            "strict".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mux".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 100),
            GateM::Witness(FF0, 0),
            GateM::Instance(FF0, 10),
            GateM::Instance(FF0, 11),
            GateM::Instance(FF0, 12),
            GateM::Instance(FF0, 13),
            GateM::Instance(FF0, 14),
            GateM::Instance(FF0, 15),
            GateM::Instance(FF0, 16),
            GateM::Instance(FF0, 17),
            GateM::Instance(FF0, 18),
            GateM::Instance(FF0, 19),
            GateM::Instance(FF0, 20),
            GateM::Instance(FF0, 21),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(30, 32)],
                vec![(0, 0), (10, 12), (13, 15), (16, 18), (19, 21)],
            ))),
            GateM::AssertZero(FF0, 30),
            GateM::AssertZero(FF0, 31),
            GateM::AssertZero(FF0, 32),
        ];

        let instances = vec![vec![
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
        ]];
        let witnesses = vec![vec![four::<F61p>()]];

        if !test_circuit(fields, func_store, gates, instances, witnesses).is_err() {
            panic!("Test should fail");
        };
    }

    // Simple test that a permissive mux succeeds with a condition outside the number of branches
    #[test]
    fn test_f61p_mux_simple_permissive() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 1), (FF0, 3), (FF0, 3), (FF0, 3), (FF0, 3)],
            MuxV0::NAME.into(),
            "permissive".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mux".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 100),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Instance(FF0, 10),
            GateM::Instance(FF0, 11),
            GateM::Instance(FF0, 12),
            GateM::Instance(FF0, 13),
            GateM::Instance(FF0, 14),
            GateM::Instance(FF0, 15),
            GateM::Instance(FF0, 16),
            GateM::Instance(FF0, 17),
            GateM::Instance(FF0, 18),
            GateM::Instance(FF0, 19),
            GateM::Instance(FF0, 20),
            GateM::Instance(FF0, 21),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(30, 32)],
                vec![(0, 0), (10, 12), (13, 15), (16, 18), (19, 21)],
            ))),
            GateM::AddConstant(FF0, 35, 30, Box::from(minus_two::<F61p>())),
            GateM::AddConstant(FF0, 36, 31, Box::from(minus_two::<F61p>())),
            GateM::AddConstant(FF0, 37, 32, Box::from(minus_two::<F61p>())),
            GateM::AssertZero(FF0, 35),
            GateM::AssertZero(FF0, 36),
            GateM::AssertZero(FF0, 37),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(40, 42)],
                vec![(1, 1), (10, 12), (13, 15), (16, 18), (19, 21)],
            ))),
            GateM::AddConstant(FF0, 50, 40, Box::from(minus_two::<F61p>())),
            GateM::AddConstant(FF0, 51, 41, Box::from(minus_two::<F61p>())),
            GateM::AddConstant(FF0, 52, 42, Box::from(minus_two::<F61p>())),
            GateM::AssertZero(FF0, 50),
            GateM::AssertZero(FF0, 51),
            GateM::AssertZero(FF0, 52),
        ];

        let instances = vec![vec![
            two::<F61p>(),
            two::<F61p>(),
            two::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
        ]];
        let witnesses = vec![vec![zero::<F61p>(), four::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }
}
