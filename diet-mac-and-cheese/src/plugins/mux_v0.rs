use super::{Plugin, PluginExecution};
use crate::backend_trait::{BackendT, Party};
use crate::circuit_ir::{FunStore, TypeId, TypeStore, WireCount};
use crate::memory::Memory;
use eyre::{bail, ensure, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use swanky_field::FiniteRing;

#[derive(Clone, Debug)]
pub(crate) struct Mux {
    /// The [`TypeId`] associated with this mux.
    type_id: TypeId,
    /// The range of the selector
    selector_range: usize,
    // The shape of branches. It is derived from the wire ranges in outputs.
    branch_shape: Vec<WireCount>,
    // Boolean indicating if the plugin is permissive or strict.
    is_permissive: bool,
}

impl Mux {
    /// Create a new [`Mux`] instantiation for the field
    /// associated with the provided [`TypeId`], the provided number the size of the wire range,
    /// and a boolean indicating if the mux is permissive.
    pub(crate) fn new(
        type_id: TypeId,
        selector_range: usize,
        branch_shape: Vec<WireCount>,
        is_permissive: bool,
    ) -> Self {
        Mux {
            type_id,
            selector_range,
            branch_shape,
            is_permissive,
        }
    }

    /// Return the [`TypeId`] of this instantiation.
    pub(crate) fn type_id(&self) -> TypeId {
        self.type_id
    }

    /// Run the mux on the memory and the backend
    pub(crate) fn execute<B: BackendT>(
        &self,
        backend: &mut B,
        memory: &mut Memory<B::Wire>,
    ) -> Result<()> {
        // The general idea for how the mux plugin works is the following.
        // Let's consider the following example:
        // r <- mux(cond, b_0, ..., b_n)
        // The steps are basically:
        // 1) Input(a_i)  for i in 0..n
        // 2) Check that a_i is 0 or 1                (done with CheckZero(a_i * (1 - a_i)))
        // 3) Check that If a_i == 1 then cond == i   (done with CheckZero(a_i * (cond-i)))
        // 4) r = Sum_i a_i * b_i

        // NOTE: this algorithm works for any field, but there is a more direct algorithm for F2:
        // r <- mux(cond, b_0, b_1)
        // cond_neg = cond + 1
        // r = b_0 * cond_neg + b_1 * cond
        // And the number of multiplication gates could be minimized further.
        // So we keep as a TODO to specialize this code for F2 and improve the performance of mux

        // First find where the condition wire is:
        let mut cond_wire = 0;
        for branch_size in self.branch_shape.iter() {
            cond_wire += branch_size;
        }

        // 1) Input(a_i)  for i in 0..n
        let mut ai_s = Vec::with_capacity(self.selector_range);
        let cond = memory.get(cond_wire);
        let cond_value = backend.wire_value(cond);
        let mut i_f = <B as BackendT>::FieldElement::ZERO;
        for _ in 0..self.selector_range {
            // depending on the party running, if it is the prover and the index is matching then
            // it fixes the private input to 1, otherwise it fixes the private input to 0
            let what_to_input = if backend.party() == Party::Prover {
                // TODO: constant time this
                if cond_value.as_ref().unwrap() == &i_f {
                    Some(<B as BackendT>::FieldElement::ONE)
                } else {
                    Some(<B as BackendT>::FieldElement::ZERO)
                }
            } else {
                None
            };
            let t = backend.input_private(what_to_input)?;
            ai_s.push(t);

            if backend.party() == Party::Prover {
                i_f += <B as BackendT>::FieldElement::ONE;
            }
        }

        // 2) Check that a_i is 0 or 1                (done with CheckZero(a_i * (1 - a_i)))
        let one = backend.constant(B::FieldElement::ONE)?;
        for ai in ai_s.iter() {
            let tmp1 = backend.sub(&one, ai)?;
            let tmp2 = backend.mul(ai, &tmp1)?;
            backend.assert_zero(&tmp2)?;
        }

        // 3) Check that If a_i == 1 then cond == i   (done with CheckZero(a_i * (cond-i)))
        if !self.is_permissive {
            let mut minus_i = B::FieldElement::ZERO;
            for ai in ai_s.iter() {
                let tmp1 = backend.add_constant(cond, minus_i)?;
                let tmp2 = backend.mul(ai, &tmp1)?;
                backend.assert_zero(&tmp2)?;
                minus_i -= B::FieldElement::ONE;
            }
        }

        // 4) r = Sum_i a_i * b_i

        // The shape of `r` will match the self.branch_shape
        let mut r = Vec::with_capacity(self.branch_shape.len());

        let mut wire = cond_wire + 1; //  this is where the first branch wire is

        // 4) a) first we set r with the a_1 * b_1 for a branch shape
        for wirerange_size in self.branch_shape.iter() {
            let mut r1 = Vec::with_capacity(*wirerange_size as usize);

            for i in 0..*wirerange_size {
                let b = memory.get(wire + i);
                r1.push(backend.mul(&ai_s[0], b)?);
            }
            r.push(r1);

            // moving by `wirerange_size` on the inputs
            wire += wirerange_size;
        }

        // 4) b) iterate the summation updating r and bs
        let mut wire = cond_wire + 1 + cond_wire;
        for ai in ai_s[1..].iter() {
            for (branch, wirerange_size) in self.branch_shape.iter().enumerate() {
                for i in 0..*wirerange_size {
                    let b = memory.get(wire + i);
                    let t = backend.mul(ai, b)?;
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

impl Plugin for Mux {
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

        Ok(PluginExecution::Mux(Mux::new(
            type_id,
            selector_range,
            branch_shape,
            is_permissive,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::Mux;
    use crate::{
        backend_multifield::tests::FF0,
        fields::{F2_MODULUS, F61P_MODULUS},
        plugins::Plugin,
    };
    use crate::{
        backend_multifield::tests::{minus_one, one, test_circuit, three, zero},
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
            Mux::NAME.into(),
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
            Mux::NAME.into(),
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

    // More complicated test of mux selecting a triple and a unique element
    #[test]
    fn test_f61p_mux_simple() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 1), (FF0, 3), (FF0, 3), (FF0, 3), (FF0, 3)],
            Mux::NAME.into(),
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
            Mux::NAME.into(),
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
}
