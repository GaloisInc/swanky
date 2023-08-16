use super::{Plugin, PluginExecution};
use crate::backend_trait::{BackendT, Party};
use crate::circuit_ir::{FunStore, TypeId, TypeSpecification, TypeStore, WireCount};
use crate::memory::Memory;
use eyre::{bail, ensure, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

#[derive(Clone, Debug)]
pub(crate) struct MuxV0 {
    /// The [`TypeId`] associated with this mux.
    type_id: TypeId,
    // The number of wires for the condition.
    cond_num_wire: usize,
    /// The range of the selector
    selector_range: usize,
    // The shape of branches. It is derived from the wire ranges in outputs.
    branch_shape: Vec<WireCount>,
    // Boolean indicating if the plugin is permissive or strict.
    is_permissive: bool,
    // The Rust type id assiociated with the field used in this mux.
    field_type_id: std::any::TypeId,
}

// The mux_v1 plugin is a conservative extension of the mux_v0 plugin.
// mux_v1 is simply defined by wrapping mux_v0.
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
    /// Create a new [`MuxV0`] instantiation for the field
    /// associated with the provided [`TypeId`], the provided number the size of the wire range,
    /// and a boolean indicating if the mux is permissive.
    pub(crate) fn new(
        type_id: TypeId,
        cond_num_wire: usize,
        selector_range: usize,
        branch_shape: Vec<WireCount>,
        is_permissive: bool,
        field_type_id: std::any::TypeId,
    ) -> Self {
        MuxV0 {
            type_id,
            cond_num_wire,
            selector_range,
            branch_shape,
            is_permissive,
            field_type_id,
        }
    }

    /// Return the [`TypeId`] of this instantiation.
    fn type_id(&self) -> TypeId {
        self.type_id
    }

    fn decode_boolean<B: BackendT>(
        &self,
        cond_vec: &[B::Wire],
        backend: &mut B,
    ) -> Result<Vec<B::Wire>> {
        // The main idea is to initialize the output vector to 10000...
        // and use the cond expressed in binary to control shift by power of twos
        // More precisely, iterate on the bits of the cond from least significant to most significant,
        // if 1 position i then shift by 2^{i-1} the first 2^{i-1} positions

        // Example:
        // #bits = 4, #branches = 10
        // cond 0101 = 5,
        // 1000000000, y vector initialized with 1 in the first position
        // 1010 is reverse of cond 0101
        // 1... ->    shift by 1 0100000000
        // .0.. -> NO shift by 2 0100000000
        // ..1. ->    shift by 4 0000010000
        // ...0 -> NO shift by 8 0000010000
        // As a result,          0000010000: 1 in position 5

        // We shift by muxing the positions between ys[i] and ys[i + shift_by]
        // When i > #branches then we go to the next shift.
        // There are 2 mul per shift, so the number of mul is O(#branches #bits)

        assert!(self.field_type_id == std::any::TypeId::of::<F2>());

        let mut ys = Vec::with_capacity(self.selector_range);
        ys.push(backend.input_public(B::FieldElement::ONE)?);
        for _ in 1..self.selector_range {
            ys.push(backend.input_public(B::FieldElement::ZERO)?);
        }

        let mut shift_by: usize = 1;
        for cond in cond_vec.iter().rev() {
            let neg_cond = backend.add_constant(cond, B::FieldElement::ONE)?;
            for i in 0..shift_by {
                if i + shift_by < self.selector_range {
                    // only write when the index in within the bounds of the selector_range
                    ys[i + shift_by] = backend.mul(&ys[i], cond)?;
                }
                ys[i] = backend.mul(&ys[i], &neg_cond)?;
                // break the loop when the index touched is ready to get over the selector_range
                if i == self.selector_range - 1 {
                    break;
                }
            }
            shift_by *= 2;
        }

        if !self.is_permissive {
            // sum all the values upto the selector_range and make sure it's equal to 1.
            let mut acc = ys[0];
            for y in ys[1..].iter() {
                acc = backend.add(&acc, y)?;
            }
            acc = backend.add_constant(&acc, B::FieldElement::ONE)?;
            backend.assert_zero(&acc)?;
        }
        // permissive
        // no check

        Ok(ys)
    }

    fn decode<B: BackendT>(&self, cond: B::Wire, backend: &mut B) -> Result<Vec<B::Wire>> {
        // decode `cond` into a vector ys of 0s or 1s such that ys[i] == 1 <=> cond == i
        // The steps are basically:
        // 1) Input(y_i)  for i in 0..n
        // 2) Check that y_i is 0 or 1
        //    (done with CheckZero(y_i * (1 - y_i)))
        // 3) Check that If y_i == 1 then cond == i
        //       (done with CheckZero(y_i * (cond-i)))
        // 4) a) strict: exactly one y_i is 1
        //       (done with Sum y_i = 1)
        // 4) b) permissive: no check

        assert!(self.field_type_id != std::any::TypeId::of::<F2>());

        // 1) Input(y_i)  for i in 0..n
        let mut ys = Vec::with_capacity(self.selector_range);
        let cond_value = backend.wire_value(&cond);
        let mut i_f = B::FieldElement::ZERO;

        let mut inputs = Vec::with_capacity(self.selector_range);
        for _ in 0..self.selector_range {
            // depending on the party running, if it is the prover and the index is matching then
            // it fixes the private input to 1, otherwise it fixes the private input to 0
            let what_to_input = if backend.party() == Party::Prover {
                let cond_eq_i_f = cond_value.as_ref().unwrap().ct_eq(&i_f);
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

        // 3) Check that If y_i == 1 then cond == i   (done with CheckZero(y_i * (cond-i)))
        let mut minus_i = B::FieldElement::ZERO;
        for y_i in ys.iter() {
            let tmp1 = backend.add_constant(&cond, minus_i)?;
            let tmp2 = backend.mul(y_i, &tmp1)?;
            backend.assert_zero(&tmp2)?;
            minus_i -= B::FieldElement::ONE;
        }

        // 4) exactly one y_i is 0 or 1. done Sum y_i = 1
        if !self.is_permissive {
            // 4) a) exactly one y_i is 0 or 1. done Sum y_i = 1
            let mut sum_ys = ys[0];
            for y_i in ys[1..].iter() {
                sum_ys = backend.add(&sum_ys, y_i)?;
            }
            let sum_ys_minus_one = backend.sub(&one, &sum_ys)?;
            backend.assert_zero(&sum_ys_minus_one)?;
        } // 4) b) otherwise permissive
          // no check
        Ok(ys)
    }

    /// Execute the mux on the memory and the backend
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
        let mut start_cond_wire = 0;
        for branch_size in self.branch_shape.iter() {
            start_cond_wire += branch_size;
        }

        // 1) decode cond to get ys
        let ys = if self.cond_num_wire == 1 && self.field_type_id != std::any::TypeId::of::<F2>() {
            let cond = memory.get(start_cond_wire);
            self.decode(*cond, backend)?
        } else {
            let mut cond_vec = Vec::with_capacity(self.cond_num_wire);
            for i in 0..self.cond_num_wire {
                cond_vec.push(*memory.get(start_cond_wire + (i as u64)));
            }
            self.decode_boolean(cond_vec.as_slice(), backend)?
        };
        // The shape of `r` will match the self.branch_shape
        let mut r = Vec::with_capacity(self.branch_shape.len());

        let mut wire = start_cond_wire + (self.cond_num_wire as u64); //  this is where the first branch wire is

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
        let mut wire = start_cond_wire + (self.cond_num_wire as u64) + start_cond_wire;
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
        type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> Result<PluginExecution> {
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

        let cond_num_wire = input_counts[0].1;
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

        let field_type_id = match type_store.get(&type_id).unwrap() {
            TypeSpecification::Field(f) => *f,
            _ => {
                bail!("Mux plugin does not support plugin types");
            }
        };
        Ok(PluginExecution::Mux(MuxVersion::MuxVerV0(MuxV0::new(
            type_id,
            cond_num_wire.try_into().unwrap(),
            selector_range,
            branch_shape,
            is_permissive,
            field_type_id,
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
        type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> Result<PluginExecution> {
        match MuxV0::instantiate(
            operation,
            params,
            output_counts,
            input_counts,
            type_store,
            _fun_store,
        )? {
            PluginExecution::Mux(p) => match p {
                MuxVersion::MuxVerV0(m) => Ok(PluginExecution::Mux(MuxVersion::MuxVerV1(MuxV1(m)))),
                _ => panic!("Broken invariant: should return a MuxV0"),
            },
            _ => panic!("Broken invariant: should return a Mux"),
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

    // test for mux wire vector of wires for the condition
    #[test]
    fn test_f2_mux_cond_vec() {
        let fields = vec![F2_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 2), (FF0, 1), (FF0, 1), (FF0, 1), (FF0, 1)],
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
            GateM::New(FF0, 0, 14),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Instance(FF0, 6),
            GateM::Instance(FF0, 7),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(10, 10)],
                vec![(0, 1), (4, 4), (5, 5), (6, 6), (7, 7)],
            ))),
            GateM::AssertZero(FF0, 12),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(11, 11)],
                vec![(2, 3), (4, 4), (5, 5), (6, 6), (7, 7)],
            ))),
            GateM::AddConstant(FF0, 12, 11, Box::from(minus_one::<F2>())),
            GateM::AssertZero(FF0, 12),
        ];

        let instances = vec![vec![zero::<F2>(), zero::<F2>(), one::<F2>(), zero::<F2>()]];
        let witnesses = vec![vec![zero::<F2>(), zero::<F2>(), one::<F2>(), zero::<F2>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    // test for mux wire vector of wires for the condition,
    // fails when strict and succeeds when permissive
    #[test]
    fn test_f2_mux_cond_vec_strict_fails() {
        let fields = vec![F2_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 2), (FF0, 1), (FF0, 1), (FF0, 1)],
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

        let mut gates = vec![
            GateM::New(FF0, 0, 14),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Instance(FF0, 6),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(10, 10)],
                vec![(0, 1), (4, 4), (5, 5), (6, 6)],
            ))),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(11, 11)],
                vec![(2, 3), (4, 4), (5, 5), (6, 6)],
            ))),
            // No check zero here because we want the circuit to fail because of strict
        ];

        let instances = vec![vec![one::<F2>(), one::<F2>(), one::<F2>()]];
        let witnesses = vec![vec![zero::<F2>(), zero::<F2>(), one::<F2>(), one::<F2>()]];

        if !test_circuit(
            fields.clone(),
            func_store,
            gates.clone(),
            instances.clone(),
            witnesses.clone(),
        )
        .is_err()
        {
            panic!("This circuit should fail because it's strict")
        };

        let mut func_store = FunStore::default();
        let func = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 2), (FF0, 1), (FF0, 1), (FF0, 1)],
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

        // We add the checks to make sure the computation is correct
        gates.push(GateM::AddConstant(
            FF0,
            12,
            10,
            Box::from(minus_one::<F2>()),
        ));
        gates.push(GateM::AssertZero(FF0, 12));
        gates.push(GateM::AssertZero(FF0, 11));

        test_circuit(fields.clone(), func_store, gates, instances, witnesses).unwrap();

        let mut func_store = FunStore::default();
        let func = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 4), (FF0, 1), (FF0, 1), (FF0, 1)],
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
            GateM::New(FF0, 0, 14),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Witness(FF0, 4),
            GateM::Witness(FF0, 5),
            GateM::Witness(FF0, 6),
            GateM::Witness(FF0, 7),
            GateM::Instance(FF0, 8),
            GateM::Instance(FF0, 9),
            GateM::Instance(FF0, 10),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(11, 11)],
                vec![(0, 3), (8, 8), (9, 9), (10, 10)],
            ))),
            GateM::Call(Box::new((
                "my_mux".into(),
                vec![(12, 12)],
                vec![(4, 7), (8, 8), (9, 9), (10, 10)],
            ))),
            // No check zero here because we want the circuit to fail because of strict
        ];

        let instances = vec![vec![one::<F2>(), one::<F2>(), one::<F2>()]];
        let witnesses = vec![vec![
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(), // 0001
            one::<F2>(),
            zero::<F2>(),
            zero::<F2>(),
            zero::<F2>(), // 1000
        ]];

        if !test_circuit(fields.clone(), func_store, gates, instances, witnesses).is_err() {
            panic!("This circuit should fail because it's strict")
        };
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
            // No check here because we want the circuit to fail because of strict
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
            GateM::AssertZero(FF0, 40),
            GateM::AssertZero(FF0, 41),
            GateM::AssertZero(FF0, 42),
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
