use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};

use crate::circuit_ir::{
    first_unused_wire_id, FunStore, GateM, GatesBody, TypeId, TypeSpecification, TypeStore,
    WireCount,
};

use super::{Plugin, PluginExecution};

pub(crate) struct VectorsV1;

impl Plugin for VectorsV1 {
    const NAME: &'static str = "vectors_v1";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> eyre::Result<PluginExecution> {
        eyre::ensure!(
            output_counts.len() == 1,
            "{}: {operation} outputs 1 wire range, but this declaration specifies {}.",
            Self::NAME,
            output_counts.len(),
        );

        let t = output_counts[0].0;
        let TypeSpecification::Field(_) = type_store.get(&t)? else {
            eyre::bail!("{}: {operation} expects only field-typed inputs and outputs, but the type with index {} is plugin-defined.", Self::NAME, t);
        };

        match operation {
            "add" | "mul" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 2,
                    "{}: {operation} takes 2 wire ranges as input, but this declaration specifics {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                eyre::ensure!(
                    input_counts[0].0 == input_counts[1].0,
                    "{}: The type indices of the inputs to {operation} must match: {} != {}.",
                    Self::NAME,
                    input_counts[0].0,
                    input_counts[1].0,
                );

                eyre::ensure!(
                    input_counts[0].1 == input_counts[1].1,
                    "{}: The lengths of the inputs to {operation} must match: {} != {}.",
                    Self::NAME,
                    input_counts[0].1,
                    input_counts[1].1,
                );

                eyre::ensure!(
                    output_counts[0].0 == input_counts[0].0,
                    "{}: The type of the output of {operation} must match the types of the inputs: {} != {}.",
                    Self::NAME,
                    output_counts[0].0,
                    input_counts[0].0,
                );

                eyre::ensure!(
                    output_counts[0].1 == input_counts[0].1,
                    "{}: The length of the output of {operation} must match the lengths of the inputs: {} != {}.",
                    Self::NAME,
                    output_counts[0].1,
                    input_counts[0].1,
                );

                let s = output_counts[0].1;

                let mut gates = Vec::with_capacity(s as usize);
                for i in 0..s {
                    gates.push(match operation {
                        "add" => GateM::Add(t, i, s + i, 2 * s + i),
                        "mul" => GateM::Mul(t, i, s + i, 2 * s + i),
                        _ => unreachable!(),
                    });
                }

                Ok(GatesBody::new(gates).into())
            }
            "addc" | "mulc" => {
                eyre::ensure!(
                    params.len() == 1,
                    "{}: {operation} expects 1 parameter (the constant), but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 1,
                    "{}: {operation} takes 1 wire range as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                eyre::ensure!(
                    output_counts[0].0 == input_counts[0].0,
                    "{}: The type of the output of {operation} must match the type of the input: {} != {}.",
                    Self::NAME,
                    output_counts[0].0,
                    input_counts[0].0,
                );

                eyre::ensure!(
                    output_counts[0].1 == input_counts[0].1,
                    "{}: The length of the output of {operation} must match the length of the input: {} != {}.",
                    Self::NAME,
                    output_counts[0].1,
                    input_counts[0].1,
                );

                let s = output_counts[0].1;

                let PluginTypeArg::Number(c) = params[0] else {
                    eyre::bail!("{}: The constant parameter must be numeric, not a string.", Self::NAME);
                };

                let mut gates = Vec::with_capacity(s as usize);
                for i in 0..s {
                    gates.push(match operation {
                        "addc" => GateM::AddConstant(t, i, s + i, Box::new(c)),
                        "mulc" => GateM::MulConstant(t, i, s + i, Box::new(c)),
                        _ => unreachable!(),
                    });
                }

                Ok(GatesBody::new(gates).into())
            }
            "add_scalar" | "mul_scalar" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 2,
                    "{}: {operation} takes 2 wire ranges as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                eyre::ensure!(
                    input_counts[0].0 == input_counts[1].0,
                    "{}: The type indices of the inputs to {operation} must match: {} != {}.",
                    Self::NAME,
                    input_counts[0].0,
                    input_counts[1].0,
                );

                eyre::ensure!(
                    output_counts[0].0 == input_counts[0].0,
                    "{}: The type of the output of {operation} must match the types of the inputs: {} != {}.",
                    Self::NAME,
                    output_counts[0].0,
                    input_counts[0].0,
                );

                eyre::ensure!(
                    output_counts[0].1 == input_counts[0].1,
                    "{}: The length of the output of {operation} must match the length of the vector input: {} != {}",
                    Self::NAME,
                    output_counts[0].1,
                    input_counts[0].1,
                );

                eyre::ensure!(
                    input_counts[1].1 == 1,
                    "{}: The scalar input to {operation} must be given on a single wire.",
                    Self::NAME,
                );

                let s = output_counts[0].1;

                let scalar = first_unused_wire_id(output_counts, input_counts) - 1;

                let mut gates = Vec::with_capacity(s as usize);
                for i in 0..s {
                    gates.push(match operation {
                        "add_scalar" => GateM::Add(t, i, s + i, scalar),
                        "mul_scalar" => GateM::Mul(t, i, s + i, scalar),
                        _ => unreachable!(),
                    });
                }

                Ok(GatesBody::new(gates).into())
            }
            "sum" | "product" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}; {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 1,
                    "{}: {operation} takes 1 wire range as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                eyre::ensure!(
                    output_counts[0].0 == input_counts[0].0,
                    "{}: The type of the output of {operation} must match the type of the input: {} != {}.",
                    Self::NAME,
                    output_counts[0].0,
                    input_counts[0].0,
                );

                eyre::ensure!(
                    output_counts[0].1 == 1,
                    "{}: The length of the output of {operation} must be 1, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts[0].1,
                );

                let s = input_counts[0].1;

                let mut gates = Vec::with_capacity(match s {
                    0 | 1 | 2 => 1,
                    _ => s as usize,
                });
                match s {
                    0 => gates.push(match operation {
                        "sum" => GateM::Constant(t, 0, Box::new(Number::ZERO)),
                        "product" => GateM::Constant(t, 0, Box::new(Number::ONE)),
                        _ => unreachable!(),
                    }),
                    1 => gates.push(GateM::Copy(t, 0, 1)),
                    2 => gates.push(match operation {
                        "sum" => GateM::Add(t, 0, 1, 2),
                        "product" => GateM::Mul(t, 0, 1, 2),
                        _ => unreachable!(),
                    }),
                    _ => {
                        let mut res = first_unused_wire_id(output_counts, input_counts);

                        gates.push(match operation {
                            "sum" => GateM::Add(t, res, 1, 2),
                            "product" => GateM::Mul(t, res, 1, 2),
                            _ => unreachable!(),
                        });

                        for i in 3..=s {
                            gates.push(match operation {
                                "sum" => GateM::Add(t, res + 1, res, i),
                                "product" => GateM::Mul(t, res + 1, res, i),
                                _ => unreachable!(),
                            });

                            res += 1;
                        }

                        gates.push(GateM::Copy(t, 0, res));
                    }
                };

                Ok(GatesBody::new(gates).into())
            }
            "dotproduct" => {
                eyre::ensure!(
                    params.len() == 0,
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                eyre::ensure!(
                    input_counts.len() == 2,
                    "{}: {operation} takes 2 wire ranges as input, but this declarations specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                eyre::ensure!(
                    input_counts[0].0 == input_counts[1].0,
                    "{}: The type indices of the inputs to {operation} must match: {} != {}.",
                    Self::NAME,
                    input_counts[0].0,
                    input_counts[1].0,
                );

                eyre::ensure!(
                    input_counts[0].1 == input_counts[1].1,
                    "{}: The lengths of the inputs to {operation} must match: {} != {}.",
                    Self::NAME,
                    input_counts[0].1,
                    input_counts[1].1,
                );

                eyre::ensure!(
                    output_counts[0].0 == input_counts[0].0,
                    "{}: The type of the output of {operation} must match the types of the inputs: {} != {}.",
                    Self::NAME,
                    output_counts[0].0,
                    input_counts[0].0,
                );

                eyre::ensure!(
                    output_counts[0].1 == 1,
                    "{}: The length of the output of {operation} must be 1, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts[0].1,
                );

                let s = input_counts[0].1;

                let first_mul = first_unused_wire_id(output_counts, input_counts);

                let mut gates = Vec::with_capacity(match s {
                    0 | 1 => 1,
                    2 => 3,
                    _ => 2 * s as usize,
                });
                match s {
                    0 => gates.push(GateM::Constant(t, 0, Box::new(Number::ZERO))),
                    1 => gates.push(GateM::Mul(t, 0, 1, 2)),
                    2 => gates.append(&mut vec![
                        GateM::Mul(t, first_mul, 1, 3),
                        GateM::Mul(t, first_mul + 1, 2, 4),
                        GateM::Add(t, 0, first_mul, first_mul + 1),
                    ]),
                    _ => {
                        for i in 1..=s {
                            gates.push(GateM::Mul(t, first_mul + i - 1, i, s + i));
                        }

                        let mut res = first_mul + s;

                        gates.push(GateM::Add(t, res, first_mul, first_mul + 1));

                        for i in (first_mul + 2)..(first_mul + s) {
                            gates.push(GateM::Add(t, res + 1, res, i));

                            res += 1;
                        }

                        gates.push(GateM::Copy(t, 0, res));
                    }
                };

                Ok(GatesBody::new(gates).into())
            }
            _ => eyre::bail!("{}: Unknown operation: {operation}", Self::NAME,),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VectorsV1;
    use crate::{
        backend_multifield::tests::{minus_one, one, test_circuit, zero, FF0},
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
        fields::F61P_MODULUS,
        plugins::Plugin,
    };
    use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};
    use scuttlebutt::field::F61p;

    #[test]
    fn test_vector_add() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 3), (FF0, 3)],
            VectorsV1::NAME.into(),
            "add".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_add".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 2),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::New(FF0, 3, 5),
            GateM::Instance(FF0, 3),
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Call(Box::new((
                "my_add".into(),
                vec![(6, 8)],
                vec![(0, 2), (3, 5)],
            ))),
            GateM::AssertZero(FF0, 6),
            GateM::AssertZero(FF0, 7),
            GateM::AssertZero(FF0, 8),
        ];

        let instances = vec![vec![
            minus_one::<F61p>(),
            one::<F61p>(),
            minus_one::<F61p>(),
        ]];

        let witnesses = vec![vec![one::<F61p>(), minus_one::<F61p>(), one::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_vector_mul() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 3), (FF0, 3)],
            VectorsV1::NAME.into(),
            "mul".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mul".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 2),
            GateM::Witness(FF0, 0),
            GateM::Witness(FF0, 1),
            GateM::Witness(FF0, 2),
            GateM::New(FF0, 3, 5),
            GateM::Instance(FF0, 3),
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Call(Box::new((
                "my_mul".into(),
                vec![(6, 8)],
                vec![(0, 2), (3, 5)],
            ))),
            GateM::AssertZero(FF0, 6),
            GateM::AssertZero(FF0, 7),
            GateM::AssertZero(FF0, 8),
        ];

        let instances = vec![vec![one::<F61p>(), zero::<F61p>(), one::<F61p>()]];

        let witnesses = vec![vec![zero::<F61p>(), one::<F61p>(), zero::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_vector_addc() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 3)],
            VectorsV1::NAME.into(),
            "addc".into(),
            vec![PluginTypeArg::Number(Number::ONE)],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_addc".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 2),
            GateM::Instance(FF0, 0),
            GateM::Instance(FF0, 1),
            GateM::Instance(FF0, 2),
            GateM::Call(Box::new(("my_addc".into(), vec![(3, 5)], vec![(0, 2)]))),
            GateM::AssertZero(FF0, 3),
            GateM::AssertZero(FF0, 4),
            GateM::AssertZero(FF0, 5),
        ];

        let instances = vec![vec![
            minus_one::<F61p>(),
            minus_one::<F61p>(),
            minus_one::<F61p>(),
        ]];

        let witnesses = vec![vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_vector_mulc() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 3)],
            VectorsV1::NAME.into(),
            "mulc".into(),
            vec![PluginTypeArg::Number(Number::ZERO)],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mulc".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 2),
            GateM::Instance(FF0, 0),
            GateM::Instance(FF0, 1),
            GateM::Instance(FF0, 2),
            GateM::Call(Box::new(("my_mulc".into(), vec![(3, 5)], vec![(0, 2)]))),
            GateM::AssertZero(FF0, 3),
            GateM::AssertZero(FF0, 4),
            GateM::AssertZero(FF0, 5),
        ];

        let instances = vec![vec![one::<F61p>(), one::<F61p>(), one::<F61p>()]];

        let witnesses = vec![vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_vector_add_scalar() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 3), (FF0, 1)],
            VectorsV1::NAME.into(),
            "add_scalar".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_add_scalar".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 2),
            GateM::Instance(FF0, 0),
            GateM::Instance(FF0, 1),
            GateM::Instance(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Call(Box::new((
                "my_add_scalar".into(),
                vec![(4, 6)],
                vec![(0, 2), (3, 3)],
            ))),
            GateM::AssertZero(FF0, 4),
            GateM::AssertZero(FF0, 5),
            GateM::AssertZero(FF0, 6),
        ];

        let instances = vec![vec![
            minus_one::<F61p>(),
            minus_one::<F61p>(),
            minus_one::<F61p>(),
        ]];

        let witnesses = vec![vec![one::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_vector_mul_scalar() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_plugin(
            vec![(FF0, 3)],
            vec![(FF0, 3), (FF0, 1)],
            VectorsV1::NAME.into(),
            "mul_scalar".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_mul_scalar".into(), func);

        let gates = vec![
            GateM::New(FF0, 0, 2),
            GateM::Instance(FF0, 0),
            GateM::Instance(FF0, 1),
            GateM::Instance(FF0, 2),
            GateM::Witness(FF0, 3),
            GateM::Call(Box::new((
                "my_mul_scalar".into(),
                vec![(4, 6)],
                vec![(0, 2), (3, 3)],
            ))),
            GateM::AssertZero(FF0, 4),
            GateM::AssertZero(FF0, 5),
            GateM::AssertZero(FF0, 6),
        ];

        let instances = vec![vec![one::<F61p>(), one::<F61p>(), one::<F61p>()]];

        let witnesses = vec![vec![zero::<F61p>()]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_vector_sum() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let sum_one = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 1)],
            VectorsV1::NAME.into(),
            "sum".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let sum_two = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 2)],
            VectorsV1::NAME.into(),
            "sum".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let sum_three = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 3)],
            VectorsV1::NAME.into(),
            "sum".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let sum_four = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 4)],
            VectorsV1::NAME.into(),
            "sum".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("sum_one".into(), sum_one);
        func_store.insert("sum_two".into(), sum_two);
        func_store.insert("sum_three".into(), sum_three);
        func_store.insert("sum_four".into(), sum_four);

        let gates = vec![
            GateM::New(FF0, 0, 3),
            GateM::Instance(FF0, 0),
            GateM::Instance(FF0, 1),
            GateM::Instance(FF0, 2),
            GateM::Instance(FF0, 3),
            GateM::Call(Box::new(("sum_one".into(), vec![(4, 4)], vec![(0, 0)]))),
            GateM::Call(Box::new(("sum_two".into(), vec![(5, 5)], vec![(1, 2)]))),
            GateM::Call(Box::new(("sum_three".into(), vec![(6, 6)], vec![(0, 2)]))),
            GateM::Call(Box::new(("sum_four".into(), vec![(7, 7)], vec![(0, 3)]))),
            GateM::AssertZero(FF0, 4),
            GateM::AssertZero(FF0, 5),
            GateM::AssertZero(FF0, 6),
            GateM::AssertZero(FF0, 7),
        ];

        let instances = vec![vec![
            zero::<F61p>(),
            one::<F61p>(),
            minus_one::<F61p>(),
            zero::<F61p>(),
        ]];

        let witnesses = vec![vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_vector_product() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let mul_one = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 1)],
            VectorsV1::NAME.into(),
            "product".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let mul_two = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 2)],
            VectorsV1::NAME.into(),
            "product".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let mul_three = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 3)],
            VectorsV1::NAME.into(),
            "product".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let mul_four = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 4)],
            VectorsV1::NAME.into(),
            "product".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("mul_one".into(), mul_one);
        func_store.insert("mul_two".into(), mul_two);
        func_store.insert("mul_three".into(), mul_three);
        func_store.insert("mul_four".into(), mul_four);

        let gates = vec![
            GateM::New(FF0, 0, 3),
            GateM::Instance(FF0, 0),
            GateM::Instance(FF0, 1),
            GateM::Instance(FF0, 2),
            GateM::Instance(FF0, 3),
            GateM::Call(Box::new(("mul_one".into(), vec![(4, 4)], vec![(0, 0)]))),
            GateM::Call(Box::new(("mul_two".into(), vec![(5, 5)], vec![(0, 1)]))),
            GateM::Call(Box::new(("mul_three".into(), vec![(6, 6)], vec![(0, 2)]))),
            GateM::Call(Box::new(("mul_four".into(), vec![(7, 7)], vec![(0, 3)]))),
            GateM::AssertZero(FF0, 4),
            GateM::AssertZero(FF0, 5),
            GateM::AssertZero(FF0, 6),
            GateM::AssertZero(FF0, 7),
        ];

        let instances = vec![vec![
            zero::<F61p>(),
            one::<F61p>(),
            minus_one::<F61p>(),
            one::<F61p>(),
        ]];

        let witnesses = vec![vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_vector_dotproduct() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let dot_one = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 1), (FF0, 1)],
            VectorsV1::NAME.into(),
            "dotproduct".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let dot_two = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 2), (FF0, 2)],
            VectorsV1::NAME.into(),
            "dotproduct".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let dot_three = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 3), (FF0, 3)],
            VectorsV1::NAME.into(),
            "dotproduct".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        let dot_four = FuncDecl::new_plugin(
            vec![(FF0, 1)],
            vec![(FF0, 4), (FF0, 4)],
            VectorsV1::NAME.into(),
            "dotproduct".into(),
            vec![],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("dot_one".into(), dot_one);
        func_store.insert("dot_two".into(), dot_two);
        func_store.insert("dot_three".into(), dot_three);
        func_store.insert("dot_four".into(), dot_four);

        let gates = vec![
            GateM::New(FF0, 0, 3),
            GateM::Instance(FF0, 0),
            GateM::Instance(FF0, 1),
            GateM::Instance(FF0, 2),
            GateM::Instance(FF0, 3),
            GateM::New(FF0, 4, 7),
            GateM::Instance(FF0, 4),
            GateM::Instance(FF0, 5),
            GateM::Instance(FF0, 6),
            GateM::Instance(FF0, 7),
            GateM::Call(Box::new((
                "dot_one".into(),
                vec![(8, 8)],
                vec![(0, 0), (4, 4)],
            ))),
            GateM::Call(Box::new((
                "dot_two".into(),
                vec![(9, 9)],
                vec![(0, 1), (4, 5)],
            ))),
            GateM::Call(Box::new((
                "dot_three".into(),
                vec![(10, 10)],
                vec![(0, 2), (4, 6)],
            ))),
            GateM::Call(Box::new((
                "dot_four".into(),
                vec![(11, 11)],
                vec![(0, 3), (4, 7)],
            ))),
            GateM::AssertZero(FF0, 8),
            GateM::AssertZero(FF0, 9),
            GateM::AssertZero(FF0, 10),
            GateM::AssertZero(FF0, 11),
        ];

        let instances = vec![vec![
            zero::<F61p>(),
            one::<F61p>(),
            zero::<F61p>(),
            one::<F61p>(),
            one::<F61p>(),
            zero::<F61p>(),
            one::<F61p>(),
            zero::<F61p>(),
        ]];

        let witnesses = vec![vec![]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }
}
