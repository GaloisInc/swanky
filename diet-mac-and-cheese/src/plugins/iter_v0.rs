use super::{Plugin, PluginExecution};
use crate::circuit_ir::{
    first_unused_wire_id, FunStore, FuncDecl, GateM, GatesBody, TypeId, TypeStore, WireCount,
    WireId, WireRange,
};
use eyre::Context;
use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};

pub(crate) struct IterV0;

impl Plugin for IterV0 {
    const NAME: &'static str = "iter_v0";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
        fun_store: &FunStore,
    ) -> eyre::Result<PluginExecution> {
        fn ranges_for_iteration(
            which_iteration: u64,
            mut starting_id: WireId,
            iterated_counts: &[(TypeId, WireCount)],
            f_counts: &[(TypeId, WireCount)],
        ) -> Vec<WireRange> {
            let mut res = Vec::with_capacity(f_counts.len());
            for (&(_, wc), &(_, wc_f)) in iterated_counts.iter().zip(f_counts) {
                let offset_start = starting_id + which_iteration * wc_f;

                res.push((offset_start, offset_start + wc_f - 1));

                starting_id += wc;
            }

            res
        }

        let enumerated = match operation {
            "map" => false,
            "map_enumerated" => true,
            _ => eyre::bail!("{}: Unknown operation {operation}.", Self::NAME),
        };

        eyre::ensure!(
            params.len() == 3,
            "{}: {operation} expects 3 parametesr, but {} were given.",
            Self::NAME,
            params.len(),
        );

        let PluginTypeArg::String(ref func_name) = params[0] else {
            eyre::bail!("{}: The function name parameter must be a string.", Self::NAME);
        };

        let FuncDecl {
            output_counts: f_output_counts,
            input_counts: f_input_counts,
            ..
        } = fun_store.get(func_name).with_context(|| {
            eyre::eyre!(
                "{}: A function named {func_name} was not found.",
                Self::NAME
            )
        })?;

        eyre::ensure!(
            output_counts.len() == f_output_counts.len(),
            "{}: {operation} should return the same number of output ranges as {func_name}: {} != {}.",
            Self::NAME,
            output_counts.len(),
            f_output_counts.len(),
        );

        // Functions used with map_enumerated expect an additional input range
        eyre::ensure!(
            input_counts.len() == f_input_counts.len() - if enumerated { 1 } else { 0 },
            "{}: {operation} expected {} inputs, but got {}.",
            Self::NAME,
            input_counts.len(),
            f_input_counts.len() - if enumerated { 1 } else { 0 },
        );

        let PluginTypeArg::Number(num_env) = params[1] else {
            eyre::bail!("{}: The #env parameter must be numeric.", Self::NAME);
        };
        // TODO: Should we assume this param fits in a u64?
        let num_env = num_env.as_words()[0];

        let PluginTypeArg::Number(iter_count) = params[2] else {
            eyre::bail!("{}: The iteration count parameter must be numeric.", Self::NAME);
        };
        // TODO: Should we assume this param fits in a u64?
        let iter_count: u64 = iter_count.as_words()[0].into();

        for (i, (&(t, wc), &(t_f, wc_f))) in output_counts.iter().zip(f_output_counts).enumerate() {
            eyre::ensure!(
                t == t_f,
                "{}: The output at position {i} has type {t}, but {func_name} expects {t_f}.",
                Self::NAME,
            );

            eyre::ensure!(
                wc == wc_f * iter_count,
                "{}: The output at position {i} should be {iter_count} times as large as the corresponding output of {func_name}: {wc} != {wc_f} * {iter_count}.",
                Self::NAME,
            );
        }

        for (i, ((t, wc), (t_f, wc_f))) in input_counts[..num_env as usize]
            .iter()
            .zip(&f_input_counts[..num_env as usize])
            .enumerate()
        {
            eyre::ensure!(
                t == t_f,
                "{}: The parameter at position {i} has type {t}, but {func_name} expects {t_f}.",
                Self::NAME,
            );

            eyre::ensure!(
            wc == wc_f,
            "{}: The input at position {i} must have exactly the same count as the corresponding input of {func_name}: {wc} != {wc_f}.",
            Self::NAME,
        );
        }

        let input_start = if enumerated {
            num_env as usize + 1
        } else {
            num_env as usize
        };

        for (i, (&(t, wc), &(t_f, wc_f))) in input_counts[num_env as usize..]
            .iter()
            .zip(&f_input_counts[input_start..])
            .enumerate()
        {
            eyre::ensure!(
                t == t_f,
                "{}: The parameter at position {i} has type {t}, but {func_name} expects {t_f}.",
                Self::NAME,
            );

            eyre::ensure!(
                wc == wc_f * iter_count,
                "{}: The input at position {i} should be {iter_count} times as large as the corresponding input of {func_name}: {wc} != {wc_f} * {iter_count}.",
                Self::NAME,
            );
        }

        let mut gates = Vec::with_capacity(if enumerated {
            2 * iter_count as usize
        } else {
            iter_count as usize
        });

        // Compute ID of the first input wire
        let mut first_input_wire = 0;
        for (_, wc) in output_counts {
            first_input_wire += wc;
        }

        if enumerated {
            let counter_type = f_input_counts[num_env as usize].0;
            let mut counter_wire = first_unused_wire_id(output_counts, input_counts);

            for i in 0..iter_count {
                gates.push(GateM::Constant(
                    counter_type,
                    counter_wire,
                    Box::new(Number::from_u64(i)),
                ));

                let outs = ranges_for_iteration(i, 0, output_counts, f_output_counts);

                // Seed Vec of inputs with the closure environment inputs.
                // After this loop, curr_input_wire will be the ID of the first
                // 'normal' input wire.
                let mut curr_env_wire = first_input_wire;
                let mut ins = vec![];
                for &(_, wc) in &input_counts[..num_env as usize] {
                    ins.push((curr_env_wire, curr_env_wire + wc - 1));
                    curr_env_wire += wc;
                }

                // TODO: Assumes counter is on one wire, but the spec actually
                // accepts any type/count for this input, where many wires are
                // interpreted as a single big-endian number.
                ins.push((counter_wire, counter_wire));

                ins.append(&mut ranges_for_iteration(
                    i,
                    curr_env_wire,
                    &input_counts[num_env as usize..],
                    &f_input_counts[input_start..],
                ));

                gates.push(GateM::Call(Box::new((func_name.clone(), outs, ins))));

                counter_wire += 1;
            }
        } else {
            for i in 0..iter_count {
                let outs = ranges_for_iteration(i, 0, output_counts, f_output_counts);

                let mut curr_env_wire = first_input_wire;
                let mut ins = vec![];
                for &(_, wc) in &input_counts[..num_env as usize] {
                    ins.push((curr_env_wire, curr_env_wire + wc - 1));
                    curr_env_wire += wc;
                }
                ins.append(&mut ranges_for_iteration(
                    i,
                    curr_env_wire,
                    &input_counts[num_env as usize..],
                    &f_input_counts[input_start..],
                ));

                gates.push(GateM::Call(Box::new((func_name.clone(), outs, ins))));
            }
        }

        Ok(GatesBody::new(gates).into())
    }
}

#[cfg(test)]
mod tests {
    use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};
    use scuttlebutt::field::F61p;

    use crate::{
        backend_multifield::tests::{
            minus_four, minus_one, minus_three, minus_two, test_circuit, zero, FF0,
        },
        circuit_ir::{FunStore, FuncDecl, GateM, TypeStore},
        fields::F61P_MODULUS,
        plugins::Plugin,
    };

    use super::IterV0;

    #[test]
    fn test_iter_map() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_function(
            vec![
                GateM::Add(FF0, 100, 1, 2),
                GateM::Add(FF0, 101, 3, 4),
                GateM::Add(FF0, 102, 5, 6),
                GateM::Add(FF0, 103, 100, 101),
                GateM::Add(FF0, 0, 102, 103),
            ],
            vec![(FF0, 1)],
            vec![(FF0, 1), (FF0, 2), (FF0, 3)],
        );

        func_store.insert("f".into(), func);

        let map_func = FuncDecl::new_plugin(
            vec![(FF0, 5)],
            vec![(FF0, 1), (FF0, 10), (FF0, 15)],
            IterV0::NAME.into(),
            "map".into(),
            vec![
                PluginTypeArg::String("f".into()),
                PluginTypeArg::Number(Number::from_u64(1)),
                PluginTypeArg::Number(Number::from_u64(5)),
            ],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_map".into(), map_func);

        let gates = vec![
            GateM::New(FF0, 0, 4),
            GateM::New(FF0, 100, 100),
            GateM::New(FF0, 200, 209),
            GateM::New(FF0, 300, 314),
            GateM::Witness(FF0, 100),
            GateM::Witness(FF0, 200),
            GateM::Witness(FF0, 201),
            GateM::Witness(FF0, 202),
            GateM::Witness(FF0, 203),
            GateM::Witness(FF0, 204),
            GateM::Witness(FF0, 205),
            GateM::Witness(FF0, 206),
            GateM::Witness(FF0, 207),
            GateM::Witness(FF0, 208),
            GateM::Witness(FF0, 209),
            GateM::Witness(FF0, 300),
            GateM::Witness(FF0, 301),
            GateM::Witness(FF0, 302),
            GateM::Witness(FF0, 303),
            GateM::Witness(FF0, 304),
            GateM::Witness(FF0, 305),
            GateM::Witness(FF0, 306),
            GateM::Witness(FF0, 307),
            GateM::Witness(FF0, 308),
            GateM::Witness(FF0, 309),
            GateM::Witness(FF0, 310),
            GateM::Witness(FF0, 311),
            GateM::Witness(FF0, 312),
            GateM::Witness(FF0, 313),
            GateM::Witness(FF0, 314),
            GateM::Call(Box::new((
                "my_map".into(),
                vec![(0, 4)],
                vec![(100, 100), (200, 209), (300, 314)],
            ))),
            GateM::AssertZero(FF0, 0),
            GateM::AssertZero(FF0, 1),
            GateM::AssertZero(FF0, 2),
            GateM::AssertZero(FF0, 3),
            GateM::AssertZero(FF0, 4),
        ];

        let instances = vec![];

        let witnesses = vec![vec![
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
        ]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }

    #[test]
    fn test_iter_map_enumerated() {
        let fields = vec![F61P_MODULUS];
        let mut func_store = FunStore::default();
        let type_store = TypeStore::try_from(fields.clone()).unwrap();

        let func = FuncDecl::new_function(
            vec![
                GateM::Add(FF0, 100, 1, 2),
                GateM::Add(FF0, 101, 3, 4),
                GateM::Add(FF0, 102, 5, 6),
                GateM::Add(FF0, 103, 100, 101),
                GateM::Add(FF0, 0, 102, 103),
            ],
            vec![(FF0, 1)],
            vec![(FF0, 1), (FF0, 1), (FF0, 2), (FF0, 3)],
        );

        func_store.insert("f".into(), func);

        let map_func = FuncDecl::new_plugin(
            vec![(FF0, 5)],
            vec![(FF0, 1), (FF0, 10), (FF0, 15)],
            IterV0::NAME.into(),
            "map_enumerated".into(),
            vec![
                PluginTypeArg::String("f".into()),
                PluginTypeArg::Number(Number::from_u64(1)),
                PluginTypeArg::Number(Number::from_u64(5)),
            ],
            vec![],
            vec![],
            &type_store,
            &func_store,
        )
        .unwrap();

        func_store.insert("my_map_enumerated".into(), map_func);

        let gates = vec![
            GateM::New(FF0, 0, 4),
            GateM::New(FF0, 100, 100),
            GateM::New(FF0, 200, 209),
            GateM::New(FF0, 300, 314),
            GateM::Witness(FF0, 100),
            GateM::Witness(FF0, 200),
            GateM::Witness(FF0, 201),
            GateM::Witness(FF0, 202),
            GateM::Witness(FF0, 203),
            GateM::Witness(FF0, 204),
            GateM::Witness(FF0, 205),
            GateM::Witness(FF0, 206),
            GateM::Witness(FF0, 207),
            GateM::Witness(FF0, 208),
            GateM::Witness(FF0, 209),
            GateM::Witness(FF0, 300),
            GateM::Witness(FF0, 301),
            GateM::Witness(FF0, 302),
            GateM::Witness(FF0, 303),
            GateM::Witness(FF0, 304),
            GateM::Witness(FF0, 305),
            GateM::Witness(FF0, 306),
            GateM::Witness(FF0, 307),
            GateM::Witness(FF0, 308),
            GateM::Witness(FF0, 309),
            GateM::Witness(FF0, 310),
            GateM::Witness(FF0, 311),
            GateM::Witness(FF0, 312),
            GateM::Witness(FF0, 313),
            GateM::Witness(FF0, 314),
            GateM::Call(Box::new((
                "my_map_enumerated".into(),
                vec![(0, 4)],
                vec![(100, 100), (200, 209), (300, 314)],
            ))),
            GateM::AssertZero(FF0, 0),
            GateM::AddConstant(FF0, 1001, 1, Box::new(minus_one::<F61p>())),
            GateM::AssertZero(FF0, 1001),
            GateM::AddConstant(FF0, 1002, 2, Box::new(minus_two::<F61p>())),
            GateM::AssertZero(FF0, 1002),
            GateM::AddConstant(FF0, 1003, 3, Box::new(minus_three::<F61p>())),
            GateM::AssertZero(FF0, 1003),
            GateM::AddConstant(FF0, 1004, 4, Box::new(minus_four::<F61p>())),
            GateM::AssertZero(FF0, 1004),
        ];

        let instances = vec![];

        let witnesses = vec![vec![
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
            zero::<F61p>(),
        ]];

        test_circuit(fields, func_store, gates, instances, witnesses).unwrap();
    }
}
