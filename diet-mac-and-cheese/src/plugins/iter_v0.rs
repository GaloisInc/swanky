use eyre::Context;
use mac_n_cheese_sieve_parser::PluginTypeArg;

use crate::circuit_ir::{
    first_unused_wire_id, FunStore, FuncDecl, GateM, GatesBody, TypeId, TypeStore, WireCount,
    WireId, WireRange,
};

use super::Plugin;

pub(crate) struct IterV0;

impl Plugin for IterV0 {
    const NAME: &'static str = "iter_v0";

    fn gates_body(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
        fun_store: &FunStore,
    ) -> eyre::Result<GatesBody> {
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
        let iter_count = iter_count.as_words()[0];

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
        let mut curr_input_wire = 0;
        for (_, wc) in output_counts {
            curr_input_wire += wc;
        }

        if enumerated {
            let counter_type = f_input_counts[num_env as usize].0;
            let mut counter_wire = first_unused_wire_id(output_counts, input_counts);

            for i in 0..iter_count {
                // TODO: This seems a little bit sus. Do we need to do something more clever?
                gates.push(GateM::Constant(
                    counter_type,
                    counter_wire,
                    Box::new(i.to_le_bytes().to_vec()),
                ));

                let outs = ranges_for_iteration(i, 0, output_counts, f_output_counts);

                // Seed Vec of inputs with the closure environment inputs.
                // After this loop, curr_input_wire will be the ID of the first
                // 'normal' input wire.
                let mut ins = vec![];
                for &(_, wc) in &input_counts[..num_env as usize] {
                    ins.push((curr_input_wire, curr_input_wire + wc - 1));
                    curr_input_wire += wc;
                }

                // TODO: Assumes counter is on one wire, but the spec actually
                // accepts any type/count for this input, where many wires are
                // interpreted as a single big-endian number.
                ins.push((counter_wire, counter_wire));

                ins.append(&mut ranges_for_iteration(
                    i,
                    curr_input_wire,
                    &input_counts[num_env as usize..],
                    &f_input_counts[input_start..],
                ));

                gates.push(GateM::Call(Box::new((func_name.clone(), outs, ins))));

                counter_wire += 1;
            }
        } else {
            for i in 0..iter_count {
                let outs = ranges_for_iteration(i, 0, output_counts, f_output_counts);

                let mut ins = vec![];
                for &(_, wc) in &input_counts[..num_env as usize] {
                    ins.push((curr_input_wire, curr_input_wire + wc - 1));
                    curr_input_wire += wc;
                }
                ins.append(&mut ranges_for_iteration(
                    i,
                    curr_input_wire,
                    &input_counts[num_env as usize..],
                    &f_input_counts[input_start..],
                ));

                gates.push(GateM::Call(Box::new((func_name.clone(), outs, ins))));
            }
        }

        Ok(GatesBody::new(gates))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_iter_map() {}

    #[test]
    fn test_iter_map_enumerated() {}
}
