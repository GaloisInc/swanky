use eyre::Context;
use mac_n_cheese_sieve_parser::PluginTypeArg;

use crate::circuit_ir::{FunStore, FuncDecl, GatesBody, TypeId, TypeStore, WireCount};

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
        let f_input_count = f_input_counts.len() - if enumerated { 1 } else { 0 };
        eyre::ensure!(
            input_counts.len() == f_input_count,
            "{}: {operation} expected {f_input_count} inputs, but got {}.",
            Self::NAME,
            input_counts.len(),
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

        for (i, ((t, wc), (t_f, wc_f))) in output_counts.iter().zip(f_output_counts).enumerate() {
            eyre::ensure!(
                t == t_f,
                "{}: The output at position {i} has type {t}, but {func_name} expects {t_f}.",
                Self::NAME,
            );

            eyre::ensure!(
                *wc == wc_f * iter_count,
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

        for (i, ((t, wc), (t_f, wc_f))) in input_counts[num_env as usize..]
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
                *wc == wc_f * iter_count,
                "{}: The input at position {i} should be {iter_count} times as large as the corresponding input of {func_name}: {wc} != {wc_f} * {iter_count}.",
                Self::NAME,
            );
        }

        let mut gates = Vec::with_capacity(iter_count as usize);
        Ok(GatesBody::new(gates))
    }
}
