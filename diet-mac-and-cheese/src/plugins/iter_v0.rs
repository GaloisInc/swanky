use mac_n_cheese_sieve_parser::PluginTypeArg;

use crate::circuit_ir::{FunStore, GatesBody, TypeId, TypeStore, WireCount};

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
        eyre::ensure!(
            params.len() == 3,
            "{}: {operation} expects 3 parametesr, but {} were given.",
            Self::NAME,
            params.len(),
        );

        let PluginTypeArg::String(ref func_name) = params[0] else {
            eyre::bail!("{}: The function name parameter must be a string.", Self::NAME);
        };

        let PluginTypeArg::Number(num_env) = params[1] else {
            eyre::bail!("{}: The #env parameter must be numeric.", Self::NAME);
        };
        // TODO: Should we assume this param fits in a u64?
        let num_env = num_env.as_words()[0] as usize;

        let PluginTypeArg::Number(iter_count) = params[2] else {
            eyre::bail!("{}: The iteration count parameter must be numeric.", Self::NAME);
        };
        // TODO: Should we assume this param fits in a u64?
        let iter_count = iter_count.as_words()[0] as usize;

        eyre::ensure!(
            input_counts.len() >= num_env,
            "{}: {operation} expects at least {num_env} inputs for the environment, but a total of {} were specified.",
            Self::NAME,
            input_counts.len(),
        );

        let mut gates = Vec::with_capacity(iter_count);
        Ok(GatesBody::new(gates))
    }
}
