use mac_n_cheese_sieve_parser::PluginTypeArg;

use crate::circuit_ir::{GatesBody, TypeId, TypeStore, WireCount};

use super::Plugin;

pub(crate) struct IterV0;

impl Plugin for IterV0 {
    const NAME: &'static str = "iter_v0";

    fn gates_body(
        _operation: &str,
        _params: &[PluginTypeArg],
        _output_counts: &[(TypeId, WireCount)],
        _input_counts: &[(TypeId, WireCount)],
        _type_store: &TypeStore,
    ) -> eyre::Result<GatesBody> {
        todo!()
    }
}
