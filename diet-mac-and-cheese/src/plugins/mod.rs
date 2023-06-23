use crate::circuit_ir::{GatesBody, TypeId, TypeStore, WireCount};
use eyre::Result;
use mac_n_cheese_sieve_parser::PluginTypeArg;

#[derive(Clone, Debug)]
pub struct PluginType {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    operation: String,
    #[allow(dead_code)]
    params: Vec<PluginTypeArg>,
}

impl PluginType {
    pub(crate) fn new(name: String, operation: String, params: Vec<String>) -> Self {
        let params = params
            .into_iter()
            .map(|s| PluginTypeArg::String(s))
            .collect();
        Self {
            name,
            operation,
            params,
        }
    }
}

impl From<mac_n_cheese_sieve_parser::PluginType> for PluginType {
    fn from(ty: mac_n_cheese_sieve_parser::PluginType) -> Self {
        Self {
            name: ty.name,
            operation: ty.operation,
            params: ty.args,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PluginBody {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    operation: String,
}

impl PluginBody {
    pub(crate) fn new(name: String, operation: String) -> Self {
        Self { name, operation }
    }
}

/// This trait defines a Circuit IR plugin.
pub(crate) trait Plugin {
    /// The name of the plugin.
    const NAME: &'static str;

    /// Return the [`GatesBody`] associated with this plugin.
    ///
    /// Arguments:
    /// - `operation`: The name of the operation
    /// - `params`: Any additional parameters to the operation
    /// - `count`: The count of input and output wires in the operation
    ///   signature
    /// - `output_counts`: A slice containing the outputs given as a tuple of
    ///   [`TypeId`] and [`WireCount`].
    /// - `input_counts`: A slice containing the inputs given as a tuple of
    ///   [`TypeId`] and [`WireCount`].
    /// - `type_store`: The [`TypeStore`] for this circuit.
    fn gates_body(
        operation: &str,
        params: &[String],
        count: u64,
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
    ) -> Result<GatesBody>;
}

//
// The supported plugins.
//

mod mux_v0;
pub(crate) use mux_v0::MuxV0;
mod permutation_check_v1;
pub(crate) use permutation_check_v1::PermutationCheckV1;
mod vectors_v1;
pub(crate) use vectors_v1::VectorsV1;
