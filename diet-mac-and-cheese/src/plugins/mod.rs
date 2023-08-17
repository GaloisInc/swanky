use crate::circuit_ir::{FunStore, GatesBody, TypeId, TypeIdMapping, TypeStore, WireCount};
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
    pub(crate) fn new(name: String, operation: String, params: Vec<PluginTypeArg>) -> Self {
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

/// The various execution contexts for a plugin.
#[derive(Clone, Debug)]
pub(crate) enum PluginExecution {
    /// The plugin is implemented as a sequence of gates.
    Gates(GatesBody),
    /// The plugin implements a permutation check.
    PermutationCheck(PermutationCheckV1),
    /// The plugin implements a disjunction
    Disjunction(DisjunctionBody),
    /// The plugin implements a mux.
    Mux(MuxVersion),
}

impl PluginExecution {
    /// Return the [`GatesBody`] associated with the plugin, if there is any.
    pub(crate) fn gates(&self) -> Option<&GatesBody> {
        match &self {
            PluginExecution::Gates(gates) => Some(gates),
            PluginExecution::PermutationCheck(_)
            | PluginExecution::Disjunction(_)
            | PluginExecution::Mux(_) => None,
        }
    }

    /// Return the maximum [`WireCount`] for the plugin, if there is any.
    pub(crate) fn output_wire_max(&self) -> Option<WireCount> {
        self.gates().and_then(|body| body.output_wire_max())
    }

    /// Return the [`TypeIdMapping`] associated with the plugin.
    pub(crate) fn type_id_mapping(&self) -> TypeIdMapping {
        match &self {
            PluginExecution::Gates(gates) => gates.into(),
            PluginExecution::PermutationCheck(plugin) => {
                let mut mapping = TypeIdMapping::default();
                mapping.set(plugin.type_id());
                mapping
            }
            PluginExecution::Disjunction(body) => body.type_id_mapping(),
            PluginExecution::Mux(plugin) => {
                let mut mapping = TypeIdMapping::default();
                mapping.set(plugin.type_id());
                mapping
            }
        }
    }
}

impl From<GatesBody> for PluginExecution {
    fn from(body: GatesBody) -> Self {
        Self::Gates(body)
    }
}

#[derive(Clone, Debug)]
pub struct PluginBody {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    operation: String,
    execution: PluginExecution,
}

impl PluginBody {
    pub(crate) fn new(name: String, operation: String, execution: PluginExecution) -> Self {
        Self {
            name,
            operation,
            execution,
        }
    }

    pub(crate) fn execution(&self) -> &PluginExecution {
        &self.execution
    }
}

/// This trait defines a Circuit IR plugin.
pub(crate) trait Plugin {
    /// The name of the plugin.
    const NAME: &'static str;

    /// Return the [`PluginExecution`] associated with this plugin.
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
    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
        fun_store: &FunStore,
    ) -> Result<PluginExecution>;
}

//
// The supported plugins.
//

mod dora;
pub(crate) use dora::DisjunctionV0;
mod mux_v0;
pub(crate) use mux_v0::{MuxV0, MuxV1, MuxVersion};
mod permutation_check_v1;
pub(crate) use permutation_check_v1::PermutationCheckV1;
mod galois_poly_v0;
pub(crate) use galois_poly_v0::GaloisPolyV0;
mod iter_v0;
pub(crate) use iter_v0::IterV0;
mod vectors_v1;
pub(crate) use vectors_v1::VectorsV1;

pub use self::dora::DisjunctionBody;
