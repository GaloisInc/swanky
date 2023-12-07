use mac_n_cheese_sieve_parser::PluginTypeArg;

use crate::circuit_ir::{FunStore, TypeId, TypeStore, WireCount};

use super::{Plugin, PluginExecution};

/// Supported RAM operations.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RamOp {
    /// Initialize a RAM with the given number of cells.
    Init(usize),

    /// Read a value from the RAM.
    Read,

    /// Write a value to the RAM.
    Write,
}

/// Description of a field-generic RAM operation execution.
#[derive(Clone, Copy, Debug)]
struct RamV1 {
    /// The address/value field.
    pub(crate) field_id: TypeId,

    /// The number of address wires.
    pub(crate) addr_count: usize,

    /// The number of value wires.
    pub(crate) value_count: usize,

    /// The RAM operation to execute.
    pub(crate) op: RamOp,
}

/// Description of a RAM operation execution, for arithmetic fields.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RamArithV1(RamV1);

impl RamArithV1 {
    /// Create a new [`RamArithV1`] execution of `op` for a RAM over
    /// `field_id` addresses/values.
    pub fn new(field_id: TypeId, op: RamOp) -> Self {
        Self(RamV1 {
            field_id,
            addr_count: 1,
            value_count: 1,
            op,
        })
    }
}

/// Description of a RAM operation execution, for F2.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RamBoolV1(RamV1);

impl RamBoolV1 {
    /// Create a new [`RamBoolV1`] execution of `op` for a RAM over
    /// `field_id` (which **must** refer to F2) addresses/values of
    /// widths `addr_count` and `value_count`, respectively.
    pub fn new(field_id: TypeId, addr_count: usize, value_count: usize, op: RamOp) -> Self {
        Self(RamV1 {
            field_id,
            addr_count,
            value_count,
            op,
        })
    }
}

/// A SIEVE RAM Plugin execution encapsulating the Boolean and arithmetic
/// plugin variants.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RamVersion {
    /// A ram_bool_v1 execution.
    RamBool(RamBoolV1),

    /// A ram_arith_v1 execution.
    RamArith(RamArithV1),
}

impl RamVersion {
    /// Return the [`TypeId`] of the address/value field.
    pub fn type_id(&self) -> TypeId {
        match self {
            Self::RamBool(RamBoolV1(RamV1 { field_id, .. }))
            | Self::RamArith(RamArithV1(RamV1 { field_id, .. })) => *field_id,
        }
    }
}

impl Plugin for RamBoolV1 {
    const NAME: &'static str = "ram_bool_v1";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> eyre::Result<PluginExecution> {
        todo!("Implement Boolean RAM instantiation")
    }
}

impl Plugin for RamArithV1 {
    const NAME: &'static str = "ram_arith_v1";

    fn instantiate(
        operation: &str,
        params: &[PluginTypeArg],
        output_counts: &[(TypeId, WireCount)],
        input_counts: &[(TypeId, WireCount)],
        type_store: &TypeStore,
        _fun_store: &FunStore,
    ) -> eyre::Result<PluginExecution> {
        todo!("Implement arithmetic RAM instantiation")
    }
}
