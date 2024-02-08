use eyre::{bail, ensure, Result};
use mac_n_cheese_sieve_parser::PluginTypeArg;
use swanky_field_binary::F2;

use crate::circuit_ir::{FunStore, TypeId, TypeSpecification, TypeStore, WireCount};

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
pub(crate) struct RamV1 {
    /// The RAM type.
    pub(crate) ram_type_id: TypeId,

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
pub(crate) struct RamArithV1(pub RamV1);

impl RamArithV1 {
    /// Create a new [`RamArithV1`] execution of `op` for a RAM over
    /// `field_id` addresses/values.
    pub fn new(ram_type_id: TypeId, field_id: TypeId, op: RamOp) -> Self {
        Self(RamV1 {
            ram_type_id,
            field_id,
            addr_count: 1,
            value_count: 1,
            op,
        })
    }
}

/// Description of a RAM operation execution, for F2.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RamBoolV1(pub RamV1);

impl RamBoolV1 {
    /// Create a new [`RamBoolV1`] execution of `op` for a RAM over
    /// `field_id` (which **must** refer to F2) addresses/values of
    /// widths `addr_count` and `value_count`, respectively.
    pub fn new(
        ram_type_id: TypeId,
        field_id: TypeId,
        addr_count: usize,
        value_count: usize,
        op: RamOp,
    ) -> Self {
        Self(RamV1 {
            ram_type_id,
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
    ) -> Result<PluginExecution> {
        match operation {
            "init" => {
                ensure!(
                    params.len() == 1,
                    "{}: {operation} expects 1 parameter, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                let PluginTypeArg::Number(size) = params[0] else {
                    bail!(
                        "{}: The parameter to {operation} must be numeric.",
                        Self::NAME
                    );
                };
                // NOTE: Assuming the given RAM size fits in a u64!
                let size = size.as_words()[0];

                let op = RamOp::Init(size as usize);

                ensure!(
                    input_counts.len() == 1,
                    "{}: {operation} takes 1 wire range as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                let initial_value_type_id = input_counts[0].0;
                let &TypeSpecification::Field(initial_value_rust_type_id) =
                    type_store.get(&initial_value_type_id)?
                else {
                    bail!("{}: No type with index {initial_value_type_id}, or that index refers to a plugin-defined type.", Self::NAME)
                };

                ensure!(
                    initial_value_rust_type_id == std::any::TypeId::of::<F2>(),
                    "{}: This plugin only supports Boolean fields.",
                    Self::NAME,
                );

                ensure!(
                    output_counts.len() == 1,
                    "{}: {operation} outputs 1 wire range, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts.len(),
                );

                ensure!(
                    output_counts[0].1 == 1,
                    "{}: {operation} outputs exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts[0].1,
                );

                let ram_output_type_id = output_counts[0].0;
                let TypeSpecification::Plugin(ram_output_type) =
                    type_store.get(&ram_output_type_id)?
                else {
                    bail!("{}: {operation} must output a plugin-defined type, but the type with index {ram_output_type_id} refers to a field (or is undefined).", Self::NAME);
                };

                ensure!(
                    ram_output_type.name.as_str() == Self::NAME,
                    "{}: Expected this plugin, but got {}.",
                    Self::NAME,
                    ram_output_type.name,
                );

                ensure!(
                    ram_output_type.operation.as_str() == "ram",
                    "{}: Expected type 'ram', but got '{}'.",
                    Self::NAME,
                    ram_output_type.operation,
                );

                ensure!(
                    ram_output_type.params.len() == 3,
                    "{}: The ram type expects 3 parameters, but {} were given.",
                    Self::NAME,
                    ram_output_type.params.len(),
                );

                let PluginTypeArg::Number(field_id) = ram_output_type.params[0] else {
                    bail!(
                        "{}: The first ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // The `field_id` _must_ fit in a u8 by the SIEVE IR spec.
                let field_id = u8::try_from(field_id.as_words()[0])?;
                ensure!(
                    field_id == initial_value_type_id,
                    "{}: The type of the input to {operation} must match the output RAM's address/value type.",
                    Self::NAME,
                );

                let PluginTypeArg::Number(addr_count) = ram_output_type.params[1] else {
                    bail!(
                        "{}: The second ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // Any count on the number of wires _must_ fit in a u64 by the SIEVE IR spec.
                let addr_count = addr_count.as_words()[0];

                let PluginTypeArg::Number(value_count) = ram_output_type.params[2] else {
                    bail!(
                        "{}: The third ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // Ditto
                let value_count = value_count.as_words()[0];

                ensure!(
                    value_count == input_counts[0].1,
                    "{}: The number of wires in the input to {operation} must match the output RAM's value size.",
                    Self::NAME,
                );

                Ok(PluginExecution::Ram(RamVersion::RamBool(RamBoolV1::new(
                    ram_output_type_id,
                    field_id,
                    addr_count as usize,
                    value_count as usize,
                    op,
                ))))
            }
            "read" => {
                let op = RamOp::Read;

                ensure!(
                    params.is_empty(),
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                ensure!(
                    input_counts.len() == 2,
                    "{}: {operation} takes 2 wire ranges as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                ensure!(
                    input_counts[0].1 == 1,
                    "{}: The first input to {operation} must be exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[0].1,
                );

                let ram_input_type_id = input_counts[0].0;
                let TypeSpecification::Plugin(ram_input_type) =
                    type_store.get(&ram_input_type_id)?
                else {
                    bail!(
                        "{}: {operation} takes a plugin-defined type as its first input.",
                        Self::NAME
                    );
                };

                ensure!(
                    ram_input_type.name.as_str() == Self::NAME,
                    "{}: Expected this plugin, but got {}.",
                    Self::NAME,
                    ram_input_type.name,
                );

                ensure!(
                    ram_input_type.operation.as_str() == "ram",
                    "{}: Expected type 'ram', but got '{}'.",
                    Self::NAME,
                    ram_input_type.operation,
                );

                ensure!(
                    ram_input_type.params.len() == 3,
                    "{}: The ram type expects 3 parameters, but {} were given.",
                    Self::NAME,
                    ram_input_type.params.len(),
                );

                let PluginTypeArg::Number(field_id) = ram_input_type.params[0] else {
                    bail!(
                        "{}: The first ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // The `field_id` _must_ fit in a u8 by the SIEVE IR spec.
                let field_id = u8::try_from(field_id.as_words()[0])?;

                let &TypeSpecification::Field(field_rust_id) = type_store.get(&field_id)? else {
                    bail!("{}: No type with index {field_id}, or that index refers to a plugin-defined type.", Self::NAME);
                };

                ensure!(
                    field_rust_id == std::any::TypeId::of::<F2>(),
                    "{}: This plugin only supports Boolean fields.",
                    Self::NAME,
                );

                let PluginTypeArg::Number(addr_count) = ram_input_type.params[1] else {
                    bail!(
                        "{}: The second ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // Any count on the number of wires _must_ fit in a u64 by the SIEVE IR spec.
                let addr_count = addr_count.as_words()[0];

                let PluginTypeArg::Number(value_count) = ram_input_type.params[2] else {
                    bail!(
                        "{}: The third ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // Ditto
                let value_count = value_count.as_words()[0];

                ensure!(
                    input_counts[1].0 == field_id,
                    "{}: The type of the second input to {operation} must match the input RAM's address/value type.",
                    Self::NAME,
                );

                ensure!(
                    input_counts[1].1 == addr_count,
                    "{}: The second input to {operation} must have exactly {addr_count} wires, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[1].1,
                );

                ensure!(
                    output_counts.len() == 1,
                    "{}: {operation} outputs 1 wire range, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts.len(),
                );

                ensure!(
                    output_counts[0].0 == field_id,
                    "{}: The type of the output of {operation} must match the input RAM's address/value type.",
                    Self::NAME,
                );

                ensure!(
                    output_counts[0].1 == value_count,
                    "{}: {operation} outputs exactly {value_count} wires, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts[0].1,
                );

                Ok(PluginExecution::Ram(RamVersion::RamBool(RamBoolV1::new(
                    ram_input_type_id,
                    field_id,
                    addr_count as usize,
                    value_count as usize,
                    op,
                ))))
            }
            "write" => {
                let op = RamOp::Write;

                ensure!(
                    params.is_empty(),
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                ensure!(
                    input_counts.len() == 3,
                    "{}: {operation} takes 3 wire ranges as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                ensure!(
                    input_counts[0].1 == 1,
                    "{}: The first input to {operation} must be exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[0].1,
                );

                let ram_input_type_id = input_counts[0].0;
                let TypeSpecification::Plugin(ram_input_type) =
                    type_store.get(&ram_input_type_id)?
                else {
                    bail!(
                        "{}: {operation} takes a plugin-defined type as its first input.",
                        Self::NAME
                    );
                };

                ensure!(
                    ram_input_type.name.as_str() == Self::NAME,
                    "{}: Expected this plugin, but got {}.",
                    Self::NAME,
                    ram_input_type.name,
                );

                ensure!(
                    ram_input_type.operation.as_str() == "ram",
                    "{}: Expected type 'ram', but got '{}'.",
                    Self::NAME,
                    ram_input_type.operation,
                );

                ensure!(
                    ram_input_type.params.len() == 3,
                    "{}: The ram type expects 3 parameters, but {} were given.",
                    Self::NAME,
                    ram_input_type.params.len(),
                );

                let PluginTypeArg::Number(field_id) = ram_input_type.params[0] else {
                    bail!(
                        "{}: The first ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // The `field_id` _must_ fit in a u8 by the SIEVE IR spec.
                let field_id = u8::try_from(field_id.as_words()[0])?;

                let &TypeSpecification::Field(field_rust_id) = type_store.get(&field_id)? else {
                    bail!("{}: No type with index {field_id}, or that index refers to a plugin-defined type.", Self::NAME);
                };

                ensure!(
                    field_rust_id == std::any::TypeId::of::<F2>(),
                    "{}: This plugin only supports Boolean fields.",
                    Self::NAME,
                );

                let PluginTypeArg::Number(addr_count) = ram_input_type.params[1] else {
                    bail!(
                        "{}: The second ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // Any count on the number of wires _must_ fit in a u64 by the SIEVE IR spec.
                let addr_count = addr_count.as_words()[0];

                let PluginTypeArg::Number(value_count) = ram_input_type.params[2] else {
                    bail!(
                        "{}: The third ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // Ditto
                let value_count = value_count.as_words()[0];

                ensure!(
                    input_counts[1].0 == field_id,
                    "{}: The type of the second input to {operation} must match the input RAM's address/value type.",
                    Self::NAME,
                );

                ensure!(
                    input_counts[1].1 == addr_count,
                    "{}: The second input to {operation} must have exactly {addr_count} wires, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[1].1,
                );

                ensure!(
                    input_counts[2].0 == field_id,
                    "{}: The type of the third input to {operation} must match the input RAM's address/value type.",
                    Self::NAME,
                );

                ensure!(
                    input_counts[2].1 == value_count,
                    "{}: The third input to {operation} must have exactly {value_count} wires, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[2].1,
                );

                ensure!(
                    output_counts.is_empty(),
                    "{}: {operation} outputs 0 wire ranges, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts.len(),
                );

                Ok(PluginExecution::Ram(RamVersion::RamBool(RamBoolV1::new(
                    ram_input_type_id,
                    field_id,
                    addr_count as usize,
                    value_count as usize,
                    op,
                ))))
            }
            _ => bail!("{}: Unknown operation: {operation}", Self::NAME),
        }
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
    ) -> Result<PluginExecution> {
        match operation {
            "init" => {
                ensure!(
                    params.len() == 1,
                    "{}: {operation} expects 1 parameter, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                let PluginTypeArg::Number(size) = params[0] else {
                    bail!(
                        "{}: The parameter to {operation} must be numeric.",
                        Self::NAME
                    );
                };
                // NOTE: Assuming the given RAM size fits in a u64!
                let size = size.as_words()[0];

                let op = RamOp::Init(size as usize);

                ensure!(
                    input_counts.len() == 1,
                    "{}: {operation} takes 1 wire range as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                let initial_value_type_id = input_counts[0].0;
                let &TypeSpecification::Field(_) = type_store.get(&initial_value_type_id)? else {
                    bail!("{}: No type with index {initial_value_type_id}, or that index refers to a plugin-defined type.", Self::NAME)
                };

                ensure!(
                    input_counts[0].1 == 1,
                    "{}: {operation} takes exactly 1 wire as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[0].1,
                );

                ensure!(
                    output_counts.len() == 1,
                    "{}: {operation} outputs 1 wire range, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts.len(),
                );

                ensure!(
                    output_counts[0].1 == 1,
                    "{}: {operation} outputs exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts[0].1,
                );

                let ram_output_type_id = output_counts[0].0;
                let TypeSpecification::Plugin(ram_output_type) =
                    type_store.get(&ram_output_type_id)?
                else {
                    bail!("{}: {operation} must output a plugin-defined type, but the type with index {ram_output_type_id} refers to a field (or is undefined).", Self::NAME);
                };

                ensure!(
                    ram_output_type.name.as_str() == Self::NAME,
                    "{}: Expected this plugin, but got {}.",
                    Self::NAME,
                    ram_output_type.name,
                );

                ensure!(
                    ram_output_type.operation.as_str() == "ram",
                    "{}: Expected type 'ram', but got '{}'.",
                    Self::NAME,
                    ram_output_type.operation,
                );

                ensure!(
                    ram_output_type.params.len() == 1,
                    "{}: The ram type expects 1 parameters, but {} were given.",
                    Self::NAME,
                    ram_output_type.params.len(),
                );

                let PluginTypeArg::Number(field_id) = ram_output_type.params[0] else {
                    bail!(
                        "{}: The first ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // The `field_id` _must_ fit in a u8 by the SIEVE IR spec.
                let field_id = u8::try_from(field_id.as_words()[0])?;
                ensure!(
                    field_id == initial_value_type_id,
                    "{}: The type of the input to {operation} must match the output RAM's address/value type.",
                    Self::NAME,
                );

                Ok(PluginExecution::Ram(RamVersion::RamArith(RamArithV1::new(
                    ram_output_type_id,
                    field_id,
                    op,
                ))))
            }
            "read" => {
                let op = RamOp::Read;

                ensure!(
                    params.is_empty(),
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                ensure!(
                    input_counts.len() == 2,
                    "{}: {operation} takes 2 wire ranges as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                ensure!(
                    input_counts[0].1 == 1,
                    "{}: The first input to {operation} must be exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[0].1,
                );

                let ram_input_type_id = input_counts[0].0;
                let TypeSpecification::Plugin(ram_input_type) =
                    type_store.get(&ram_input_type_id)?
                else {
                    bail!(
                        "{}: {operation} takes a plugin-defined type as its first input.",
                        Self::NAME
                    );
                };

                ensure!(
                    ram_input_type.name.as_str() == Self::NAME,
                    "{}: Expected this plugin, but got {}.",
                    Self::NAME,
                    ram_input_type.name,
                );

                ensure!(
                    ram_input_type.operation.as_str() == "ram",
                    "{}: Expected type 'ram', but got '{}'.",
                    Self::NAME,
                    ram_input_type.operation,
                );

                ensure!(
                    ram_input_type.params.len() == 1,
                    "{}: The ram type expects 1 parameter, but {} were given.",
                    Self::NAME,
                    ram_input_type.params.len(),
                );

                let PluginTypeArg::Number(field_id) = ram_input_type.params[0] else {
                    bail!(
                        "{}: The first ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // The `field_id` _must_ fit in a u8 by the SIEVE IR spec.
                let field_id = u8::try_from(field_id.as_words()[0])?;

                let &TypeSpecification::Field(_) = type_store.get(&field_id)? else {
                    bail!("{}: No type with index {field_id}, or that index refers to a plugin-defined type.", Self::NAME);
                };

                ensure!(
                    input_counts[1].0 == field_id,
                    "{}: The type of the second input to {operation} must match the input RAM's address/value type.",
                    Self::NAME,
                );

                ensure!(
                    input_counts[1].1 == 1,
                    "{}: The second input to {operation} must have exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[1].1,
                );

                ensure!(
                    output_counts.len() == 1,
                    "{}: {operation} outputs 1 wire range, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts.len(),
                );

                ensure!(
                    output_counts[0].0 == field_id,
                    "{}: The type of the output of {operation} must match the input RAM's address/value type.",
                    Self::NAME,
                );

                ensure!(
                    output_counts[0].1 == 1,
                    "{}: {operation} outputs exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts[0].1,
                );

                Ok(PluginExecution::Ram(RamVersion::RamArith(RamArithV1::new(
                    ram_input_type_id,
                    field_id,
                    op,
                ))))
            }
            "write" => {
                let op = RamOp::Write;

                ensure!(
                    params.is_empty(),
                    "{}: {operation} expects 0 parameters, but {} were given.",
                    Self::NAME,
                    params.len(),
                );

                ensure!(
                    input_counts.len() == 3,
                    "{}: {operation} takes 3 wire ranges as input, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts.len(),
                );

                ensure!(
                    input_counts[0].1 == 1,
                    "{}: The first input to {operation} must be exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[0].1,
                );

                let ram_input_type_id = input_counts[0].0;
                let TypeSpecification::Plugin(ram_input_type) =
                    type_store.get(&ram_input_type_id)?
                else {
                    bail!(
                        "{}: {operation} takes a plugin-defined type as its first input.",
                        Self::NAME
                    );
                };

                ensure!(
                    ram_input_type.name.as_str() == Self::NAME,
                    "{}: Expected this plugin, but got {}.",
                    Self::NAME,
                    ram_input_type.name,
                );

                ensure!(
                    ram_input_type.operation.as_str() == "ram",
                    "{}: Expected type 'ram', but got '{}'.",
                    Self::NAME,
                    ram_input_type.operation,
                );

                ensure!(
                    ram_input_type.params.len() == 1,
                    "{}: The ram type expects 1 parameter, but {} were given.",
                    Self::NAME,
                    ram_input_type.params.len(),
                );

                let PluginTypeArg::Number(field_id) = ram_input_type.params[0] else {
                    bail!(
                        "{}: The first ram type argument must be numeric.",
                        Self::NAME
                    );
                };

                // The `field_id` _must_ fit in a u8 by the SIEVE IR spec.
                let field_id = u8::try_from(field_id.as_words()[0])?;

                let &TypeSpecification::Field(_) = type_store.get(&field_id)? else {
                    bail!("{}: No type with index {field_id}, or that index refers to a plugin-defined type.", Self::NAME);
                };

                ensure!(
                    input_counts[1].0 == field_id,
                    "{}: The type of the second input to {operation} must match the input RAM's address/value type.",
                    Self::NAME,
                );

                ensure!(
                    input_counts[1].1 == 1,
                    "{}: The second input to {operation} must have exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[1].1,
                );

                ensure!(
                    input_counts[2].0 == field_id,
                    "{}: The type of the third input to {operation} must match the input RAM's address/value type.",
                    Self::NAME,
                );

                ensure!(
                    input_counts[2].1 == 1,
                    "{}: The third input to {operation} must have exactly 1 wire, but this declaration specifies {}.",
                    Self::NAME,
                    input_counts[2].1,
                );

                ensure!(
                    output_counts.is_empty(),
                    "{}: {operation} outputs 0 wire ranges, but this declaration specifies {}.",
                    Self::NAME,
                    output_counts.len(),
                );

                Ok(PluginExecution::Ram(RamVersion::RamArith(RamArithV1::new(
                    ram_input_type_id,
                    field_id,
                    op,
                ))))
            }
            _ => bail!("{}: Unknown operation: {operation}", Self::NAME),
        }
    }
}
