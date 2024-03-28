/*!
In-memory representations of SIEVE IR resources.

This module provides types for the expression of circuits in the SIEVE IR
format. Typically, values of these types will be returned by one of the parsers
in [`crate::sieveir_reader_fbs`] or [`crate::sieveir_reader_text`] - but they
may be manually constructed when using DMC as a library / circuits are generated
by other means.

 **NOTE:** If you manually construct values, you're responsible for checking for
validity (e.g. wires are SSA) as defined by the SIEVE IR specification!
*/
use crate::{
    fields::{extension_field_to_type_id, modulus_to_type_id, SieveIrDeserialize},
    plugins::{Plugin, PluginExecution, PluginType, RamArithV0, RamArithV1, RamBoolV0, RamBoolV1},
};
use eyre::{bail, ensure, eyre, Result};
use log::debug;
use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};
use std::{
    cmp::max,
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
};
use swanky_field::FiniteField;

/// A SIEVE IR wire identifier.
///
/// In a circuit, `WireId`s are scoped to a type. That is, for each [`TypeId`]
/// defined in a circuit relation, the full range `0` to `u64::MAX` is available
/// for `WireId` values.
pub type WireId = u64;

/// A count of the number of wires in a range.
///
/// **CAUTION!** Technically, it is possible in SIEVE IR to express circuits
/// using the full range of wires in a single range. This means that this type
/// is insufficient at the upper bound, since a range containing wires numbered
/// `0` to `u64::MAX` contains `u64::MAX + 1` total wires. Since this is an
/// unlikely edge case, we don't bother worrying about it for any real circuits.
pub type WireCount = u64;

/// A SIEVE IR type identifier.
///
/// SIEVE IR supports up to 256 type declarations in a single circuit.
pub type TypeId = u8;

/// An _inclusive_ range of [`WireId`]s.
pub type WireRange = (WireId, WireId);

/// A SIEVE IR conversion gate.
///
/// The first [`TypeId`]-[`WireRange`] pairing denotes the _output_ of the
/// conversion, and the second pairing denotes the _input_ to the conversion.
pub type ConvGate = (TypeId, WireRange, TypeId, WireRange);

/// A SIEVE IR call gate.
///
/// The [`FunId`] denotes a unique ID associated with a function name by a
/// [`FunStore`] - use [`FunStore::name_to_fun_id`] to get the ID associated
/// with a particular function name.
///
/// The first [`Vec`] denotes the _output_ wires, and the second [`Vec`] denotes the
/// _input_ wires.
pub type CallGate = (FunId, Vec<WireRange>, Vec<WireRange>);

/// A 'core' SIEVE IR gate.
///
/// Most gates take a [`TypeId`] as their first argument, which denotes the
/// evaluation context for the gate. In addition, the [`WireId`] ordering for
/// gates is generally: `<out> <in> ...`; that is, the first [`WireId`] denotes
/// denotes the _output_ of the gate.
///
/// When constructing sequences of `GateM` for evaluation, take care to follow
/// the validity requirements as defined by SIEVE IR. Most importantly:
///
/// - Circuits are topologically ordered; wires must be defined before use in
///   a given scope
/// - Wires may only be assigned exactly once (SSA)
/// - Ranges of wires must be part of the same allocation for use as inputs and
///   outputs (and naturally, ranges must be of the right/expected size)
/// - Delete gates may not 'split' an allocation into smaller pieces
///
/// **NOTE:** To optimize cache performance, we require that `GateM` values fit
/// in 32 bytes or fewer; we use [`Box`] strategically to achieve this storage
/// property.
#[derive(Clone, Debug)]
pub enum GateM {
    /// Write the value to the given `WireId`.
    Constant(TypeId, WireId, Box<Number>),

    /// Assert that the element on [`WireId`] is zero.
    AssertZero(TypeId, WireId),

    /// Copy ranges of wires.
    Copy(TypeId, WireRange, Box<Vec<WireRange>>),

    /// Add the values on two `WireId`, storing the result.
    Add(TypeId, WireId, WireId, WireId),

    /// Subtract the values on two `WireId`, storing the result.
    Sub(TypeId, WireId, WireId, WireId),

    /// Multiply the values on two `WireId`, storing the result.
    Mul(TypeId, WireId, WireId, WireId),

    /// Add a constant to the value on a `WireId`, storing the result.
    AddConstant(TypeId, WireId, WireId, Box<Number>),

    /// Multiply the value on a `WireId` by a constant, storing the result.
    MulConstant(TypeId, WireId, WireId, Box<Number>),

    /// Get public instances from the scope's queue, storing to the `WireRange`.
    Instance(TypeId, WireRange),

    /// Get private witnesses from the scope's queue, storing to the
    /// `WireRange`.
    Witness(TypeId, WireRange),

    /// Convert values in one field to values in another.
    Conv(Box<ConvGate>),

    /// Allocate a new, uninitialized range of wires.
    New(TypeId, WireId, WireId),

    /// Delete/free a range of wires.
    Delete(TypeId, WireId, WireId),

    /// Call a function.
    Call(Box<CallGate>),

    /// Get a random challenge value, storing the result.
    Challenge(TypeId, WireId),

    /// An informational comment.
    Comment(String),
}

#[test]
fn size_of_gate_m_less_than_32_bytes() {
    // Enforce that `GateM` fits in 32 bytes.
    assert!(std::mem::size_of::<GateM>() <= 32);
}

impl GateM {
    /// Return the [`TypeId`] associated with this gate.
    pub(crate) fn type_id(&self) -> TypeId {
        use GateM::*;
        match self {
            Constant(ty, _, _)
            | AssertZero(ty, _)
            | Copy(ty, _, _)
            | Add(ty, _, _, _)
            | Sub(ty, _, _, _)
            | Mul(ty, _, _, _)
            | AddConstant(ty, _, _, _)
            | MulConstant(ty, _, _, _)
            | New(ty, _, _)
            | Delete(ty, _, _)
            | Instance(ty, _)
            | Witness(ty, _)
            | Challenge(ty, _) => *ty,
            Conv(_) | Call(_) => unreachable!("Should not ask the type_id for conv/call gates"),
            Comment(_) => panic!("There's no `TypeId` associated with a comment!"),
        }
    }

    /// Return the [`WireId`] associated with the output of this gate, or
    /// `None` if the gate has no output wire.
    pub(crate) fn out_wire(&self) -> Option<WireId> {
        use GateM::*;
        match self {
            Constant(_, out, _)
            | Copy(_, (_, out), _)
            | Add(_, out, _, _)
            | Sub(_, out, _, _)
            | Mul(_, out, _, _)
            | AddConstant(_, out, _, _)
            | MulConstant(_, out, _, _)
            | Instance(_, (_, out))
            | Witness(_, (_, out))
            | New(_, _, out)
            | Challenge(_, out) => Some(*out),
            AssertZero(_, _) | Delete(_, _, _) | Comment(_) => None,
            Conv(c) => {
                let (_, (_, out), _, _) = c.as_ref();
                Some(*out)
            }
            Call(arg) => {
                let (_, v, _) = arg.as_ref();
                v.iter().fold(None, |acc, (_, last)| max(acc, Some(*last)))
            }
        }
    }
}

/// A SIEVE IR type specification.
///
/// This corresponds to the `@type` specifier in concrete SIEVE IR syntax.
/// DMC currently supports field types and a limited set of types defined by
/// plugins.
#[derive(Clone, Debug)]
pub enum TypeSpecification {
    /// A field, given as a [`TypeId`](std::any::TypeId).
    ///
    /// Consider using [`crate::modulus_to_type_id`] to construct these values.
    Field(std::any::TypeId),

    /// A plugin-defined type.
    ///
    /// DMC currently only supports RAM types as defined in the RAM plugin
    /// specification for `TypeSpecification::Plugin`.
    Plugin(PluginType),
}

/// A SIEVE IR type environment.
///
/// This contains all the types used in the circuit, accessible by their
/// SIEVE IR [`TypeId`].
#[derive(Clone, Default)]
pub struct TypeStore(BTreeMap<TypeId, TypeSpecification>);

impl TypeStore {
    /// Insert a [`TypeId`]-[`TypeSpecification`] pair into the [`TypeStore`].
    pub fn insert(&mut self, key: TypeId, value: TypeSpecification) {
        self.0.insert(key, value);
    }

    /// Get the [`TypeSpecification`] associated with a [`TypeId`].
    pub fn get(&self, key: &TypeId) -> Result<&TypeSpecification> {
        self.0
            .get(key)
            .ok_or_else(|| eyre!("Type ID {key} not found in `TypeStore`"))
    }

    /// Return an [`Iterator`] over the [`TypeId`]-[`TypeSpecification`] pairs
    /// in the [`TypeStore`].
    pub fn iter(&self) -> std::collections::btree_map::Iter<TypeId, TypeSpecification> {
        self.0.iter()
    }
}

impl TryFrom<Vec<mac_n_cheese_sieve_parser::Type>> for TypeStore {
    type Error = eyre::Error;

    fn try_from(
        types: Vec<mac_n_cheese_sieve_parser::Type>,
    ) -> std::result::Result<Self, Self::Error> {
        debug!("Converting Circuit IR types to `TypeStore`");
        if types.len() > 256 {
            return Err(eyre!("Too many types specified: {} > 256", types.len()));
        }
        let mut store = TypeStore::default();
        for (i, ty) in types.into_iter().enumerate() {
            let spec = match ty {
                mac_n_cheese_sieve_parser::Type::Field { modulus } => {
                    TypeSpecification::Field(modulus_to_type_id(modulus)?)
                }
                mac_n_cheese_sieve_parser::Type::ExtField {
                    index,
                    degree,
                    modulus,
                } => {
                    if index >= i as TypeId {
                        bail!("Type index too large.");
                    }
                    let spec = store.get(&index)?;
                    let base_type_id = match spec {
                        TypeSpecification::Field(ty) => *ty,
                        _ => bail!("Invalid type specification for base field"),
                    };
                    TypeSpecification::Field(extension_field_to_type_id(
                        base_type_id,
                        degree,
                        modulus,
                    )?)
                }
                mac_n_cheese_sieve_parser::Type::Ring { .. } => {
                    bail!("Rings not supported in Diet Mac'n'Cheese.")
                }
                mac_n_cheese_sieve_parser::Type::PluginType(ty) => {
                    TypeSpecification::Plugin(PluginType::from(ty))
                }
            };
            store.insert(i as u8, spec);
        }
        Ok(store)
    }
}

impl TryFrom<Vec<Number>> for TypeStore {
    type Error = eyre::Error;

    fn try_from(fields: Vec<Number>) -> std::result::Result<Self, Self::Error> {
        debug!("Converting vector of fields to `TypeStore`");
        if fields.len() > 256 {
            return Err(eyre!("Too many types specified: {} > 256", fields.len()));
        }
        let mut store = TypeStore::default();
        for (i, field) in fields.into_iter().enumerate() {
            let spec = TypeSpecification::Field(modulus_to_type_id(field)?);
            store.insert(i as u8, spec);
        }
        Ok(store)
    }
}

/// A bitmap of the used / set [`TypeId`]s.
///
/// A [`TypeId`] is "set" if it is used in the computation.
pub(crate) struct TypeIdMapping([bool; 256]);

impl TypeIdMapping {
    /// Set the associated [`TypeId`].
    pub(crate) fn set(&mut self, ty: TypeId) {
        self.0[ty as usize] = true;
    }

    /// Set the [`TypeId`]s associated with a given [`GateM`].
    pub(crate) fn set_from_gate(&mut self, gate: &GateM) {
        use GateM::*;
        match gate {
            Constant(ty, _, _)
            | AssertZero(ty, _)
            | Copy(ty, _, _)
            | Add(ty, _, _, _)
            | Sub(ty, _, _, _)
            | Mul(ty, _, _, _)
            | AddConstant(ty, _, _, _)
            | MulConstant(ty, _, _, _)
            | Instance(ty, _)
            | Witness(ty, _)
            | New(ty, _, _)
            | Delete(ty, _, _)
            | Challenge(ty, _) => {
                self.set(*ty);
            }
            Call(_) | Comment(_) => {}
            Conv(c) => {
                let (ty1, _, ty2, _) = c.as_ref();
                self.set(*ty1);
                self.set(*ty2);
            }
        }
    }

    /// Convert [`TypeIdMapping`] to a [`Vec`] containing the set [`TypeId`]s.
    fn to_type_ids(&self) -> Vec<TypeId> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, b)| {
                if *b {
                    Some(i.try_into().expect("Index should be less than 256"))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for TypeIdMapping {
    fn default() -> Self {
        Self([false; 256]) // There are only 256 possible `TypeId`s
    }
}

impl From<&GatesBody> for TypeIdMapping {
    fn from(gates: &GatesBody) -> Self {
        let mut mapping = TypeIdMapping::default();
        for g in gates.gates.iter() {
            mapping.set_from_gate(g);
        }
        mapping
    }
}

/// A body of computation containing a sequence of [`GateM`]s.
#[derive(Clone, Debug)]
#[repr(transparent)]
pub(crate) struct GatesBody {
    gates: Vec<GateM>,
}

impl GatesBody {
    /// Create a new [`GatesBody`].
    pub(crate) fn new(gates: Vec<GateM>) -> Self {
        Self { gates }
    }

    pub(crate) fn gates(&self) -> &[GateM] {
        &self.gates
    }

    /// Return the maximum [`WireId`] found, or `None` if no [`WireId`] was found.
    pub(crate) fn output_wire_max(&self) -> Option<WireId> {
        self.gates
            .iter()
            .fold(None, |acc, x| max(acc, x.out_wire()))
    }
}

/// The body of a Circuit IR function.
///
/// The function body can be either a sequence of gates or a plugin.
#[derive(Clone)]
pub(crate) enum FunctionBody {
    /// The function body as a sequence of gates.
    Gates(GatesBody),
    /// The function body as a plugin.
    Plugin(PluginExecution),
}

/// Collected information associated with a Circuit IR function.
#[derive(Clone)]
pub(crate) struct CompiledInfo {
    /// Count of wires for output/input arguments to the function.
    pub(crate) args_count: WireId,
    // The maximum [`WireId`] in the function body.
    pub(crate) body_max: Option<WireId>,
    /// [`TypeId`]s encountered in the function body.
    pub(crate) type_ids: Vec<TypeId>,

    pub(crate) outputs_cnt: WireId,
    pub(crate) inputs_cnt: WireId,
}

/// A Circuit IR function declaration.
#[derive(Clone)]
pub struct FuncDecl {
    /// The function body.
    body: FunctionBody,
    /// A [`Vec`] containing pairings of [`TypeId`]s and their associated output
    /// [`WireCount`].
    pub(crate) output_counts: Vec<(TypeId, WireCount)>,
    /// A [`Vec`] containing pairings of [`TypeId`]s and their associated input
    /// [`WireCount`].
    pub(crate) input_counts: Vec<(TypeId, WireCount)>,
    pub(crate) compiled_info: CompiledInfo, // pub(crate) to ease logging
}

/// Convenience function returning a pair of [`WireId`] for the next wire id following the last output,
/// and the next wire id following the last input.
///
/// Arguments:
/// - `output_counts`: A slice containing the outputs given as a tuple of
/// [`TypeId`] and [`WireCount`].
/// - `input_counts`: A slice containing the inputs given as a tuple of
/// [`TypeId`] and [`WireCount`].
pub(crate) fn output_input_counts(
    output_counts: &[(TypeId, WireCount)],
    input_counts: &[(TypeId, WireCount)],
) -> (WireId, WireId) {
    let mut first_unused_wire_outputs = 0;

    for (_, wc) in output_counts.iter() {
        first_unused_wire_outputs += wc;
    }

    let mut first_unused_wire_inputs = first_unused_wire_outputs;

    for (_, wc) in input_counts.iter() {
        first_unused_wire_inputs += wc;
    }

    (first_unused_wire_outputs, first_unused_wire_inputs)
}

/// Return the first [`WireId`] available for allocation in the `Plugin`'s
/// [`GateBody`].
///
/// Arguments:
/// - `output_counts`: A slice containing the outputs given as a tuple of
/// [`TypeId`] and [`WireCount`].
/// - `input_counts`: A slice containing the inputs given as a tuple of
/// [`TypeId`] and [`WireCount`].
pub(crate) fn first_unused_wire_id(
    output_counts: &[(TypeId, WireCount)],
    input_counts: &[(TypeId, WireCount)],
) -> WireId {
    let (_, first_unused_wire_inputs) = output_input_counts(output_counts, input_counts);
    first_unused_wire_inputs
}

impl FuncDecl {
    /// Instantiate a new function.
    ///
    /// * `gates` denotes a sequence of gates that makes up the function body.
    /// * `output_counts` denotes the wire counts for each [`TypeId`] used as an
    ///   output.
    /// * `input_counts` denotes the wire counts for each [`TypeId`] used as an
    ///   input.
    pub fn new_function(
        gates: Vec<GateM>,
        output_counts: Vec<(TypeId, WireCount)>,
        input_counts: Vec<(TypeId, WireCount)>,
    ) -> Self {
        let gates = GatesBody::new(gates);
        let mut type_presence = TypeIdMapping::from(&gates);

        for (ty, _) in output_counts.iter() {
            type_presence.set(*ty);
        }
        for (ty, _) in input_counts.iter() {
            type_presence.set(*ty);
        }

        let (first_unused_output, first_unused_input) =
            output_input_counts(&output_counts, &input_counts);

        let body_max = gates
            .output_wire_max()
            .map(|out| std::cmp::max(first_unused_input, out));

        let type_ids = type_presence.to_type_ids();
        let body = FunctionBody::Gates(gates);

        FuncDecl {
            body,
            output_counts,
            input_counts,
            compiled_info: CompiledInfo {
                args_count: first_unused_input,
                body_max,
                type_ids,
                outputs_cnt: first_unused_output,
                inputs_cnt: first_unused_input,
            },
        }
    }

    /// Instantiate a new plugin.
    ///
    /// * `output_counts` contains the [`TypeId`] and [`WireCount`] for each output.
    /// * `input_counts` contains the [`TypeId`] and [`WireCount`] for each input.
    /// * `plugin_name` is the name of the plugin.
    /// * `operation` is the plugin operation.
    /// * `params` contains any associated parameters to the plugin operation.
    /// * `type_store` contains the [`TypeStore`] of the circuit.
    /// * `fun_store` contains the [`FunStore`] of the circuit.
    // SIEVE IR plugins require all of these arguments to be instantiated
    #[allow(clippy::too_many_arguments)]
    pub fn new_plugin(
        output_counts: Vec<(TypeId, WireCount)>,
        input_counts: Vec<(TypeId, WireCount)>,
        plugin_name: String,
        operation: String,
        params: Vec<PluginTypeArg>,
        _public_count: Vec<(TypeId, WireId)>,
        _private_count: Vec<(TypeId, WireId)>,
        type_store: &TypeStore,
        fun_store: &FunStore,
    ) -> Result<Self> {
        use crate::plugins::{
            DisjunctionV0, GaloisPolyV0, IterV0, MuxV0, MuxV1, PermutationCheckV1, VectorsV1,
        };

        let execution = match plugin_name.as_str() {
            MuxV0::NAME => MuxV0::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            MuxV1::NAME => MuxV1::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            PermutationCheckV1::NAME => PermutationCheckV1::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            IterV0::NAME => IterV0::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            VectorsV1::NAME => VectorsV1::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            GaloisPolyV0::NAME => GaloisPolyV0::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            DisjunctionV0::NAME => DisjunctionV0::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            RamBoolV0::NAME => RamBoolV0::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            RamBoolV1::NAME => RamBoolV1::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            RamArithV0::NAME => RamArithV0::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            RamArithV1::NAME => RamArithV1::instantiate(
                &operation,
                &params,
                &output_counts,
                &input_counts,
                type_store,
                fun_store,
            )?,
            name => bail!("Unsupported plugin: {name}"),
        };

        let (first_unused_output, first_unused_input) =
            output_input_counts(&output_counts, &input_counts);
        let body_max = execution
            .output_wire_max()
            .map(|out| std::cmp::max(first_unused_input, out));

        let mut type_presence = execution.type_id_mapping();
        for (ty, _) in output_counts.iter() {
            type_presence.set(*ty);
        }
        for (ty, _) in input_counts.iter() {
            type_presence.set(*ty);
        }

        let type_ids = type_presence.to_type_ids();

        Ok(FuncDecl {
            body: FunctionBody::Plugin(execution),
            output_counts,
            input_counts,
            compiled_info: CompiledInfo {
                args_count: first_unused_input,
                body_max,
                type_ids,
                outputs_cnt: first_unused_output,
                inputs_cnt: first_unused_input,
            },
        })
    }

    pub(crate) fn body(&self) -> &FunctionBody {
        &self.body
    }

    pub(crate) fn input_counts(&self) -> &[(TypeId, WireCount)] {
        &self.input_counts
    }

    pub(crate) fn output_counts(&self) -> &[(TypeId, WireCount)] {
        &self.output_counts
    }
}

/// Integer type to identify functions in a `FunStore`.
pub type FunId = u32;

/// The function store.
///
/// It maps function names `String` or `FunId` into  the [`FuncDecl`]
/// associated with functions. Functions inserted into the store are assigned unique [`FunId`].
/// The retrieval of [`FuncDecl`] by the name of a function has a runtime complexity
/// $log(n)$ where $n$ is the number of functions in the store.
/// The retrieval of [`FuncDecl`] by [`FunId`] is done in constant time; this is
/// important for performance of circuits using extensively function and call gates.
#[derive(Clone, Default)]
pub struct FunStore(
    // The internal representation maintains two mappings, one from names to `FunId` using a `BTreeMap`,
    // and another one associating a [`FunId`] to the [`FuncDecl`] using a vector indexed by [`FunId`].
    BTreeMap<String, FunId>,
    Vec<FuncDecl>,
);

impl FunStore {
    /// Insert a function to the `FunStore` with its name and returns a fresh `FunId`.
    /// It returns an error if the `FunStore` already contains a function associated with the same
    /// name.
    pub fn insert(&mut self, name: String, func: FuncDecl) -> Result<FunId> {
        ensure!(
            !self.0.contains_key(&name),
            "Function with name {name} already exists."
        );
        let fun_id = self
            .0
            .len()
            .try_into()
            .expect("Function store length greater than 2^32 - 1");
        self.0.insert(name.clone(), fun_id);
        self.1.push(func);
        Ok(fun_id)
    }

    /// Get function associated with a given [`FunId`].
    pub fn get_func(&self, fun_id: FunId) -> Result<&FuncDecl> {
        ensure!(
            (fun_id as usize) < self.1.len(),
            "Missing function id {} in func store",
            fun_id
        );
        Ok(&self.1[fun_id as usize])
    }

    /// Get function associated with a given name.
    pub fn get_func_by_name(&self, name: &String) -> Result<&FuncDecl> {
        let fun_id = self.name_to_fun_id(name)?;
        self.get_func(fun_id)
    }

    /// Get the id associated with a function name.
    pub fn name_to_fun_id(&self, name: &String) -> Result<FunId> {
        self.0
            .get(name)
            .copied()
            .ok_or_else(|| eyre!("Missing function {name}"))
    }
}

/// Types that act like a stream of values.
///
/// Tapes are used store instances/public-inputs or witnesses/private-inputs.
/// The interface of the trait allows to either ingest values into the tape, or pop values from the tape.
/// This interface allows for some implementation to only store a small number of the stream's values in memory at once.
pub trait TapeT {
    /// Ingest a tape value.
    ///
    /// This is an optional function is unimplemented by default. It makes sense to implement it when
    /// the tape is not a stream.
    fn ingest(&mut self, _n: Number) {
        unimplemented!("The function ingest() is not required.")
    }

    /// Ingest several tape values.
    ///
    /// This is an optional function is unimplemented by default. It makes sense to implement it when
    /// the tape is not a stream.
    fn ingest_many(&mut self, _ns: VecDeque<Number>) {
        unimplemented!("The function ingest_many() is not required.")
    }

    /// Pop a value from the tape.
    fn pop(&mut self) -> Option<Number>;

    /// Pop many values from the tape into a vector.
    fn pop_many(&mut self, num: u64) -> Option<Vec<Number>>;
}

/// Simple Tape type.
///
/// The internal of the type is a `VecDeque<...>`.
/// This makes the implementation of the [`TapeT`] trait straightforward using the standard
/// functions from the `VecDeque` collection.
#[derive(Debug, Default)]
pub struct Tape(VecDeque<Number>);

impl TapeT for Tape {
    fn ingest(&mut self, n: Number) {
        self.0.push_back(n);
    }

    fn ingest_many(&mut self, ns: VecDeque<Number>) {
        self.0.extend(ns);
    }

    fn pop(&mut self) -> Option<Number> {
        self.0.pop_front()
    }

    fn pop_many(&mut self, num: u64) -> Option<Vec<Number>> {
        let mut numbers = Vec::with_capacity(num as usize);
        for _ in 0..num {
            numbers.push(self.pop()?);
        }
        Some(numbers)
    }
}

/// Allows strongly typed iteration
/// over the tape with minimal overhead
#[repr(transparent)]
pub struct TapeF<'a, F>(&'a mut Box<dyn TapeT>, PhantomData<F>);

impl<'a, F: FiniteField + SieveIrDeserialize> Iterator for TapeF<'a, F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        let val = self.0.pop()?;
        F::from_number(&val).ok()
    }
}

/// A [`TapeT`] of instances (and a [`TapeT`] of witnesses) for a single field.
pub struct FieldInputs {
    ins: Box<dyn TapeT>,
    wit: Box<dyn TapeT>,
}

impl Default for FieldInputs {
    /// The default is to use [`Tape`] for the instance and witness tape.
    fn default() -> Self {
        Self {
            ins: Box::<Tape>::default(),
            wit: Box::<Tape>::default(),
        }
    }
}

impl FieldInputs {
    /// Access the witness tape for this field.
    pub fn wit(&mut self) -> &mut Box<dyn TapeT> {
        &mut self.wit
    }

    /// Access the instance tape for this field.
    pub fn ins(&mut self) -> &mut Box<dyn TapeT> {
        &mut self.ins
    }

    /// Make an iterator for witness tape.
    pub fn wit_iter<F>(&mut self) -> TapeF<F> {
        TapeF(self.wit(), PhantomData)
    }

    /// Make an iterator for the instance tape.
    pub fn ins_iter<F>(&mut self) -> TapeF<F> {
        TapeF(self.ins(), PhantomData)
    }
}

/// Public instance and private witness inputs to a circuit.
///
/// Effectively, this is a mapping from [`TypeId`] to [`FieldInputs`] to managed
/// these values in circuits utilizing more than one field type.
#[derive(Default)]
pub struct CircInputs {
    field: Vec<FieldInputs>,
}

// TODO: reconsider the interface for this: we could use .get()
impl CircInputs {
    /// Get the [`FieldInputs`] associated with a [`TypeId`].
    ///
    /// **CAUTION!** `TypeId`s should be assigned to type declarations in order
    /// and starting from 0. This interface **does not** enforce this, and will
    /// happily grow the internal representation to support larger `TypeId`s!
    #[inline]
    pub fn get(&mut self, type_id: usize) -> &mut FieldInputs {
        self.adjust_type_idx(type_id);
        &mut self.field[type_id]
    }

    #[inline]
    fn adjust_type_idx(&mut self, type_id: usize) {
        if self.field.len() <= type_id {
            self.field.resize_with(type_id + 1, Default::default);
        }
    }

    /// Set the instances for a [`TypeId`] from a concrete [`TapeT`].
    ///
    /// **CAUTION!** See the note on [`Self::get`].
    pub fn set_instances(&mut self, type_id: usize, instances: Box<dyn TapeT>) {
        self.adjust_type_idx(type_id);
        self.field[type_id].ins = instances;
    }

    /// Set the witnesses for a [`TypeId`] from a concrete [`TapeT`].
    ///
    /// *CAUTION!** See the note on [`Self::get`].
    pub fn set_witnesses(&mut self, type_id: usize, witnesses: Box<dyn TapeT>) {
        self.adjust_type_idx(type_id);
        self.field[type_id].wit = witnesses;
    }

    /// Ingest an instance into a [`TypeId`]'s instance queue.
    pub fn ingest_instance(&mut self, type_id: usize, instance: Number) {
        self.get(type_id).ins().ingest(instance);
    }

    /// Ingest a witness into a [`TypeId`]'s witness queue.
    pub fn ingest_witness(&mut self, type_id: usize, witness: Number) {
        self.get(type_id).wit().ingest(witness);
    }

    /// Ingest instances into a [`TypeId`]'s instance queue.
    pub fn ingest_instances(&mut self, type_id: usize, instances: VecDeque<Number>) {
        self.get(type_id).ins().ingest_many(instances);
    }

    /// Ingest witnesses into a [`TypeId`]'s witness queue.
    pub fn ingest_witnesses(&mut self, type_id: usize, witnesses: VecDeque<Number>) {
        self.get(type_id).wit().ingest_many(witnesses);
    }

    /// Pop a single instance from a [`TypeId`]'s instance queue.
    pub fn pop_instance(&mut self, type_id: usize) -> Option<Number> {
        self.get(type_id).ins().pop()
    }

    /// Pop a given number of instances from a [`TypeId`]'s instance queue.
    pub fn pop_instances(&mut self, type_id: usize, num: u64) -> Option<Vec<Number>> {
        self.get(type_id).ins().pop_many(num)
    }

    /// Pop a single witness from a [`TypeId`]'s witness queue.
    pub fn pop_witness(&mut self, type_id: usize) -> Option<Number> {
        self.get(type_id).wit().pop()
    }

    /// Pop a given number of witnesses from a [`TypeId`]'s witness queue.
    pub fn pop_witnesses(&mut self, type_id: usize, num: u64) -> Option<Vec<Number>> {
        self.get(type_id).wit().pop_many(num)
    }
}
