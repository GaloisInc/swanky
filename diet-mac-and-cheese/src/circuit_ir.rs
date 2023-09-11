//! This module contains types pertaining to the internal representation of the
//! SIEVE Circuit IR.

use crate::{
    fields::{extension_field_to_type_id, modulus_to_type_id},
    plugins::{Plugin, PluginBody, PluginType},
};
use eyre::{bail, ensure, eyre, Result};
use log::debug;
use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};
use std::{
    cmp::max,
    collections::{BTreeMap, VecDeque},
};

/// The wire index.
pub type WireId = u64;
/// A count of the number of wires.
pub type WireCount = u64;
/// The type index.
///
/// This is a value `< 256` that is associated with a specific Circuit IR
/// [`@type`](`TypeSpecification`).
pub type TypeId = u8;
/// An inclusive range of [`WireId`]s.
pub type WireRange = (WireId, WireId);

/// The conversion gate representation. The first [`TypeId`]-[`WireRange`]
/// pairing denotes the _output_ of the conversion, and the second pairing
/// denotes the _input_ of the conversion.
pub type ConvGate = (TypeId, WireRange, TypeId, WireRange);
/// The call gate representation. The [`FunId`] denotes a unique id associated with a function,
/// the first [`Vec`] denotes the _output_ wires, and the second [`Vec`] denotes the
/// _input_ wires.
pub type CallGate = (FunId, Vec<WireRange>, Vec<WireRange>);

/// The internal circuit representation gate types.
///
/// Most gates take a [`TypeId`] as their first argument, which denotes the
/// Circuit IR type associated with the given gate. In addition, the [`WireId`]
/// ordering for gates is generally: `<out> <in> ...`; that is, the first
/// [`WireId`] denotes the _output_ of the gate.
// This enum should fit in 32 bytes.
// Using `Box<Number>` for this reason.
#[derive(Clone, Debug)]
pub enum GateM {
    /// Store the given element in [`WireId`].
    Constant(TypeId, WireId, Box<Number>),
    /// Assert that the element in [`WireId`] is zero.
    AssertZero(TypeId, WireId),
    Copy(TypeId, WireId, WireId),
    /// Adds the elements in the latter two [`WireId`]s together, storing the
    /// result in the first [`WireId`].
    Add(TypeId, WireId, WireId, WireId),
    Sub(TypeId, WireId, WireId, WireId),
    Mul(TypeId, WireId, WireId, WireId),
    AddConstant(TypeId, WireId, WireId, Box<Number>),
    MulConstant(TypeId, WireId, WireId, Box<Number>),
    Instance(TypeId, WireId),
    Witness(TypeId, WireId),
    /// Does field conversion.
    Conv(Box<ConvGate>),
    New(TypeId, WireId, WireId),
    Delete(TypeId, WireId, WireId),
    Call(Box<CallGate>),
    Challenge(TypeId, WireId),
    Comment(String),
}

#[test]
fn size_of_gate_m_less_than_32_bytes() {
    // Enforce that `GateM` fits in 32 bytes.
    assert!(std::mem::size_of::<GateM>() <= 32);
}

pub type WireIdOpt = u32;

/// Optimized gates where wires can be u32.
#[derive(Clone, Debug)]
pub enum GateMOpt {
    Constant(TypeId, WireIdOpt, Box<Number>),
    AssertZero(TypeId, WireIdOpt),
    Copy(TypeId, WireIdOpt, WireIdOpt),
    Add(TypeId, WireIdOpt, WireIdOpt, WireIdOpt),
    Sub(TypeId, WireIdOpt, WireIdOpt, WireIdOpt),
    Mul(TypeId, WireIdOpt, WireIdOpt, WireIdOpt),
    AddConstant(TypeId, WireIdOpt, Box<(WireIdOpt, Box<Number>)>),
    MulConstant(TypeId, WireIdOpt, Box<(WireIdOpt, Box<Number>)>),
    Instance(TypeId, WireIdOpt),
    Witness(TypeId, WireIdOpt),
    Conv(Box<ConvGate>),
    New(TypeId, WireIdOpt, WireIdOpt),
    Delete(TypeId, WireIdOpt, WireIdOpt),
    Call(Box<CallGate>),
    Challenge(TypeId, WireIdOpt),
    Comment(Box<String>),
}

#[test]
fn size_of_gate_m_opt_less_than_16_bytes2() {
    // Enforce that `GateM` fits in 32 bytes.
    assert!(std::mem::size_of::<GateMOpt>() <= 16);
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
            | Copy(_, out, _)
            | Add(_, out, _, _)
            | Sub(_, out, _, _)
            | Mul(_, out, _, _)
            | AddConstant(_, out, _, _)
            | MulConstant(_, out, _, _)
            | Instance(_, out)
            | Witness(_, out)
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

    // Convert a slice of `GateM` into `GateMOpt`.
    fn to_gates_opt(gates: &[GateM]) -> Vec<GateMOpt> {
        let mut r = Vec::with_capacity(gates.len());
        use GateM::*;
        for gate in gates.iter() {
            let gate2 = match gate {
                Constant(ty, out, n) => GateMOpt::Constant(*ty, *out as WireIdOpt, n.clone()),
                Copy(ty, out, inp) => GateMOpt::Copy(*ty, *out as WireIdOpt, *inp as WireIdOpt),
                Add(ty, out, left, right) => GateMOpt::Add(
                    *ty,
                    *out as WireIdOpt,
                    *left as WireIdOpt,
                    *right as WireIdOpt,
                ),
                Sub(ty, out, left, right) => GateMOpt::Sub(
                    *ty,
                    *out as WireIdOpt,
                    *left as WireIdOpt,
                    *right as WireIdOpt,
                ),
                Mul(ty, out, left, right) => GateMOpt::Mul(
                    *ty,
                    *out as WireIdOpt,
                    *left as WireIdOpt,
                    *right as WireIdOpt,
                ),
                AddConstant(ty, out, left, number) => GateMOpt::AddConstant(
                    *ty,
                    *out as WireIdOpt,
                    Box::new((*left as WireIdOpt, number.clone())),
                ),
                MulConstant(ty, out, left, number) => GateMOpt::MulConstant(
                    *ty,
                    *out as WireIdOpt,
                    Box::new((*left as WireIdOpt, number.clone())),
                ),
                Instance(ty, out) => GateMOpt::Instance(*ty, *out as WireIdOpt),
                Witness(ty, out) => GateMOpt::Witness(*ty, *out as WireIdOpt),
                New(ty, start, end) => GateMOpt::New(*ty, *start as WireIdOpt, *end as WireIdOpt),
                Delete(ty, start, end) => {
                    GateMOpt::Delete(*ty, *start as WireIdOpt, *end as WireIdOpt)
                }
                AssertZero(ty, out) => GateMOpt::AssertZero(*ty, *out as WireIdOpt),
                Conv(c) => GateMOpt::Conv(c.clone()),
                Call(arg) => GateMOpt::Call(arg.clone()),
                Comment(s) => GateMOpt::Comment(Box::new(s.clone())),
                Challenge(ty, out) => GateMOpt::Challenge(*ty, *out as WireIdOpt),
            };
            r.push(gate2);
        }
        r
    }
}

impl GateMOpt {
    /// Return the [`TypeId`] associated with this gate.
    pub(crate) fn type_id(&self) -> TypeId {
        use GateMOpt::*;
        match self {
            Constant(ty, _, _)
            | AssertZero(ty, _)
            | Copy(ty, _, _)
            | Add(ty, _, _, _)
            | Sub(ty, _, _, _)
            | Mul(ty, _, _, _)
            | AddConstant(ty, _, _)
            | MulConstant(ty, _, _)
            | New(ty, _, _)
            | Delete(ty, _, _)
            | Instance(ty, _)
            | Witness(ty, _)
            | Challenge(ty, _) => *ty,
            Conv(_) | Call(_) => unreachable!("Should not ask the type_id for conv/call gates"),
            Comment(_) => panic!("There's no `TypeId` associated with a comment!"),
        }
    }
}
/// Specification for Circuit IR types.
///
/// This corresponds to the `@type` specifier. A type can either be a `Field` or
/// a `Plugin`.
#[derive(Clone, Debug)]
pub enum TypeSpecification {
    /// A field, stored as a [`TypeId`](std::any::TypeId).
    Field(std::any::TypeId),
    /// A plugin type.
    Plugin(PluginType),
}

/// A mapping from [`TypeId`]s to their [`TypeSpecification`]s.
///
/// This mapping contains all the types used in the circuit, accessible by their
/// [`TypeId`].
#[derive(Clone, Default)]
pub struct TypeStore(BTreeMap<TypeId, TypeSpecification>);

impl TypeStore {
    /// Insert a [`TypeId`]-[`TypeSpecification`] pair into the [`TypeStore`].
    pub(crate) fn insert(&mut self, key: TypeId, value: TypeSpecification) {
        self.0.insert(key, value);
    }

    /// Get the [`TypeSpecification`] associated with the given [`TypeId`].
    pub(crate) fn get(&self, key: &TypeId) -> eyre::Result<&TypeSpecification> {
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
    /// The function body as a sequence of optimized gates.
    GatesOpt(Vec<GateMOpt>),
    /// The function body as a plugin.
    Plugin(PluginBody),
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
            first_unused_wire_id(&output_counts, &input_counts);

        let body_max = gates
            .output_wire_max()
            .map(|out| std::cmp::max(first_unused_input, out));

        let type_ids = type_presence.to_type_ids();
        let body = if body_max.is_some() && body_max.unwrap() < (u32::MAX - 1) as WireId {
            let gates_opt = GateM::to_gates_opt(&gates.gates());
            FunctionBody::GatesOpt(gates_opt)
        } else {
            FunctionBody::Gates(gates)
        };

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
            name => bail!("Unsupported plugin: {name}"),
        };

        let (first_unused_output, first_unused_input) =
            first_unused_wire_id(&output_counts, &input_counts);
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
        let plugin_body = PluginBody::new(plugin_name, operation, execution);

        Ok(FuncDecl {
            body: FunctionBody::Plugin(plugin_body),
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
    Vec<(String, FuncDecl)>,
);

impl FunStore {
    /// Insert a function to the `FunStore` with its name and returns a fresh `FunId`.
    /// It returns an error if the `FunStore` already contains a function associated with the same
    /// name.
    pub fn insert(&mut self, name: String, func: FuncDecl) -> eyre::Result<FunId> {
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
        self.1.push((name, func));
        Ok(fun_id)
    }

    /// Get function associated with a given [`FunId`].
    pub fn get_func(&self, fun_id: FunId) -> eyre::Result<&FuncDecl> {
        ensure!(
            (fun_id as usize) < self.1.len(),
            "Missing function id {} in func store",
            fun_id
        );
        Ok(&self.1[fun_id as usize].1)
    }

    /// Get function associated with a given name.
    pub fn get_func_by_name(&self, name: &String) -> eyre::Result<&FuncDecl> {
        let fun_id = self.name_to_fun_id(name)?;
        self.get_func(fun_id)
    }

    /// Get the id associated with a function name.
    pub fn name_to_fun_id(&self, name: &String) -> eyre::Result<FunId> {
        self.0
            .get(name)
            .copied()
            .ok_or_else(|| eyre!("Missing function {name}"))
    }

    /// Get the name associated with a `FunId`.
    pub fn id_to_name(&self, fun_id: FunId) -> eyre::Result<&String> {
        ensure!(
            (fun_id as usize) < self.1.len(),
            "No function name asociated to function id {}",
            fun_id
        );
        Ok(&self.1[fun_id as usize].0)
    }
}

// TODO: add type synonym for Vec<u8> serialized field values,
//       maybe use Box<[u8]> like in other places.
#[derive(Debug, Default)]
pub struct CircInputs {
    ins: Vec<VecDeque<Number>>,
    wit: Vec<VecDeque<Number>>,
}

impl CircInputs {
    #[inline]
    fn adjust_ins_type_idx(&mut self, type_id: usize) {
        let n = self.ins.len();
        if n <= type_id {
            for _i in n..(type_id + 1) {
                self.ins.push(Default::default());
            }
        }
    }
    #[inline]
    fn adjust_wit_type_idx(&mut self, type_id: usize) {
        let n = self.wit.len();
        if n <= type_id {
            for _i in n..(type_id + 1) {
                self.wit.push(Default::default());
            }
        }
    }

    // Return the number of instances associated with a given `type_id`
    pub fn num_instances(&self, type_id: usize) -> usize {
        self.ins[type_id].len()
    }

    // Return the number of witnesses associated with a given `type_id`
    pub fn num_witnesses(&self, type_id: usize) -> usize {
        self.wit[type_id].len()
    }

    /// Ingest instance.
    pub fn ingest_instance(&mut self, type_id: usize, instance: Number) {
        self.adjust_ins_type_idx(type_id);
        self.ins[type_id].push_back(instance);
    }

    /// Ingest witness.
    pub fn ingest_witness(&mut self, type_id: usize, witness: Number) {
        self.adjust_wit_type_idx(type_id);
        self.wit[type_id].push_back(witness);
    }

    /// Ingest instances.
    pub fn ingest_instances(&mut self, type_id: usize, instances: VecDeque<Number>) {
        self.adjust_ins_type_idx(type_id);
        self.ins[type_id] = instances;
    }

    /// Ingest witnesses.
    pub fn ingest_witnesses(&mut self, type_id: usize, witnesses: VecDeque<Number>) {
        self.adjust_wit_type_idx(type_id);
        self.wit[type_id] = witnesses;
    }

    pub fn pop_instance(&mut self, type_id: usize) -> Option<Number> {
        self.adjust_ins_type_idx(type_id);
        self.ins[type_id].pop_front()
    }

    pub fn pop_witness(&mut self, type_id: usize) -> Option<Number> {
        self.adjust_wit_type_idx(type_id);
        self.wit[type_id].pop_front()
    }
}
