//! This module contains types pertaining to the internal representation of the
//! SIEVE Circuit IR.

use crate::{
    fields::modulus_to_type_id,
    plugins::{MuxV0, Plugin, PluginBody, PluginType},
};
use crypto_bigint::ArrayEncoding;
use eyre::{eyre, Result};
use log::debug;
use std::{
    cmp::max,
    collections::{BTreeMap, VecDeque},
};

pub type WireId = u64;
pub type WireCount = u64;
/// The type index.
///
/// This is a value `< 256` that is associated with a specific Circuit IR
/// [`@type`](`TypeSpecification`).
pub type TypeId = u8;
pub type FunId = usize;
pub type WireRange = (WireId, WireId);

/// The Circuit IR gate types.
// This enum should fit in 32 bytes.
// Using Box<Vec<u8>> for this reason, beware the size of `Box<[T]>` is not 8, it's 16.
#[derive(Clone, Debug)]
pub enum GateM {
    Constant(TypeId, WireId, Box<Vec<u8>>), // Using Box<Vec<u8>>
    AssertZero(TypeId, WireId),
    Copy(TypeId, WireId, WireId),
    Add(TypeId, WireId, WireId, WireId),
    Mul(TypeId, WireId, WireId, WireId),
    AddConstant(TypeId, WireId, WireId, Box<Vec<u8>>),
    MulConstant(TypeId, WireId, WireId, Box<Vec<u8>>),
    Instance(TypeId, WireId),
    Witness(TypeId, WireId),
    Conv(Box<(TypeId, WireRange, TypeId, WireRange)>),
    New(TypeId, WireId, WireId),
    Delete(TypeId, WireId, WireId),
    Call(Box<(String, Vec<WireRange>, Vec<WireRange>)>),
    Challenge(TypeId, WireId),
    Comment(String),
}

impl GateM {
    /// Return the [`TypeId`] associated with this gate.
    pub(crate) fn type_id(&self) -> TypeId {
        use GateM::*;
        match self {
            Constant(ty, _, _) => *ty,
            AssertZero(ty, _) => *ty,
            Copy(ty, _, _) => *ty,
            Add(ty, _, _, _) => *ty,
            Mul(ty, _, _, _) => *ty,
            AddConstant(ty, _, _, _) => *ty,
            MulConstant(ty, _, _, _) => *ty,
            New(ty, _, _) => *ty,
            Delete(ty, _, _) => *ty,
            Instance(ty, _) => *ty,
            Witness(ty, _) => *ty,
            Conv(_) => todo!(),
            Call(_) => todo!(),
            Challenge(ty, _) => *ty,
            Comment(_) => panic!("There's no `TypeId` associated with a comment!"),
        }
    }

    /// Return the [`WireId`] associated with the output of this gate, or
    /// `None` if the gate has no output wire.
    fn out_wire(&self) -> Option<WireId> {
        use GateM::*;
        match self {
            Constant(_, out, _value) => Some(*out),
            AssertZero(_, _inp) => None,
            Copy(_, out, _inp) => Some(*out),
            Add(_, out, _left, _right) => Some(*out),
            Mul(_, out, _left, _right) => Some(*out),
            AddConstant(_, out, _inp, _constant) => Some(*out),
            MulConstant(_, out, _inp, _constant) => Some(*out),
            Conv(c) => {
                let (_, (_, out), _, _) = c.as_ref();
                Some(*out)
            }
            Instance(_, out) => Some(*out),
            Witness(_, out) => Some(*out),
            New(_, _, last) => Some(*last),
            Delete(_, _, _) => None,
            Call(arg) => {
                let (_, v, _) = arg.as_ref();
                let mut out = None;
                for (_first, last) in v.iter() {
                    match out {
                        None => {
                            out = Some(*last);
                        }
                        Some(m) => {
                            out = Some(max(m, *last));
                        }
                    }
                }
                out
            }
            Challenge(_, out) => Some(*out),
            Comment(_str) => None,
        }
    }
}

/// Specification for Circuit IR types.
///
/// This corresponds to the `@type` specifier. A type can either be a `Field` or
/// a `Plugin`.
#[derive(Clone, Debug)]
pub enum TypeSpecification {
    /// The field, stored as a [`TypeId`](std::any::TypeId).
    Field(std::any::TypeId),
    /// The plugin type.
    Plugin(PluginType),
}

/// A mapping from [`TypeId`]s to their [`TypeSpecification`]s.
///
/// This mapping contains all the types used in the circuit, accessible by their
/// [`TypeId`].
#[derive(Clone, Default)]
pub struct TypeStore(BTreeMap<TypeId, TypeSpecification>);

impl TypeStore {
    pub(crate) fn insert(&mut self, key: TypeId, value: TypeSpecification) {
        self.0.insert(key, value);
    }

    // pub(crate) fn get(&self, key: &TypeId) -> eyre::Result<&TypeSpecification> {
    //     self.0
    //         .get(key)
    //         .ok_or_else(|| eyre!("Type ID {key} not found in `TypeStore`"))
    // }

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
                    // `modulus` is provided as a fixed length large integer, so
                    // when we convert it to a vector we get a bunch of zero
                    // bytes at the end. We need to remove those before we pass
                    // the vector to `modulus_to_type_id`, otherwise it won't
                    // correctly recognize the vector.
                    let v = modulus.to_le_byte_array().to_vec();
                    // Get the last index that is non-zero.
                    let to = v.iter().rposition(|x| *x != 0).unwrap_or(v.len() - 1);
                    TypeSpecification::Field(modulus_to_type_id(&v[..=to])?)
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

impl TryFrom<Vec<Vec<u8>>> for TypeStore {
    type Error = eyre::Error;

    fn try_from(fields: Vec<Vec<u8>>) -> std::result::Result<Self, Self::Error> {
        debug!("Converting vector of fields to `TypeStore`");
        if fields.len() > 256 {
            return Err(eyre!("Too many types specified: {} > 256", fields.len()));
        }
        let mut store = TypeStore::default();
        for (i, field) in fields.into_iter().enumerate() {
            let spec = TypeSpecification::Field(modulus_to_type_id(&field)?);
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
            Constant(ty, _, _) => {
                self.0[*ty as usize] = true;
            }
            AssertZero(ty, _) => {
                self.0[*ty as usize] = true;
            }
            Copy(ty, _, _) => {
                self.0[*ty as usize] = true;
            }
            Add(ty, _, _, _) => {
                self.0[*ty as usize] = true;
            }
            Mul(ty, _, _, _) => {
                self.0[*ty as usize] = true;
            }
            AddConstant(ty, _, _, _) => {
                self.0[*ty as usize] = true;
            }
            MulConstant(ty, _, _, _) => {
                self.0[*ty as usize] = true;
            }
            Conv(c) => {
                let (ty1, _, ty2, _) = c.as_ref();
                self.0[*ty1 as usize] = true;
                self.0[*ty2 as usize] = true;
            }
            Instance(ty, _) => {
                self.0[*ty as usize] = true;
            }
            Witness(ty, _) => {
                self.0[*ty as usize] = true;
            }
            New(ty, _, _) => {
                self.0[*ty as usize] = true;
            }
            Delete(ty, _, _) => {
                self.0[*ty as usize] = true;
            }
            Call(_) => {}
            Challenge(ty, _) => self.0[*ty as usize] = true,
            Comment(_) => {}
        }
    }

    /// Convert [`TypeIdMapping`] to a [`Vec`] containing the set [`TypeId`]s.
    fn to_type_ids(self) -> Vec<TypeId> {
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
#[derive(Clone)]
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
    fn output_wire_max(&self) -> Option<WireId> {
        self.gates
            .iter()
            .fold(None, |acc, x| max(acc, x.out_wire()))
    }
}

#[derive(Clone)]
pub(crate) enum GatesOrPluginBody {
    Gates(GatesBody),
    Plugin(PluginBody),
}

#[derive(Clone)]
pub(crate) struct CompiledInfo {
    /// Count of wires for output/input args to function.
    pub(crate) args_count: Option<WireId>,
    // Maximum [`WireId`] in the function body.
    pub(crate) body_max: Option<WireId>,
    /// [`TypeId`]s encountered in the function body.
    pub(crate) type_ids: Vec<TypeId>,
    /// Gates associated to the function, if any.
    pub(crate) plugin_gates: Option<GatesBody>,
}

/// Function declaration.
#[derive(Clone)]
pub struct FuncDecl {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    fun_id: FunId,
    body: GatesOrPluginBody,
    output_counts: Vec<(TypeId, WireCount)>,
    input_counts: Vec<(TypeId, WireCount)>,
    pub(crate) compiled_info: CompiledInfo, // pub(crate) to ease logging
}

impl FuncDecl {
    pub fn new_function(
        name: String,
        fun_id: FunId,
        gates: Vec<GateM>,
        output_counts: Vec<(TypeId, WireCount)>,
        input_counts: Vec<(TypeId, WireCount)>,
    ) -> Self {
        let gates = GatesBody::new(gates);
        let body_max = gates.output_wire_max();
        let mut type_presence = TypeIdMapping::from(&gates);
        let mut args_count = 0;
        for (ty, wc) in output_counts.iter() {
            type_presence.set(*ty);
            args_count += wc;
        }
        for (ty, wc) in input_counts.iter() {
            type_presence.set(*ty);
            args_count += wc;
        }

        let body = GatesOrPluginBody::Gates(gates);
        let type_ids = type_presence.to_type_ids();

        FuncDecl {
            name,
            fun_id,
            body,
            output_counts,
            input_counts,
            compiled_info: CompiledInfo {
                args_count: Some(args_count),
                body_max,
                type_ids,
                plugin_gates: None,
            },
        }
    }

    pub fn new_plugin(
        name: String,
        fun_id: FunId,
        output_counts: Vec<(TypeId, WireCount)>,
        input_counts: Vec<(TypeId, WireCount)>,
        plugin_name: String,
        operation: String,
        params: Vec<String>,
        _public_count: Vec<(TypeId, WireId)>,
        _private_count: Vec<(TypeId, WireId)>,
        type_store: &TypeStore,
    ) -> Result<Self> {
        // Count of input and output wires.
        let mut count = 0;
        for (_, w) in output_counts.iter() {
            count += w;
        }
        for (_, w) in input_counts.iter() {
            count += w;
        }

        let gates = match plugin_name.as_str() {
            MuxV0::NAME => MuxV0::gates_body(
                &operation,
                &params,
                count,
                &output_counts,
                &input_counts,
                type_store,
            )?,
            // PermutationCheckV1::NAME => PermutationCheckV1::gates_body(
            //     &operation,
            //     &params,
            //     count,
            //     &output_counts,
            //     &input_counts,
            //     type_store,
            // )?,
            name => return Err(eyre!("Unsupported plugin: {name}")),
        };

        let body_max = gates.output_wire_max();
        let type_presence = TypeIdMapping::from(&gates);
        let type_ids = type_presence.to_type_ids();
        let plugin_body = PluginBody::new(plugin_name, operation);

        Ok(FuncDecl {
            name,
            fun_id,
            body: GatesOrPluginBody::Plugin(plugin_body),
            output_counts,
            input_counts,
            compiled_info: CompiledInfo {
                args_count: Some(count),
                body_max,
                type_ids,
                plugin_gates: Some(gates),
            },
        })
    }

    pub(crate) fn body(&self) -> &GatesOrPluginBody {
        &self.body
    }

    pub(crate) fn input_counts(&self) -> &[(TypeId, WireCount)] {
        &self.input_counts
    }

    pub(crate) fn output_counts(&self) -> &[(TypeId, WireCount)] {
        &self.output_counts
    }
}

/// A mapping of function names to their [`FuncDecl`]s.
#[derive(Clone, Default)]
pub struct FunStore(BTreeMap<String, FuncDecl>);

impl FunStore {
    pub fn insert(&mut self, name: String, func: FuncDecl) {
        self.0.insert(name, func);
    }

    pub fn get(&self, name: &String) -> eyre::Result<&FuncDecl> {
        self.0
            .get(name)
            .ok_or_else(|| eyre!("Missing function name '{name}' in `FuncStore`"))
    }
}

// TODO: add type synonym for Vec<u8> serialized field values,
//       maybe use Box<[u8]> like in other places.
#[derive(Default)]
pub struct CircInputs {
    pub ins: Vec<VecDeque<Vec<u8>>>,
    pub wit: Vec<VecDeque<Vec<u8>>>,
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

    /// Ingest instance.
    pub fn ingest_instance(&mut self, type_id: usize, instance: Vec<u8>) {
        self.adjust_ins_type_idx(type_id);
        self.ins[type_id].push_back(instance);
    }

    /// Ingest witness.
    pub fn ingest_witness(&mut self, type_id: usize, witness: Vec<u8>) {
        self.adjust_wit_type_idx(type_id);
        self.wit[type_id].push_back(witness);
    }

    /// Ingest instances.
    pub fn ingest_instances(&mut self, type_id: usize, instances: VecDeque<Vec<u8>>) {
        self.adjust_ins_type_idx(type_id);
        self.ins[type_id] = instances;
    }

    /// Ingest witnesses.
    pub fn ingest_witnesses(&mut self, type_id: usize, witnesses: VecDeque<Vec<u8>>) {
        self.adjust_wit_type_idx(type_id);
        self.wit[type_id] = witnesses;
    }

    pub fn pop_instance(&mut self, type_id: usize) -> Option<Vec<u8>> {
        self.adjust_ins_type_idx(type_id);
        self.ins[type_id].pop_front()
    }

    pub fn pop_witness(&mut self, type_id: usize) -> Option<Vec<u8>> {
        self.adjust_wit_type_idx(type_id);
        self.wit[type_id].pop_front()
    }
}
