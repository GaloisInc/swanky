/*!
Tools to read SIEVE IR from flatbuffers, in particular to stream large circuits.

This module provides types to work with circuit inputs (public instances and
private witnesses) and relations given in the SIEVE IR flatbuffer format.

When dealing with very large circuits, this module should be preferred over
[`crate::sieveir_reader_text`], since it streams relations rather than loading
them entirely into memory (the exception being functions).
*/
use crate::sieveir_phase2::sieve_ir_generated::sieve_ir::{self as g};
use crate::{
    circuit_ir::{FunStore, FuncDecl, GateM, TypeSpecification, TypeStore},
    plugins::PluginType,
};
use crate::{
    circuit_ir::{TapeT, TypeId},
    sieveir_phase2::sieve_ir_generated::sieve_ir::GateSet as gs,
};
use crate::{
    fields::modulus_to_type_id, sieveir_phase2::sieve_ir_generated::sieve_ir::DirectiveSet as ds,
};
use eyre::{ensure, eyre, Result};
use flatbuffers::{read_scalar_at, UOffsetT, SIZE_UOFFSET};
use log::info;
use mac_n_cheese_sieve_parser::{Number, PluginTypeArg, ValueStreamKind};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

fn bigint_from_bytes(bytes: &[u8]) -> Number {
    assert!(bytes.len() <= Number::BYTES, "number too big",);

    let mut bigint_bytes = [0; Number::BYTES];
    bigint_bytes[..bytes.len()].copy_from_slice(bytes);

    Number::from_le_slice(&bigint_bytes)
}

// Read a flatbuffers size prefix (4 bytes, little-endian). Size including the prefix.
//
// This function is from the zkinterface library.
fn read_size_prefix(buf: &[u8]) -> usize {
    if buf.len() < SIZE_UOFFSET {
        return 0;
    }
    let size = unsafe { read_scalar_at::<UOffsetT>(buf, 0) as usize };
    SIZE_UOFFSET + size
}

/// Read from a stream a size prefix and stores the content in a vector provided as an argument.
///
/// It returns an `Option<()>` with `Some(())` indicating that it succeeded to read more
/// and `None` if there was nothing more to read.
/// This function is adapted from `read_buffer` from zkinterface.
fn read_size_prefix_in_vec(stream: &mut impl Read, buffer: &mut Vec<u8>) -> Result<Option<()>> {
    buffer.clear();
    buffer.extend_from_slice(&[0u8; 4]);
    if stream.read_exact(buffer).is_err() {
        return Ok(None); // not even a prefix to read, done!
    }
    let size = read_size_prefix(buffer);
    if size <= SIZE_UOFFSET {
        return Ok(None); // a 0 size prefix
    }
    buffer.resize(size, 0u8);
    stream.read_exact(&mut buffer[4..])?;
    Ok(Some(()))
}

/// Read instances from bytes into the `instances` argument and return the associated field.
///
/// # Panics
///
/// May panic from flatbuffer error.
fn read_public_inputs_bytes(bytes: &[u8], instances: &mut VecDeque<Number>) -> Number {
    let root = g::size_prefixed_root_as_root(bytes);

    if root.is_err() {
        panic!("Error while reading flatbuffer public input")
    }

    let v = root.unwrap().message_as_public_inputs().unwrap();

    let type_field = v
        .type_()
        .unwrap()
        .element_as_field()
        .unwrap()
        .modulo()
        .unwrap()
        .value()
        .unwrap();

    let v1 = v.inputs().unwrap();
    let n = v1.len();

    for i in 0..n {
        let instance_read = v1.get(i);
        let t = instance_read.value().unwrap();
        instances.push_back(bigint_from_bytes(t.bytes()));
    }

    bigint_from_bytes(type_field.bytes())
}

/// Read instances from path and return the associated field.
///
/// # Panics
///
/// May panic with io error or flatbuffer error.
pub fn read_public_inputs(path: &PathBuf, instances: &mut VecDeque<Number>) -> Number {
    let md = std::fs::metadata(path).unwrap();
    if !md.is_file() {
        panic!("Only support file instance")
    }

    let mut file = std::fs::File::open(path).unwrap();
    let mut buffer = vec![];
    file.read_to_end(&mut buffer).unwrap();

    read_public_inputs_bytes(&buffer, instances)
}

/// Read witnesses from bytes into the `witnesses` argument and return the associated field.
///
/// # Panics
///
/// May panic from flatbuffer error.
fn read_private_inputs_bytes(bytes: &[u8], witnesses: &mut VecDeque<Number>) -> Number {
    let root = g::size_prefixed_root_as_root(bytes);

    if root.is_err() {
        panic!("Error while reading flatbuffer private input")
    }

    let v = root.unwrap().message_as_private_inputs().unwrap();

    let type_field = v
        .type_()
        .unwrap()
        .element_as_field()
        .unwrap()
        .modulo()
        .unwrap()
        .value()
        .unwrap();

    let v1 = v.inputs().unwrap();
    let n = v1.len();

    for i in 0..n {
        let witness_read = v1.get(i);
        let t = witness_read.value().unwrap();
        witnesses.push_back(bigint_from_bytes(t.bytes()));
    }

    bigint_from_bytes(type_field.bytes())
}

/// SIEVE IR inputs (public instances or private witnesses) from flatbuffers.
///
/// Together with [`BufRelation`], provides a streaming interface to SIEVE IR
/// circuits expressed as flatbuffers.
pub struct InputFlatbuffers {
    buffer_file: BufReader<File>,
    buffer_mem: Vec<u8>,
    queue: VecDeque<Number>,
    field: Option<Number>,
    ty: ValueStreamKind,
}

impl InputFlatbuffers {
    /// Create an `InputFlatbuffers` for private witness inputs.
    pub fn new_private_inputs(path: &PathBuf) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let buffer_file = BufReader::new(file);
        let buffer_mem = vec![];

        let mut private_inputs = Self {
            buffer_file,
            buffer_mem,
            queue: Default::default(),
            field: Default::default(),
            ty: ValueStreamKind::Private,
        };
        private_inputs.load_more_in_queue()?;
        Ok(private_inputs)
    }

    /// Create an `InputFlatbuffers` for public instance inputs.
    pub fn new_public_inputs(path: &PathBuf) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let buffer_file = BufReader::new(file);
        let buffer_mem = vec![];
        let mut public_inputs = Self {
            buffer_file,
            buffer_mem,
            queue: Default::default(),
            field: Default::default(),
            ty: ValueStreamKind::Public,
        };
        public_inputs.load_more_in_queue()?;
        Ok(public_inputs)
    }

    fn next_one(&mut self) -> Result<Option<Number>> {
        if let Some(n) = self.queue.pop_front() {
            return Ok(Some(n));
        }

        // the queue is empty let's load some more
        self.load_more_in_queue()?;

        if let Some(n) = self.queue.pop_front() {
            Ok(Some(n))
        } else {
            Ok(None)
        }
    }

    /// Load more instances or witnesses into the internal queue.
    fn load_more_in_queue(&mut self) -> Result<Option<()>> {
        let msg = read_size_prefix_in_vec(&mut self.buffer_file, &mut self.buffer_mem)?;
        match msg {
            None => Ok(None),
            Some(_) => {
                let field_read = match self.ty {
                    ValueStreamKind::Private => {
                        read_private_inputs_bytes(&self.buffer_mem, &mut self.queue)
                    }
                    ValueStreamKind::Public => {
                        read_public_inputs_bytes(&self.buffer_mem, &mut self.queue)
                    }
                };
                ensure!(
                    self.field.is_none() || self.field.unwrap() == field_read,
                    "inconsistent field in tape, previous:{} current:{}",
                    self.field.unwrap(),
                    field_read,
                );
                self.field = Some(field_read);
                Ok(Some(()))
            }
        }
    }
}

impl TapeT for InputFlatbuffers {
    fn pop(&mut self) -> Option<Number> {
        match self.next_one() {
            Ok(r) => r,
            Err(_) => None,
        }
    }

    fn pop_many(&mut self, num: u64) -> Option<Vec<Number>> {
        let mut numbers = Vec::with_capacity(num as usize);
        for _ in 0..num {
            numbers.push(self.pop()?);
        }
        Some(numbers)
    }
}

/// Read witnesses from path and return the associated field.
///
/// # Panics
///
/// May panic with io error or flatbuffer error.
pub fn read_private_inputs(path: &PathBuf, witnesses: &mut VecDeque<Number>) -> Number {
    let file = std::fs::File::open(path).unwrap();
    let mut buffer = BufReader::new(file);

    let mut buffer_mem = vec![];
    let mut field_res = None;
    loop {
        let msg = read_size_prefix_in_vec(&mut buffer, &mut buffer_mem);
        match msg {
            Err(_) => {
                panic!("Error while reading private inputs");
            }
            Ok(b) => match b {
                None => {
                    break;
                }
                Some(_) => {
                    let field = read_private_inputs_bytes(&buffer_mem, witnesses);
                    assert!(field_res.is_none() || field_res.unwrap() == field);
                    field_res = Some(field);
                }
            },
        }
    }
    field_res.expect("Could not determine field modulus")
}

/// A buffered SIEVE IR relation.
///
/// This provides an interface similar to [`BufReader`] to stream SIEVE IR
/// flatbuffer relations from disk.
pub struct BufRelation {
    /// The [`TypeStore`] for this relation.
    ///
    /// In most cases, `TypeStore::try_from` should be used in conjunction with
    /// [`read_types`] to compute this field.
    pub type_store: TypeStore,

    /// The [`FunStore`] for this relation, which will be built as
    /// [`Self::read_next`] is called.
    pub fun_store: FunStore,

    /// The current batch of gates to be evaluated.
    pub gates: Vec<GateM>,
    buffer_file: BufReader<File>,
    buffer_bytes: Vec<u8>,
}

impl BufRelation {
    /// Create a new `BufRelation` given a [`TypeStore`].
    ///
    /// This method returns an error if `path` is not a file.
    pub fn new(path: &PathBuf, type_store: &TypeStore) -> Result<Self> {
        let md = std::fs::metadata(path).unwrap();

        if md.is_file() {
            let file = std::fs::File::open(path).unwrap();
            let buffer = BufReader::new(file);
            let fun_store = FunStore::default();
            Ok(BufRelation {
                type_store: type_store.clone(),
                fun_store,
                gates: Vec::new(),
                buffer_file: buffer,
                buffer_bytes: Vec::new(),
            })
        } else {
            Err(eyre!("cannot open file"))
        }
    }

    /// Advance the stream, accumulating functions / gates as appropriate.
    ///
    /// # Panics
    ///
    /// This method panics if there is an error reading the relation buffer.
    pub fn read_next(&mut self) -> Option<()> {
        let msg = read_size_prefix_in_vec(&mut self.buffer_file, &mut self.buffer_bytes);
        match msg {
            Err(_) => {
                panic!("Error while reading relation");
            }
            Ok(b) => match b {
                None => {
                    info!("reached end of everything");
                    return None;
                }
                Some(_) => {
                    self.gates.clear();
                    read_relation_and_functions_bytes_accu(self);
                }
            },
        }
        Some(())
    }
}

fn flatbuffer_gate_to_gate(the_gate: g::Gate, fun_store: &FunStore) -> GateM {
    match the_gate.gate_type() {
        gs::GateConstant => {
            let u = the_gate.gate_as_gate_constant().unwrap();
            GateM::Constant(
                u.type_id(),
                u.out_id(),
                Box::from(bigint_from_bytes(u.constant().unwrap().bytes())),
            )
        }
        gs::GateAssertZero => {
            let u = the_gate.gate_as_gate_assert_zero().unwrap();
            GateM::AssertZero(u.type_id(), u.in_id())
        }
        gs::GateCopy => {
            let u = the_gate.gate_as_gate_copy().unwrap();
            let mut src = vec![];
            for input in u.in_id().into_iter().flat_map(|x| x.iter()) {
                src.push((input.first_id(), input.last_id()))
            }
            GateM::Copy(
                u.type_id(),
                (
                    u.out_id().unwrap().first_id(),
                    u.out_id().unwrap().last_id(),
                ),
                Box::new(src),
            )
        }
        gs::GateAdd => {
            let u = the_gate.gate_as_gate_add().unwrap();
            GateM::Add(u.type_id(), u.out_id(), u.left_id(), u.right_id())
        }
        gs::GateMul => {
            let u = the_gate.gate_as_gate_mul().unwrap();
            GateM::Mul(u.type_id(), u.out_id(), u.left_id(), u.right_id())
        }
        gs::GateAddConstant => {
            let u = the_gate.gate_as_gate_add_constant().unwrap();
            GateM::AddConstant(
                u.type_id(),
                u.out_id(),
                u.in_id(),
                Box::from(bigint_from_bytes(u.constant().unwrap().bytes())),
            )
        }
        gs::GateMulConstant => {
            let u = the_gate.gate_as_gate_mul_constant().unwrap();
            GateM::MulConstant(
                u.type_id(),
                u.out_id(),
                u.in_id(),
                Box::from(bigint_from_bytes(u.constant().unwrap().bytes())),
            )
        }
        gs::GatePublic => {
            let u = the_gate.gate_as_gate_public().unwrap();
            GateM::Instance(
                u.type_id(),
                (
                    u.out_id().unwrap().first_id(),
                    u.out_id().unwrap().last_id(),
                ),
            )
        }
        gs::GatePrivate => {
            let u = the_gate.gate_as_gate_private().unwrap();
            GateM::Witness(
                u.type_id(),
                (
                    u.out_id().unwrap().first_id(),
                    u.out_id().unwrap().last_id(),
                ),
            )
        }
        gs::GateNew => {
            let u = the_gate.gate_as_gate_new().unwrap();
            GateM::New(u.type_id(), u.first_id(), u.last_id())
        }
        gs::GateDelete => {
            let u = the_gate.gate_as_gate_delete().unwrap();
            GateM::Delete(u.type_id(), u.first_id(), u.last_id())
        }
        gs::GateCall => {
            let u = the_gate.gate_as_gate_call().unwrap();

            // read the output wires
            let vo = u.out_ids().unwrap();
            let mut outids = Vec::with_capacity(vo.len());
            for o in vo {
                outids.push((o.first_id(), o.last_id()));
            }

            // read the input wires
            let vi = u.in_ids().unwrap();
            let mut inids = Vec::with_capacity(vi.len());
            for i in vi {
                inids.push((i.first_id(), i.last_id()));
            }
            let fun_id = fun_store.name_to_fun_id(&u.name().unwrap().into()).unwrap();
            GateM::Call(Box::new((fun_id, outids, inids)))
        }
        gs::GateConvert => {
            let u = the_gate.gate_as_gate_convert().unwrap();

            // read the output wires
            let ty_out = u.out_type_id();
            let out_first = u.out_first_id();
            let out_last = u.out_last_id();

            // read the input wires
            let ty_in = u.in_type_id();
            let in_first = u.in_first_id();
            let in_last = u.in_last_id();

            GateM::Conv(Box::new((
                ty_out,
                (out_first, out_last),
                ty_in,
                (in_first, in_last),
            )))
        }
        gs::NONE => {
            panic!("unhandled NONE");
        }
        _ => {
            panic!("unhandled other case");
        }
    }
}

/// Read relation and functions from `BufRelation`.
///
/// # Panics
///
/// May panic with io error or flatbuffer error.
fn read_relation_and_functions_bytes_accu(rel: &mut BufRelation) -> Option<()> {
    // Checked version
    /*
    let v = g::size_prefixed_root_as_root_with_opts(
        &flatbuffers::VerifierOptions {
            max_tables: u32::MAX as usize,
            ..flatbuffers::VerifierOptions::default()
        },
        rel.buffer_bytes.as_slice(),
    )
    .unwrap()
    .message_as_relation()
    .unwrap();*/

    // Unchecked
    let v = unsafe {
        g::size_prefixed_root_as_root_unchecked(rel.buffer_bytes.as_slice())
            .message_as_relation()
            .unwrap()
    };

    let v1 = v.directives().unwrap();
    let n = v1.len();

    for i in 0..n {
        let directive_read = v1.get(i);
        let t = directive_read.directive_type();

        match t {
            ds::Gate => {
                let gate = flatbuffer_gate_to_gate(
                    directive_read.directive_as_gate().unwrap(),
                    &rel.fun_store,
                );
                rel.gates.push(gate);
            }
            ds::Function => {
                let mut gates_body = Vec::new();
                let mut output_counts = Vec::new();
                let mut input_counts = Vec::new();

                let the_function = directive_read.directive_as_function().unwrap();
                let name: String = the_function.name().unwrap().into();

                // read the output counts
                let output_count = the_function.output_count().unwrap();
                for o in output_count {
                    output_counts.push((o.type_id(), o.count()));
                }

                // read the input counts
                let input_count = the_function.input_count().unwrap();
                for i in input_count {
                    input_counts.push((i.type_id(), i.count()));
                }

                let function_bdy = the_function.body_type();
                match function_bdy {
                    g::FunctionBody::PluginBody => {
                        let x = the_function.body_as_plugin_body().unwrap();
                        let plugin_name = x.name().unwrap().into();
                        let operation = x.operation().unwrap_or("missing_op").into();
                        let params_flatc = x.params();
                        let params = if let Some(params_flatc) = params_flatc {
                            let m = params_flatc.len();
                            let mut params_v = vec![];
                            for j in 0..m {
                                params_v.push(PluginTypeArg::from_str(params_flatc.get(j)).ok()?);
                            }
                            params_v
                        } else {
                            vec![]
                        };
                        let mut public_count = vec![];
                        for p in x.public_count().unwrap() {
                            public_count.push((p.type_id(), p.count()));
                        }
                        let mut private_count = vec![];
                        for p in x.private_count().unwrap() {
                            private_count.push((p.type_id(), p.count()));
                        }

                        let fun_body = FuncDecl::new_plugin(
                            output_counts,
                            input_counts,
                            plugin_name,
                            operation,
                            params,
                            public_count,
                            private_count,
                            &rel.type_store,
                            &rel.fun_store,
                        )
                        .unwrap();

                        let fun_id = rel.fun_store.insert(name.clone(), fun_body).unwrap();
                        let fun_body = rel.fun_store.get_func(fun_id).unwrap();
                        info!(
                            "plugin {:?} fun_id:{} args_size:{:?} body_max:{:?} type_ids:{:?}",
                            name,
                            fun_id,
                            fun_body.compiled_info.args_count,
                            fun_body.compiled_info.body_max,
                            fun_body.compiled_info.type_ids
                        );
                    }
                    g::FunctionBody::Gates => {
                        let u = the_function.body_as_gates().unwrap().gates().unwrap();
                        let n = u.len();
                        for i in 0..n {
                            let gate = flatbuffer_gate_to_gate(u.get(i), &rel.fun_store);
                            gates_body.push(gate);
                        }
                        let fun_body =
                            FuncDecl::new_function(gates_body, output_counts, input_counts);

                        let fun_id = rel.fun_store.insert(name.clone(), fun_body).unwrap();
                        let fun_body = rel.fun_store.get_func(fun_id).unwrap();
                        info!(
                            "function {:?} fun_id:{} args_size:{:?} body_max:{:?} type_ids:{:?} output_ranges:{:?} input_ranges:{:?}",
                            name.clone(),
                            fun_id,
                            fun_body.compiled_info.args_count,
                            fun_body.compiled_info.body_max,
                            fun_body.compiled_info.type_ids,
                            output_count.len(),
                            input_count.len()
                        );
                    }
                    _ => {
                        panic!("Unhandled case")
                    }
                }
            }
            _ => {
                panic!("Unhandled case")
            }
        }
    }
    Some(())
}

/// Read types from relation.
///
/// # Panics
///
/// May panic with io error or flatbuffer error.
pub fn read_types(path: &PathBuf) -> Option<TypeStore> {
    let file = std::fs::File::open(path).unwrap();
    let mut buffer = BufReader::new(file);

    let mut buffer_mem = vec![];

    let msg = read_size_prefix_in_vec(&mut buffer, &mut buffer_mem);
    if msg.is_err() {
        return None;
    }
    if buffer_mem.len() <= SIZE_UOFFSET {
        return None;
    }

    let v = g::size_prefixed_root_as_root(&buffer_mem).unwrap();

    let mut vout = TypeStore::default();

    let types = v.message_as_relation().unwrap().types().unwrap();
    let l = types.len();
    let mut type_id: TypeId = 0;
    for i in 0..l {
        let t = types.get(i);
        let out = t.element_type();
        match out {
            g::TypeU::Field => {
                let field = t
                    .element_as_field()
                    .unwrap()
                    .modulo()
                    .unwrap()
                    .value()
                    .unwrap();
                vout.insert(
                    type_id,
                    TypeSpecification::Field(
                        modulus_to_type_id(bigint_from_bytes(field.bytes())).unwrap(),
                    ),
                );
                type_id += 1;
            }
            g::TypeU::ExtField => {
                panic!("Extension field type not yet supported!");
            }
            g::TypeU::PluginType => {
                let plugin = t.element_as_plugin_type().unwrap();
                let name = plugin.name().unwrap().into();
                let operation = plugin.operation().unwrap().into();

                let params_ = plugin.params().unwrap();
                let n = params_.len();
                let mut params = Vec::with_capacity(n);
                for i in 0..n {
                    let param = params_.get(i);
                    params.push(PluginTypeArg::from_str(param).ok()?);
                }
                let plugin_type = PluginType::new(name, operation, params);
                vout.insert(type_id, TypeSpecification::Plugin(plugin_type));
                type_id += 1;
            }
            _ => {}
        }
    }
    Some(vout)
}
