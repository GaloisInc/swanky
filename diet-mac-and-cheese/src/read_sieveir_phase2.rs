/*!
SIEVE IR0+ flatbuffer reader.
*/
use crate::sieveir_phase2::sieve_ir_generated::sieve_ir::GateSet as gs;
use crate::sieveir_phase2::sieve_ir_generated::sieve_ir::{self as g};
use crate::{
    circuit_ir::{FunStore, FuncDecl, GateM, TypeSpecification, TypeStore},
    plugins::PluginType,
};
use crate::{
    fields::modulus_to_type_id, sieveir_phase2::sieve_ir_generated::sieve_ir::DirectiveSet as ds,
};
use eyre::{eyre, Result};
use flatbuffers::{read_scalar_at, UOffsetT, SIZE_UOFFSET};
use log::info;
use mac_n_cheese_sieve_parser::{Number, PluginTypeArg};
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

// Read from a stream a size prefix and stores the content in a vector provided as an argument.
// it returns an `Option<()>` with `Some(())` indicating there is more to read
// and `None` it has reached the end.
//
// This function is adapted from `read_buffer` from zkinterface.
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
pub fn read_public_inputs_bytes(bytes: &[u8], instances: &mut VecDeque<Number>) -> Number {
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
pub fn read_private_inputs_bytes(bytes: &[u8], witnesses: &mut VecDeque<Number>) -> Number {
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

/// A Buffered Relation, analogous to `BufReader`.
pub struct BufRelation {
    pub type_store: TypeStore,
    pub fun_store: FunStore,
    pub gates: Vec<GateM>,
    buffer_file: BufReader<File>,
    buffer_bytes: Vec<u8>,
}

impl BufRelation {
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

    pub fn next(&mut self) -> Option<()> {
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

fn flatbuffer_gate_to_gate(the_gate: g::Gate) -> GateM {
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
            GateM::Copy(u.type_id(), u.out_id(), u.in_id())
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
            GateM::Instance(u.type_id(), u.out_id())
        }
        gs::GatePrivate => {
            let u = the_gate.gate_as_gate_private().unwrap();
            GateM::Witness(u.type_id(), u.out_id())
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

            GateM::Call(Box::new((u.name().unwrap().into(), outids, inids)))
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
pub fn read_relation_and_functions_bytes_accu(rel: &mut BufRelation) -> Option<()> {
    // Checked version
    let v = g::size_prefixed_root_as_root_with_opts(
        &flatbuffers::VerifierOptions {
            max_tables: u32::MAX as usize,
            ..flatbuffers::VerifierOptions::default()
        },
        rel.buffer_bytes.as_slice(),
    )
    .unwrap()
    .message_as_relation()
    .unwrap();

    /* // Unchecked
    let v = unsafe {
        g::size_prefixed_root_as_root_unchecked(rel.buffer_bytes.as_slice())
            .message_as_relation()
            .unwrap()
    };
    */

    let v1 = v.directives().unwrap();
    let n = v1.len();

    for i in 0..n {
        let directive_read = v1.get(i);
        let t = directive_read.directive_type();

        match t {
            ds::Gate => {
                let gate = flatbuffer_gate_to_gate(directive_read.directive_as_gate().unwrap());
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
                        let operation = x.operation().unwrap_or_else(|| "missing_op").into();
                        let params_flatc = x.params();
                        let params = if params_flatc.is_none() {
                            vec![]
                        } else {
                            let m = params_flatc.unwrap().len();
                            let mut params_v = vec![];
                            for j in 0..m {
                                params_v.push(
                                    PluginTypeArg::from_str(params_flatc.unwrap().get(j)).ok()?,
                                );
                            }
                            params_v
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
                        info!(
                            "plugin {:?} args_size:{:?} body_max:{:?} type_ids:{:?}",
                            name.clone(),
                            fun_body.compiled_info.args_count,
                            fun_body.compiled_info.body_max,
                            fun_body.compiled_info.type_ids
                        );
                        rel.fun_store.insert(name, fun_body);
                    }
                    g::FunctionBody::Gates => {
                        let u = the_function.body_as_gates().unwrap().gates().unwrap();
                        let n = u.len();
                        for i in 0..n {
                            let gate = flatbuffer_gate_to_gate(u.get(i));
                            gates_body.push(gate);
                        }
                        let fun_body =
                            FuncDecl::new_function(gates_body, output_counts, input_counts);
                        info!(
                            "function {:?} args_size:{:?} body_max:{:?} type_ids:{:?} output_ranges:{:?} input_ranges:{:?}",
                            name.clone(),
                            fun_body.compiled_info.args_count,
                            fun_body.compiled_info.body_max,
                            fun_body.compiled_info.type_ids,
                            output_count.len(),
                            input_count.len()
                        );
                        rel.fun_store.insert(name, fun_body);
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
    let mut field_id = 0;
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
                    field_id,
                    TypeSpecification::Field(
                        modulus_to_type_id(bigint_from_bytes(field.bytes())).unwrap(),
                    ),
                );
                field_id += 1;
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
                vout.insert(field_id, TypeSpecification::Plugin(plugin_type));
                field_id += 1;
            }
            _ => {}
        }
    }
    Some(vout)
}
