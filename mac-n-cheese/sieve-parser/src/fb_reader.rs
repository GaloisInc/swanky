use std::{
    fs::File,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use crypto_bigint::ArrayEncoding;
use eyre::{Context, ContextCompat};

#[path = "sieve_ir_generated.rs"]
mod sieve_ir_generated;
use generic_array::GenericArray;
use sieve_ir_generated::sieve_ir as fb;

use crate::{
    ConversionDescription, FunctionBodyVisitor, Header, Number, PluginBinding, PluginType,
    PluginTypeArg, RelationVisitor, Type, TypedCount, TypedWireRange, ValueStreamKind, WireRange,
};

fn walk_inputs(paths: &[PathBuf]) -> eyre::Result<Vec<PathBuf>> {
    fn visit(dst: &mut Vec<PathBuf>, input: &Path) -> eyre::Result<()> {
        if let Some(name) = input.file_name() {
            if name.to_string_lossy().starts_with('.') {
                // Ignore hidden files
                return Ok(());
            }
        }
        if input.is_dir() {
            for item in std::fs::read_dir(input)
                .with_context(|| format!("Unable to open directory {input:?}"))?
            {
                let item = item?;
                visit(dst, &item.path())?;
            }
        } else {
            dst.push(input.to_path_buf());
        }
        Ok(())
    }
    let mut out = Vec::new();
    for path in paths {
        visit(&mut out, path)?;
    }
    out.sort();
    Ok(out)
}

struct MessageReader {
    paths: Vec<PathBuf>,
    current_file: Option<File>,
    // TODO: we might want to consider an alternative allocator for this.
    buf: Vec<u8>,
}
impl MessageReader {
    fn new(mut paths: Vec<PathBuf>) -> Self {
        paths.reverse();
        MessageReader {
            paths,
            buf: Vec::new(),
            current_file: None,
        }
    }
    fn next_root(&mut self) -> eyre::Result<Option<fb::Root>> {
        while !self.paths.is_empty() || self.current_file.is_some() {
            if let Some(file) = self.current_file.as_mut() {
                let pos = file.stream_position()?;
                // This isn't the most efficient way to check this, but it's easy!
                // This gets called infrequently enough that we don't care.
                if pos == file.seek(std::io::SeekFrom::End(0))? {
                    self.current_file = None;
                    continue;
                }
                file.seek(std::io::SeekFrom::Start(pos))?;
                let (len, len_buf) = {
                    let mut len_buf = [0; 4];
                    file.read_exact(&mut len_buf)
                        .context("Reading flatbuffer length")?;
                    (u32::from_le_bytes(len_buf) as usize, len_buf)
                };
                self.buf.resize(len + 4, 0);
                self.buf[..4].copy_from_slice(&len_buf);
                file.read_exact(&mut self.buf[4..])
                    .context("Reading flatbuffer root message")?;
                return Ok(Some(
                    fb::size_prefixed_root_as_root_with_opts(
                        &flatbuffers::VerifierOptions {
                            max_tables: u32::MAX as usize,
                            ..flatbuffers::VerifierOptions::default()
                        },
                        &self.buf,
                    )
                    .context("failed to verify flatbuffer root buffer")?,
                ));
            } else {
                // If current_file is None, then paths can't be empty, by the above condition.
                let path = self.paths.pop().unwrap();
                self.current_file =
                    Some(File::open(&path).with_context(|| format!("Opening file {path:?}"))?);
            }
        }
        Ok(None)
    }
    fn next_relation(&mut self) -> eyre::Result<Option<fb::Relation>> {
        if let Some(root) = self.next_root()? {
            Ok(Some(root.message_as_relation().with_context(|| {
                format!("wanted relation, got {:?}", root.message_type())
            })?))
        } else {
            Ok(None)
        }
    }
    fn next_inputs(
        &mut self,
    ) -> eyre::Result<
        Option<(
            ValueStreamKind,
            Option<fb::Type>,
            Option<flatbuffers::Vector<flatbuffers::ForwardsUOffset<fb::Value>>>,
        )>,
    > {
        if let Some(root) = self.next_root()? {
            if let Some(values) = root.message_as_public_inputs() {
                Ok(Some((
                    ValueStreamKind::Public,
                    values.type_(),
                    values.inputs(),
                )))
            } else if let Some(values) = root.message_as_private_inputs() {
                Ok(Some((
                    ValueStreamKind::Private,
                    values.type_(),
                    values.inputs(),
                )))
            } else {
                eyre::bail!(
                    "Expected public or private inputs, got {:?}",
                    root.message_type()
                );
            }
        } else {
            Ok(None)
        }
    }
}

pub struct RelationReader {
    reader: MessageReader,
    header: Header,
}

fn bytes2number(bytes: &[u8]) -> eyre::Result<Number> {
    let mut buf = GenericArray::<u8, <Number as ArrayEncoding>::ByteSize>::default();
    let to_take = buf.len().min(bytes.len());
    buf[..to_take].copy_from_slice(&bytes[..to_take]);
    eyre::ensure!(
        bytes[to_take..].iter().all(|&x| x == 0),
        "number too big (non-zero trailing bytes)"
    );
    Ok(Number::from_le_byte_array(buf))
}

impl RelationReader {
    fn handle_gate(
        gate: fb::Gate,
        v: &mut impl FunctionBodyVisitor,
        func_out_buf: &mut Vec<WireRange>,
        func_in_buf: &mut Vec<WireRange>,
    ) -> eyre::Result<()> {
        if let Some(c) = gate.gate_as_gate_constant() {
            v.constant(
                c.type_id().into(),
                c.out_id(),
                &bytes2number(c.constant().map(|x| x.bytes()).unwrap_or_default())?,
            )?;
        } else if let Some(x) = gate.gate_as_gate_assert_zero() {
            v.assert_zero(x.type_id().into(), x.in_id())?;
        } else if let Some(x) = gate.gate_as_gate_copy() {
            v.copy(x.type_id().into(), x.out_id(), x.in_id())?;
        } else if let Some(x) = gate.gate_as_gate_add() {
            v.add(x.type_id().into(), x.out_id(), x.left_id(), x.right_id())?;
        } else if let Some(x) = gate.gate_as_gate_mul() {
            v.mul(x.type_id().into(), x.out_id(), x.left_id(), x.right_id())?;
        } else if let Some(x) = gate.gate_as_gate_add_constant() {
            v.addc(
                x.type_id().into(),
                x.out_id(),
                x.in_id(),
                &bytes2number(x.constant().map(|x| x.bytes()).unwrap_or_default())?,
            )?;
        } else if let Some(x) = gate.gate_as_gate_mul_constant() {
            v.mulc(
                x.type_id().into(),
                x.out_id(),
                x.in_id(),
                &bytes2number(x.constant().map(|x| x.bytes()).unwrap_or_default())?,
            )?;
        } else if let Some(x) = gate.gate_as_gate_public() {
            v.public_input(x.type_id().into(), x.out_id())?;
        } else if let Some(x) = gate.gate_as_gate_private() {
            v.private_input(x.type_id().into(), x.out_id())?;
        } else if let Some(x) = gate.gate_as_gate_new() {
            v.new(x.type_id().into(), x.first_id(), x.last_id())?;
        } else if let Some(x) = gate.gate_as_gate_delete() {
            v.delete(x.type_id().into(), x.first_id(), x.last_id())?;
        } else if let Some(x) = gate.gate_as_gate_convert() {
            v.convert(
                TypedWireRange {
                    ty: x.out_type_id().into(),
                    range: WireRange {
                        start: x.out_first_id(),
                        end: x.out_last_id(),
                    },
                },
                TypedWireRange {
                    ty: x.in_type_id().into(),
                    range: WireRange {
                        start: x.in_first_id(),
                        end: x.in_last_id(),
                    },
                },
            )?;
        } else if let Some(x) = gate.gate_as_gate_call() {
            func_out_buf.clear();
            func_in_buf.clear();
            for input in x.in_ids().into_iter().flat_map(|x| x.iter()) {
                func_in_buf.push(WireRange {
                    start: input.first_id(),
                    end: input.last_id(),
                });
            }
            for output in x.out_ids().into_iter().flat_map(|x| x.iter()) {
                func_out_buf.push(WireRange {
                    start: output.first_id(),
                    end: output.last_id(),
                });
            }
            v.call(
                func_out_buf,
                x.name()
                    .context("function calls need the name of the funciton to call")?
                    .as_bytes(),
                func_in_buf,
            )?;
        } else {
            eyre::bail!("Unknown gate type {:?}", gate.gate_type());
        }
        Ok(())
    }
}
impl super::RelationReader for RelationReader {
    fn open(path: &Path) -> eyre::Result<Self> {
        let paths = walk_inputs(&[path.to_path_buf()])?;
        let mut initial_reader = MessageReader::new(paths.clone());
        let relation = initial_reader
            .next_relation()?
            .context("There needs to be at least one relation")?;
        let mut header = Header {
            plugins: Vec::new(),
            types: Vec::new(),
            conversion: Vec::new(),
        };
        eyre::ensure!(
            relation.version() == Some("2.0.0"),
            "Unknown sieve ir version {:?}",
            relation.version()
        );
        for plugin in relation.plugins().into_iter().flat_map(|x| x.iter()) {
            header.plugins.push(String::from(plugin))
        }
        for ty in relation.types().into_iter().flat_map(|x| x.iter()) {
            if let Some(field) = ty.element_as_field() {
                header.types.push(Type::Field {
                    modulus: bytes2number(
                        field
                            .modulo()
                            .context("field type needs modulus")?
                            .value()
                            .context("field type needs modulus")?
                            .bytes(),
                    )?,
                })
            } else if let Some(plugin) = ty.element_as_plugin_type() {
                let mut args_buf = Vec::new();
                args_buf.extend(
                    plugin
                        .params()
                        .into_iter()
                        .flat_map(|x| x.iter())
                        .map(PluginTypeArg::from_str)
                        .collect::<Result<Vec<_>, _>>()?,
                );
                header.types.push(Type::PluginType(PluginType {
                    name: String::from(plugin.name().context("plugin type needs plugin name")?),
                    operation: String::from(
                        plugin
                            .operation()
                            .context("plugin type needs plugin operation")?,
                    ),
                    args: args_buf,
                }))
            } else {
                eyre::bail!("unknown type {:?}", ty.element_type());
            }
        }
        for conv in relation.conversions().into_iter().flat_map(|x| x.iter()) {
            header.conversion.push(ConversionDescription {
                output: TypedCount {
                    ty: conv.output_count().type_id().into(),
                    count: conv.output_count().count(),
                },
                input: TypedCount {
                    ty: conv.input_count().type_id().into(),
                    count: conv.input_count().count(),
                },
            });
        }
        Ok(Self {
            reader: MessageReader::new(paths),
            header,
        })
    }

    fn read(mut self, rv: &mut impl RelationVisitor) -> eyre::Result<()> {
        let mut output_buf = Vec::new();
        let mut input_buf = Vec::new();
        let mut func_out_buf = Vec::new();
        let mut func_in_buf = Vec::new();
        let mut i = 0;
        while let Some(relation) = self.reader.next_relation()? {
            for directive in relation.directives().into_iter().flat_map(|x| x.iter()) {
                if let Some(gate) = directive.directive_as_gate() {
                    Self::handle_gate(gate, rv, &mut func_out_buf, &mut func_in_buf)?;
                } else if let Some(function) = directive.directive_as_function() {
                    output_buf.clear();
                    input_buf.clear();
                    output_buf.extend(
                        function
                            .output_count()
                            .into_iter()
                            .flat_map(|x| x.iter())
                            .map(|count| TypedCount {
                                ty: count.type_id().into(),
                                count: count.count(),
                            }),
                    );
                    input_buf.extend(
                        function
                            .input_count()
                            .into_iter()
                            .flat_map(|x| x.iter())
                            .map(|count| TypedCount {
                                ty: count.type_id().into(),
                                count: count.count(),
                            }),
                    );
                    if let Some(gates) = function.body_as_gates() {
                        rv.define_function(
                            function.name().context("functions need names")?.as_bytes(),
                            &output_buf,
                            &input_buf,
                            |v| {
                                for gate in gates.gates().into_iter().flat_map(|x| x.iter()) {
                                    Self::handle_gate(
                                        gate,
                                        v,
                                        &mut func_out_buf,
                                        &mut func_in_buf,
                                    )?;
                                }
                                Ok(())
                            },
                        )?;
                    } else if let Some(plugin) = function.body_as_plugin_body() {
                        let mut args_buf = Vec::new();
                        let mut private_buf = Vec::new();
                        let mut public_buf = Vec::new();

                        args_buf.extend(
                            plugin
                                .params()
                                .into_iter()
                                .flat_map(|x| x.iter())
                                .map(PluginTypeArg::from_str)
                                .collect::<Result<Vec<_>, _>>()?,
                        );

                        private_buf.extend(
                            plugin
                                .private_count()
                                .into_iter()
                                .flat_map(|x| x.iter())
                                .map(|count| TypedCount {
                                    ty: count.type_id().into(),
                                    count: count.count(),
                                }),
                        );

                        public_buf.extend(
                            plugin
                                .public_count()
                                .into_iter()
                                .flat_map(|x| x.iter())
                                .map(|count| TypedCount {
                                    ty: count.type_id().into(),
                                    count: count.count(),
                                }),
                        );

                        rv.define_plugin_function(
                            function.name().context("functions need names")?.as_bytes(),
                            &output_buf,
                            &input_buf,
                            PluginBinding {
                                plugin_type: PluginType {
                                    name: String::from(
                                        plugin
                                            .name()
                                            .context("plugin binding needs plugin name")?,
                                    ),
                                    operation: String::from(
                                        plugin
                                            .operation()
                                            .context("plugin binding needs plugin operation")?,
                                    ),
                                    args: args_buf,
                                },
                                private_counts: private_buf,
                                public_counts: public_buf,
                            },
                        )?;
                    } else {
                        eyre::bail!("unknown function body type {:?}", function.body_type());
                    }
                } else {
                    eyre::bail!("unknown directive type {:?}", directive.directive_type());
                }
            }
            i += 1;
            eprintln!("Finished relation message {i}");
        }
        Ok(())
    }
    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct ValueStreamReader {
    modulus: Number,
    buf: Vec<Number>,
    pos: usize,
    recv: flume::Receiver<eyre::Result<Vec<Number>>>,
}

impl super::ValueStreamReader for ValueStreamReader {
    fn open(kind: ValueStreamKind, path: &Path) -> eyre::Result<Self> {
        let inputs = walk_inputs(&[path.to_path_buf()])?;
        let modulus = {
            let mut reader = MessageReader::new(inputs.clone());
            let (saw_kind, ty, _) = reader.next_inputs()?.context("some inputs are needed")?;
            let ty = ty.context("type is not optional")?;
            let modulus = if let Some(ty) = ty.element_as_field() {
                bytes2number(
                    ty.modulo()
                        .context("field modulus is required")?
                        .value()
                        .context("field modulus is required")?
                        .bytes(),
                )?
            } else {
                eyre::bail!("Expected field, saw {:?}", ty);
            };
            eyre::ensure!(saw_kind == kind, "Expected {kind:?}. Saw {saw_kind:?}");
            modulus
        };
        let (s, r) = flume::bounded(64);
        std::thread::Builder::new()
            .name("ValueStreamReader".to_string())
            .spawn(move || {
                let mut reader = MessageReader::new(inputs);
                if let Err(e) = (|| -> eyre::Result<()> {
                    loop {
                        if let Some((_, _, values)) = reader.next_inputs()? {
                            const CHUNK_SIZE: usize = 8192;
                            let mut chunk = Vec::with_capacity(CHUNK_SIZE);
                            for value in values.into_iter().flat_map(|x| x.iter()) {
                                let value = bytes2number(
                                    value.value().context("values must have values")?.bytes(),
                                )?;
                                chunk.push(value);
                                if chunk.len() >= CHUNK_SIZE {
                                    if s.send(Ok(chunk)).is_err() {
                                        return Ok(());
                                    }
                                    chunk = Vec::with_capacity(CHUNK_SIZE);
                                }
                            }
                            if !chunk.is_empty() && s.send(Ok(chunk)).is_err() {
                                return Ok(());
                            }
                        } else {
                            return Ok(());
                        }
                    }
                })() {
                    let _ = s.send(Err(e));
                }
            })
            .unwrap();
        Ok(Self {
            modulus,
            buf: Vec::new(),
            recv: r,
            pos: 0,
        })
    }
    fn modulus(&self) -> &Number {
        &self.modulus
    }
    fn next(&mut self) -> eyre::Result<Option<Number>> {
        loop {
            if self.pos >= self.buf.len() {
                match self.recv.recv() {
                    Ok(buf) => {
                        self.pos = 0;
                        self.buf = buf?;
                    }
                    Err(_) => return Ok(None),
                }
            } else {
                let out = self.buf[self.pos];
                self.pos += 1;
                return Ok(Some(out));
            }
        }
    }
}
