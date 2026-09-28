use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use rustc_hash::FxHashMap;
use swanky_error::{ErrorKind, OptionExt, ResultExt, WrapErr};
use swanky_sieve_ir_parser::{
    ConversionSemantics, FunctionBodyVisitor, Identifier, Number, PluginBinding, PluginType,
    PluginTypeArg, RelationReader, RelationVisitor, TypeId, TypedWireRange, ValueStreamKind,
    ValueStreamReader, WireId, WireRange as ParserWireRange,
};

use crate::sieve_compiler::{
    Inputs,
    circuit_ir::{CounterInfo, FieldInstruction, FieldInstructions, FunctionId, Type, WireRange},
    supported_fields::{
        CompilerField, CompilerFieldVisitor, FieldGenericCoproduct, FieldIndexedArray, FieldType,
        InvariantType,
    },
};

use super::{
    CircuitChunk, FieldInstructionsTy, FunctionDefinition, Instruction, MapDefinition,
    MuxDefinition, Permissiveness, PublicInputsNeeded, SizeHint, UserDefinedFunctonId,
};

fn circuit_reader_thread<RR: RelationReader, VSR: ValueStreamReader>(
    relation: PathBuf,
    public_inputs: Vec<PathBuf>,
    out: &flume::Sender<swanky_error::Result<CircuitChunk>>,
) -> swanky_error::Result<()> {
    let relation = RR::open(&relation)?;
    let public_inputs = Inputs::<VSR>::open(ValueStreamKind::Public, &public_inputs)?;
    let mut types: Vec<Type> = Vec::new();
    for ty in relation.header().types.iter() {
        match ty {
            swanky_sieve_ir_parser::Type::Field { modulus } => types.push(Type::Field(
                FieldType::from_modulus(modulus).ok_or_swanky_error(
                    ErrorKind::UnsupportedError,
                    format!("Unknown modulus {modulus}"),
                )?,
            )),
            swanky_sieve_ir_parser::Type::ExtField { .. } => {
                swanky_error::bail!(
                    ErrorKind::UnsupportedError,
                    "Extension fields not supported!"
                )
            }
            swanky_sieve_ir_parser::Type::Ring { .. } => {
                swanky_error::bail!(ErrorKind::UnsupportedError, "Rings not supported!")
            }
            swanky_sieve_ir_parser::Type::PluginType(PluginType {
                name,
                operation,
                args: _,
            }) => match name.as_bytes() {
                b"ram_v0" | b"ram_arith_v0" => match operation.as_bytes() {
                    b"ram" => todo!("Check args based on variant, put the type somewhere useful"),
                    _ => swanky_error::bail!(
                        ErrorKind::OtherError,
                        "Plugin {name} has no {operation} type"
                    ),
                },
                _ => swanky_error::bail!(
                    ErrorKind::OtherError,
                    "Plugin {name} doesn't provide any types"
                ),
            },
        }
    }
    let mut v = Visitor {
        sink: GlobalSink {
            types,
            functions: Default::default(),
            public_inputs_reader: public_inputs,
            current_chunk: Default::default(),
            current_chunk_size_hint: 0,
            sender: out.clone(),
        },
    };
    relation.read(&mut v)?;
    v.sink.flush()?;
    Ok(())
}

pub(super) fn read_circuit<
    RR: RelationReader + Send + 'static,
    VSR: ValueStreamReader + Send + 'static,
>(
    relation: &Path,
    public_inputs: &[PathBuf],
) -> flume::Receiver<swanky_error::Result<CircuitChunk>> {
    let relation = relation.to_path_buf();
    let public_inputs = public_inputs.to_vec();
    let (s, r) = flume::bounded(16);
    std::thread::Builder::new()
        .name("Circuit Reader".to_string())
        .spawn(move || {
            if let Err(e) = circuit_reader_thread::<RR, VSR>(relation, public_inputs, &s) {
                let _ = s.send(Err(e));
            }
        })
        .unwrap();
    r
}

enum Def {
    FunctionDefinition(UserDefinedFunctonId, Arc<FunctionDefinition>),
    Mux(Arc<MuxDefinition>),
    Map(Arc<MapDefinition>),
}

type FunctionDefinitions = FxHashMap<Vec<u8>, Def>;

trait InstructionSink {
    fn types(&self) -> &[Type];
    // TODO: this doesn't need to return a result
    fn push(&mut self, instruction: Instruction) -> swanky_error::Result<&mut Instruction>;
    fn last_mut(&mut self) -> Option<&mut Instruction>;
    fn needs_public_input(&mut self, field: FieldType, count: u64) -> swanky_error::Result<()>;
    fn functions(&self) -> &FunctionDefinitions;
    fn add_function(&mut self, defn: FunctionDefinition) -> swanky_error::Result<()>;
    fn add_mux(&mut self, defn: MuxDefinition) -> swanky_error::Result<()>;
    fn add_iter(&mut self, defn: MapDefinition) -> swanky_error::Result<()>;
    fn update_size_hint(&mut self, delta: SizeHint) -> swanky_error::Result<()>;
}

struct Visitor<S: InstructionSink> {
    sink: S,
}
impl<S: InstructionSink> Visitor<S> {
    fn lookup_type(&self, ty: TypeId) -> swanky_error::Result<Type> {
        self.sink
            .types()
            .get(usize::from(ty))
            .copied()
            .ok_or_swanky_error(ErrorKind::OtherError, format!("invalid type id {ty}"))
    }
    fn per_field<CFV>(&mut self, ty: TypeId, v: CFV) -> swanky_error::Result<()>
    where
        for<'a> CFV: CompilerFieldVisitor<
                &'a mut FieldInstructionsTy,
                Output = InvariantType<swanky_error::Result<()>>,
            >,
    {
        match self.lookup_type(ty)? {
            Type::Field(field) => {
                struct V<'a, S, T>(&'a mut S, T);
                impl<'a, S: InstructionSink, T> CompilerFieldVisitor<()> for V<'a, S, T>
                where
                    for<'b> T: CompilerFieldVisitor<
                            &'b mut FieldInstructionsTy,
                            Output = InvariantType<swanky_error::Result<()>>,
                        >,
                {
                    type Output = InvariantType<swanky_error::Result<()>>;
                    fn visit<FE: crate::sieve_compiler::supported_fields::CompilerField>(
                        self,
                        (): (),
                    ) -> swanky_error::Result<()> {
                        let fi = match self.0.last_mut() {
                            Some(Instruction::FieldInstructions(fi))
                                if fi.as_ref().get::<FE>().is_some() =>
                            {
                                fi.as_mut().get::<FE>().unwrap()
                            }
                            _ => {
                                match self.0.push(Instruction::FieldInstructions(
                                    FieldGenericCoproduct::new::<FE>(
                                        FieldInstructions::<FE>::default(),
                                    ),
                                ))? {
                                    Instruction::FieldInstructions(fi) => {
                                        fi.as_mut().get::<FE>().expect(
                                            "we should get back the same instruction we pushed",
                                        )
                                    }
                                    _ => unreachable!(),
                                }
                            }
                        };
                        self.1.visit(fi)
                    }
                }
                field.visit(V(&mut self.sink, v))?;
            }
            Type::Ram { .. } => todo!(),
        }
        Ok(())
    }
}
macro_rules! push_field_insn {
    (
        $ty_id:expr, |<$FE:ident> $self:expr,
        $($k:ident : $ty:ty),*$(,)?| $block:block
    ) => {{
        struct V {
            $($k : $ty),*
        }
        impl<'a> CompilerFieldVisitor<&'a mut FieldInstructionsTy> for V {
            type Output = InvariantType<swanky_error::Result<()>>;
            fn visit<$FE: CompilerField>(self, insn: &'a mut FieldInstructions<$FE>) -> swanky_error::Result<()> {
                $(let $k = self.$k;)*
                let block_out: swanky_error::Result<FieldInstruction<FE>> = $block;
                insn.push(&block_out?);
                Ok(())
            }
        }
        $self.per_field($ty_id, V {$($k),*})
    }};
}
impl<S: InstructionSink> FunctionBodyVisitor for Visitor<S> {
    fn new(&mut self, ty: TypeId, first: WireId, last: WireId) -> swanky_error::Result<()> {
        push_field_insn!(ty, |<FE> self, first: WireId, last: WireId| {
            Ok(FieldInstruction::Alloc { first, last })
        })?;
        self.sink.update_size_hint(0)?;
        Ok(())
    }
    fn delete(&mut self, ty: TypeId, first: WireId, last: WireId) -> swanky_error::Result<()> {
        push_field_insn!(ty, |<FE> self, first: WireId, last: WireId| {
            Ok(FieldInstruction::Free { first, last })
        })?;
        self.sink.update_size_hint(0)?;
        Ok(())
    }
    fn add(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> swanky_error::Result<()> {
        push_field_insn!(ty, |<FE> self, dst: WireId, left: WireId, right: WireId| {
            Ok(FieldInstruction::Add { dst, left, right })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn mul(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> swanky_error::Result<()> {
        push_field_insn!(ty, |<FE> self, dst: WireId, left: WireId, right: WireId| {
            Ok(FieldInstruction::Mul { dst, left, right })
        })?;
        self.sink.update_size_hint(2)?;
        Ok(())
    }
    fn addc(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: &Number,
    ) -> swanky_error::Result<()> {
        let right = *right;
        push_field_insn!(ty, |<FE> self, dst: WireId, left: WireId, right: Number| {
            Ok(FieldInstruction::AddConstant { dst, left, right: FE::parse_sieve_value(&right)? })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn mulc(
        &mut self,
        ty: TypeId,
        dst: WireId,
        left: WireId,
        right: &Number,
    ) -> swanky_error::Result<()> {
        let right = *right;
        push_field_insn!(ty, |<FE> self, dst: WireId, left: WireId, right: Number| {
            Ok(FieldInstruction::MulConstant { dst, left, right: FE::parse_sieve_value(&right)? })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn copy(
        &mut self,
        _ty: TypeId,
        _dst: swanky_sieve_ir_parser::WireRange,
        _src: &[swanky_sieve_ir_parser::WireRange],
    ) -> swanky_error::Result<()> {
        unimplemented!("Full Fat Mac'n'Cheese no longer supported")
    }
    fn constant(&mut self, ty: TypeId, dst: WireId, src: &Number) -> swanky_error::Result<()> {
        let src = *src;
        push_field_insn!(ty, |<FE> self, dst: WireId, src: Number| {
            Ok(FieldInstruction::Constant { dst, src: FE::parse_sieve_value(&src)? })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn public_input(
        &mut self,
        _ty: TypeId,
        _dst: swanky_sieve_ir_parser::WireRange,
    ) -> swanky_error::Result<()> {
        unimplemented!("Full Fat Mac'n'Cheese no longer supported")
    }
    fn private_input(
        &mut self,
        _ty: TypeId,
        _dst: swanky_sieve_ir_parser::WireRange,
    ) -> swanky_error::Result<()> {
        unimplemented!("Full Fat Mac'n'Cheese no longer supported")
    }
    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> swanky_error::Result<()> {
        push_field_insn!(ty, |<FE> self, src: WireId| {
            Ok(FieldInstruction::AssertZero { src })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn convert(
        &mut self,
        _dst: TypedWireRange,
        _src: TypedWireRange,
        _semantics: ConversionSemantics,
    ) -> swanky_error::Result<()> {
        todo!()
    }
    fn call(
        &mut self,
        dst: &[ParserWireRange],
        name: Identifier,
        args: &[ParserWireRange],
    ) -> swanky_error::Result<()> {
        let name_str = || String::from_utf8_lossy(name);
        let def = self.sink.functions().get(name).ok_or_swanky_error(
            ErrorKind::UnsupportedError,
            format!("Unknown function {:?}", name_str()),
        )?;
        fn make_ranges(
            label: &str,
            fn_sizes: &[(Type, u64)],
            ranges: &[ParserWireRange],
        ) -> swanky_error::Result<FieldIndexedArray<Vec<WireRange>>> {
            swanky_error::ensure!(
                ranges.len() == fn_sizes.len(),
                ErrorKind::OtherError,
                "need {} {label} ranges, but only {} were given",
                fn_sizes.len(),
                ranges.len()
            );
            let mut out = FieldIndexedArray::<Vec<WireRange>>::default();
            for (i, ((ty, sz), range)) in fn_sizes.iter().zip(ranges.iter()).enumerate() {
                swanky_error::ensure!(
                    *sz == range.len(),
                    ErrorKind::OtherError,
                    "{label} {i} expects size {sz} but got size {}",
                    range.len()
                );
                match ty {
                    Type::Field(field) => out[*field].push(WireRange {
                        start: range.start,
                        inclusive_end: range.end,
                    }),
                    Type::Ram { .. } => todo!(),
                }
            }
            Ok(out)
        }
        match def {
            Def::FunctionDefinition(id, definition) => {
                let out_ranges = make_ranges("output", &definition.output_sizes, dst)
                    .with_context(|| format!("When calling function {:?}", name_str()))?;
                let in_ranges = make_ranges("input", &definition.input_sizes, args)
                    .with_context(|| format!("When calling function {:?}", name_str()))?;
                let public_input_needs = definition.public_inputs_needed;
                let size_hint = definition.size_hint;
                self.sink.push(Instruction::FunctionCall {
                    function_id: FunctionId::UserDefined(*id),
                    out_ranges,
                    in_ranges,
                    counter_info: None,
                })?;
                for field in FieldType::ALL {
                    self.sink
                        .needs_public_input(*field, public_input_needs[*field])?;
                }
                self.sink.update_size_hint(size_hint + 1)?;
            }
            Def::Mux(definition) => {
                // Unfortunately need a slightly different version of this function than the one above
                fn make_ranges(
                    label: &str,
                    fn_sizes: &[u64],
                    ranges: &[ParserWireRange],
                ) -> swanky_error::Result<Vec<WireRange>> {
                    swanky_error::ensure!(
                        ranges.len() == fn_sizes.len(),
                        ErrorKind::OtherError,
                        "need {} {label} ranges, but only {} were given",
                        fn_sizes.len(),
                        ranges.len()
                    );
                    let mut out = Vec::new();
                    for (i, (sz, range)) in fn_sizes.iter().zip(ranges.iter()).enumerate() {
                        swanky_error::ensure!(
                            *sz == range.len(),
                            ErrorKind::OtherError,
                            "{label} {i} expects size {sz} but got size {}",
                            range.len()
                        );

                        out.push(WireRange {
                            start: range.start,
                            inclusive_end: range.end,
                        });
                    }
                    Ok(out)
                }

                let out_ranges = make_ranges("output", &definition.branch_sizes, dst)
                    .with_context(|| format!("When calling mux {:?}", name_str()))?;

                let input_sizes = vec![definition.cond_count]
                    .into_iter()
                    .chain(
                        std::iter::repeat_n(
                            definition.branch_sizes.iter().copied(),
                            definition.num_branches,
                        )
                        .flatten(),
                    )
                    .collect::<Vec<_>>();
                let in_ranges = make_ranges("input", &input_sizes, args)
                    .with_context(|| format!("When calling mux {:?}", name_str()))?;

                self.sink.push(Instruction::MuxCall {
                    permissiveness: definition.permissiveness,
                    field_type: definition.field_type,
                    out_ranges,
                    in_ranges,
                })?;
                self.sink.update_size_hint(1)?;
            }
            Def::Map(definition) => {
                let enumerated = definition.enumerated;
                let iter_count = definition.iter_count;
                let num_env = definition.num_env;
                let (id, func) = definition.func.clone();

                for i in 0..iter_count {
                    let dst: Vec<ParserWireRange> = dst
                        .iter()
                        .map(|wr| {
                            let window_size = wr.len() / iter_count;
                            ParserWireRange {
                                start: wr.start + i * window_size,
                                end: wr.end - (iter_count - (i + 1)) * window_size,
                            }
                        })
                        .collect();

                    let args: Vec<ParserWireRange> = args
                        .iter()
                        .enumerate()
                        .map(|(j, wr)| {
                            if j < num_env as usize {
                                *wr
                            } else {
                                let window_size = wr.len() / iter_count;
                                ParserWireRange {
                                    start: wr.start + i * window_size,
                                    end: wr.end - (iter_count - (i + 1)) * window_size,
                                }
                            }
                        })
                        .collect();

                    // If this is an enumerated map, we want to ignore the
                    // index wire range intentionally when making the ranges
                    // for the calls we will emit.
                    let in_fn_sizes: Vec<_> = func
                        .input_sizes
                        .iter()
                        .enumerate()
                        .filter(|&(i, _)| !enumerated || i != num_env as usize)
                        .map(|(_, &v)| v)
                        .collect();

                    let out_ranges = make_ranges("output", &func.output_sizes, &dst)
                        .with_context(|| format!("When calling {:?}", name_str()))?;
                    let in_ranges = make_ranges("input", &in_fn_sizes, &args)
                        .with_context(|| format!("When calling {:?}", name_str()))?;
                    let public_input_needs = func.public_inputs_needed;
                    let size_hint = func.size_hint;

                    let counter_info = if enumerated {
                        let (Type::Field(field_type), num_wires) =
                            func.input_sizes[num_env as usize]
                        else {
                            swanky_error::bail!(
                                ErrorKind::OtherError,
                                "iteration index wire range must have field type"
                            )
                        };

                        let num_env_for_field = func.input_sizes[..num_env as usize]
                            .iter()
                            .filter(|&(t, _)| {
                                if let &Type::Field(ft) = t {
                                    ft == field_type
                                } else {
                                    false
                                }
                            })
                            .collect::<Vec<_>>()
                            .len();

                        if field_type != FieldType::F2 {
                            swanky_error::ensure!(
                                num_wires == 1,
                                ErrorKind::OtherError,
                                "only one wire can be used for non-binary counter values"
                            );
                        }

                        Some(CounterInfo {
                            num_env_for_field,
                            field_type,
                            num_wires: num_wires as usize,
                            value: i as usize,
                        })
                    } else {
                        None
                    };

                    self.sink.push(Instruction::FunctionCall {
                        function_id: FunctionId::UserDefined(id),
                        out_ranges,
                        in_ranges,
                        counter_info,
                    })?;
                    for field in FieldType::ALL {
                        self.sink
                            .needs_public_input(*field, public_input_needs[*field])?;
                    }
                    self.sink.update_size_hint(size_hint + 1)?;
                }
            }
        }
        Ok(())
    }
}
impl<S: InstructionSink> RelationVisitor for Visitor<S> {
    type FBV<'a> = Visitor<FunctionBuildingSink<'a>>;

    fn define_function<BodyCb>(
        &mut self,
        name: Identifier,
        outputs: &[swanky_sieve_ir_parser::TypedCount],
        inputs: &[swanky_sieve_ir_parser::TypedCount],
        body: BodyCb,
    ) -> swanky_error::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> swanky_error::Result<()>,
    {
        let name = std::str::from_utf8(name)
            .wrap_err(ErrorKind::SerializationError, "Function name isn't UTF-8")?
            .to_string();
        let sink = FunctionBuildingSink {
            types: self.sink.types(),
            functions: self.sink.functions(),
            instructions: Default::default(),
            public_inputs: Default::default(),
            size_hint: 0,
        };
        let mut v = Visitor { sink };
        body(&mut v)?;
        let sink = v.sink;
        self.sink.add_function(FunctionDefinition {
            name,
            input_sizes: inputs
                .iter()
                .map(|count| Ok((self.lookup_type(count.ty)?, count.count)))
                .collect::<swanky_error::Result<Vec<_>>>()?,
            output_sizes: outputs
                .iter()
                .map(|count| Ok((self.lookup_type(count.ty)?, count.count)))
                .collect::<swanky_error::Result<Vec<_>>>()?,
            body: sink.instructions,
            public_inputs_needed: sink.public_inputs,
            size_hint: sink.size_hint,
        })?;
        Ok(())
    }

    fn define_plugin_function(
        &mut self,
        name: Identifier,
        outputs: &[swanky_sieve_ir_parser::TypedCount],
        inputs: &[swanky_sieve_ir_parser::TypedCount],
        body: swanky_sieve_ir_parser::PluginBinding,
    ) -> swanky_error::Result<()> {
        let PluginBinding {
            plugin_type:
                PluginType {
                    name: plugin_name,
                    operation,
                    args,
                },
            // No currently supported plugin operations use input streams, but
            // we do sanity-checks that they aren't provided
            private_counts,
            public_counts,
        } = body;

        let name = std::str::from_utf8(name)
            .wrap_err(ErrorKind::SerializationError, "Function name isn't UTF-8")?
            .to_string();

        match plugin_name.as_bytes() {
            b"mux_v0" => {
                swanky_error::ensure!(
                    args.is_empty(),
                    ErrorKind::OtherError,
                    "mux plugin binding takes no arguments"
                );

                swanky_error::ensure!(
                    private_counts.is_empty(),
                    ErrorKind::UnsupportedError,
                    "mux does not read private inputs"
                );
                swanky_error::ensure!(
                    public_counts.is_empty(),
                    ErrorKind::UnsupportedError,
                    "mux does not read public inputs"
                );

                let permissiveness = match operation.as_bytes() {
                    b"permissive" => Permissiveness::Permissive,
                    b"strict" => Permissiveness::Strict,
                    _ => swanky_error::bail!(
                        ErrorKind::UnsupportedError,
                        "Invalid permissiveness {operation}"
                    ),
                };

                let cond_tc = inputs.first().ok_or_swanky_error(
                    ErrorKind::UnsupportedError,
                    "mux requires an input wire range for the condition",
                )?;

                // let-else <3
                let (Type::Field(field_type), cond_count) =
                    (self.lookup_type(cond_tc.ty)?, cond_tc.count)
                else {
                    swanky_error::bail!(
                        ErrorKind::UnsupportedError,
                        "mux only operates over field types"
                    )
                };

                if field_type != FieldType::F2 {
                    swanky_error::ensure!(
                        cond_count == 1,
                        ErrorKind::UnsupportedError,
                        "mux requires only one condition wire for non-boolean fields"
                    )
                }

                let branch_inputs = &inputs[1..];
                let num_ranges_per_branch = outputs.len();

                swanky_error::ensure!(
                    branch_inputs.len().is_multiple_of(num_ranges_per_branch),
                    ErrorKind::OtherError,
                    "The number of branch inputs must be a multiple of the number of output wire ranges"
                );

                // TODO: Need clarification if the same type can be defined multiple times; if so,
                // this check is too strict.
                swanky_error::ensure!(
                    outputs
                        .iter()
                        .chain(branch_inputs)
                        .all(|tc| tc.ty == cond_tc.ty),
                    ErrorKind::OtherError,
                    "mux requires all output/input wire types to match the condition"
                );

                for branch_tcs in branch_inputs.chunks_exact(num_ranges_per_branch) {
                    swanky_error::ensure!(
                        outputs
                            .iter()
                            .zip(branch_tcs)
                            .all(|(o, i)| o.count == i.count),
                        ErrorKind::OtherError,
                        "mux requires branch range counts to match output ranges"
                    );
                }

                let num_branches = branch_inputs.len() / num_ranges_per_branch;
                let branch_sizes = outputs.iter().map(|tc| tc.count).collect::<Vec<_>>();

                self.sink.add_mux(MuxDefinition {
                    name,
                    permissiveness,
                    field_type,
                    cond_count,
                    num_branches,
                    branch_sizes,
                })?;
            }
            b"ram_v0" | b"ram_arith_v0" => todo!(),
            b"iter_v0" => {
                let enumerated = match operation.as_bytes() {
                    b"map" => false,
                    b"map_enumerated" => true,
                    _ => swanky_error::bail!(
                        ErrorKind::UnsupportedError,
                        "Invalid iter operation {operation}"
                    ),
                };

                // 3 args: function name, number of closure wire ranges, number of iterations
                swanky_error::ensure!(
                    args.len() == 3,
                    ErrorKind::OtherError,
                    "map and map_enumerated expect exactly 3 arguments"
                );

                swanky_error::ensure!(
                    private_counts.is_empty(),
                    ErrorKind::UnsupportedError,
                    "map and map_enumerated do not read private inputs"
                );
                swanky_error::ensure!(
                    public_counts.is_empty(),
                    ErrorKind::UnsupportedError,
                    "map and map_enumerated do not read public inputs"
                );

                let PluginTypeArg::String(func_name) = args[0].clone() else {
                    swanky_error::bail!(
                        ErrorKind::UnsupportedError,
                        "map and map_enumerated expect a function name as the first plugin-binding argument"
                    )
                };

                // NOTE: We assume the Number arguments fit in u64s for iter
                let num_env = match args[1] {
                    PluginTypeArg::Number(x) => x.as_words()[0],
                    _ => swanky_error::bail!(
                        ErrorKind::UnsupportedError,
                        "map and map_enumerated a number (the number of closure wire ranges) as the second plugin-binding argument"
                    ),
                };

                let iter_count = match args[2] {
                    PluginTypeArg::Number(x) => x.as_words()[0],
                    _ => swanky_error::bail!(
                        ErrorKind::UnsupportedError,
                        "map and map_enumerated expects a number (the number of iterations) as the second plugin-binding argument"
                    ),
                };

                // Check basic input/output compatibility
                let Def::FunctionDefinition(id, func) = self
                    .sink
                    .functions()
                    .get(func_name.as_bytes())
                    .ok_or_swanky_error(
                        ErrorKind::OtherError,
                        "Function to be iterated has not been defined",
                    )?
                else {
                    swanky_error::bail!(
                        ErrorKind::UnsupportedError,
                        "map and map_enumerated only support iterating user-defined functions"
                    )
                };

                swanky_error::ensure!(
                    outputs.len() == func.output_sizes.len(),
                    ErrorKind::OtherError,
                    "the number of iteration outputs must match the number of closure outputs"
                );

                for (plugin_output, (_, func_output_count)) in
                    outputs.iter().zip(func.output_sizes.iter())
                {
                    // TODO: Would be nice to check the types here, too, but
                    // that's expensive / hard since we can't compare `Type`s
                    // directly. We'll let that be taken care of down-stream.
                    // For now, checking counts alone is a nice 'early-exit'
                    // condition to have here.

                    // plugin_output_count should be iter_count * func_output_count
                    swanky_error::ensure!(
                        plugin_output.count == func_output_count * iter_count,
                        ErrorKind::OtherError,
                        "map and map enumerated expect that each output count is #iterations * closure output count"
                    );
                }

                swanky_error::ensure!(
                    inputs.len() + if enumerated { 1 } else { 0 } == func.input_sizes.len(),
                    ErrorKind::OtherError,
                    "the number of iteration inputs must match the number of closure inputs"
                );

                if enumerated {
                    for (plugin_input, (_, func_input_count)) in inputs[..num_env as usize]
                        .iter()
                        .zip(&func.input_sizes[..num_env as usize])
                    {
                        swanky_error::ensure!(
                            plugin_input.count == *func_input_count,
                            ErrorKind::OtherError,
                            "map and map enumerated expect that each environment wire range count is closure input count"
                        );
                    }

                    for (plugin_input, (_, func_input_count)) in inputs[num_env as usize..]
                        .iter()
                        .zip(&func.input_sizes[num_env as usize + 1..])
                    {
                        swanky_error::ensure!(
                            plugin_input.count == func_input_count * iter_count,
                            ErrorKind::OtherError,
                            "map and map enumerated expext that each non-environment input count is #iterations * closure input count"
                        );
                    }
                } else {
                    for (i, (plugin_input, (_, func_input_count))) in
                        inputs.iter().zip(func.input_sizes.iter()).enumerate()
                    {
                        // For the first num_env, the counts should match exactly.
                        // For the rest, counts should be multiples as for outputs.
                        if i < num_env as usize {
                            swanky_error::ensure!(
                                plugin_input.count == *func_input_count,
                                ErrorKind::OtherError,
                                "map and map enumerated expect that each environment wire range count is closure input count"
                            );
                        } else if i == num_env as usize && enumerated {
                            swanky_error::ensure!(
                                plugin_input.count == *func_input_count,
                                ErrorKind::OtherError,
                                "map enumerated expects that the index wire range count is closure input count"
                            )
                        } else {
                            swanky_error::ensure!(
                                plugin_input.count == func_input_count * iter_count,
                                ErrorKind::OtherError,
                                "map and map enumerated expext that each non-environment input count is #iterations * closure input count"
                            );
                        }
                    }
                }

                self.sink.add_iter(MapDefinition {
                    name,
                    func: (*id, func.clone()),
                    num_env,
                    iter_count,
                    enumerated,
                })?;
            }
            _ => swanky_error::bail!(ErrorKind::UnsupportedError, "Unknown plugin {plugin_name}"),
        }

        Ok(())
    }
}
struct FunctionBuildingSink<'a> {
    instructions: Vec<Instruction>,
    public_inputs: PublicInputsNeeded,
    types: &'a [Type],
    functions: &'a FunctionDefinitions,
    size_hint: SizeHint,
}
impl InstructionSink for FunctionBuildingSink<'_> {
    fn push(&mut self, instruction: Instruction) -> swanky_error::Result<&mut Instruction> {
        self.instructions.push(instruction);
        Ok(self.instructions.last_mut().unwrap())
    }

    fn last_mut(&mut self) -> Option<&mut Instruction> {
        self.instructions.last_mut()
    }

    fn needs_public_input(&mut self, field: FieldType, count: u64) -> swanky_error::Result<()> {
        self.public_inputs[field] += count;
        Ok(())
    }

    fn functions(&self) -> &FunctionDefinitions {
        self.functions
    }

    fn add_function(&mut self, _defn: FunctionDefinition) -> swanky_error::Result<()> {
        swanky_error::bail!(ErrorKind::UnsupportedError, "Functions cannot be nested")
    }

    fn add_mux(&mut self, _defn: MuxDefinition) -> swanky_error::Result<()> {
        swanky_error::bail!(ErrorKind::UnsupportedError, "Functions cannot be nested")
    }

    fn add_iter(&mut self, _defn: MapDefinition) -> swanky_error::Result<()> {
        swanky_error::bail!(ErrorKind::UnsupportedError, "Functions cannot be nested")
    }

    fn types(&self) -> &[Type] {
        self.types
    }

    fn update_size_hint(&mut self, delta: SizeHint) -> swanky_error::Result<()> {
        self.size_hint += delta;
        Ok(())
    }
}

struct GlobalSink<VSR: ValueStreamReader> {
    types: Vec<Type>,
    functions: FunctionDefinitions,
    public_inputs_reader: Inputs<VSR>,
    current_chunk: CircuitChunk,
    current_chunk_size_hint: u64,
    sender: flume::Sender<swanky_error::Result<CircuitChunk>>,
}

impl<VSR: ValueStreamReader> GlobalSink<VSR> {
    fn flush(&mut self) -> swanky_error::Result<()> {
        if self
            .sender
            .send(Ok(std::mem::take(&mut self.current_chunk)))
            .is_err()
        {
            swanky_error::bail!(
                ErrorKind::OtherError,
                "circuit chunk recieved closed prematurely"
            );
        }
        self.current_chunk_size_hint = 0;
        Ok(())
    }
}
impl<VSR: ValueStreamReader> InstructionSink for GlobalSink<VSR> {
    fn types(&self) -> &[Type] {
        &self.types
    }

    fn push(&mut self, instruction: Instruction) -> swanky_error::Result<&mut Instruction> {
        self.current_chunk.new_root_instructions.push(instruction);
        Ok(self.current_chunk.new_root_instructions.last_mut().unwrap())
    }

    fn last_mut(&mut self) -> Option<&mut Instruction> {
        self.current_chunk.new_root_instructions.last_mut()
    }

    fn needs_public_input(&mut self, field: FieldType, count: u64) -> swanky_error::Result<()> {
        struct V<'a, VSR: ValueStreamReader>(&'a mut Inputs<VSR>, &'a mut CircuitChunk, usize);
        impl<'a, VSR: ValueStreamReader> CompilerFieldVisitor<()> for V<'a, VSR> {
            type Output = InvariantType<swanky_error::Result<()>>;
            fn visit<FE: CompilerField>(self, (): ()) -> swanky_error::Result<()> {
                self.0
                    .read_into::<FE>(self.2, self.1.public_inputs.as_mut().get::<FE>())
            }
        }
        field.visit(V(
            &mut self.public_inputs_reader,
            &mut self.current_chunk,
            usize::try_from(count)
                .wrap_err(ErrorKind::OtherError, "{count} does not fit in a usize.")?,
        ))
    }

    fn functions(&self) -> &FunctionDefinitions {
        &self.functions
    }

    fn add_function(&mut self, defn: FunctionDefinition) -> swanky_error::Result<()> {
        let defn = Arc::new(defn);
        let id = self
            .functions
            .iter()
            .filter(|(_, d)| matches!(d, Def::FunctionDefinition(_, _)))
            .collect::<Vec<_>>()
            .len();
        let old = self.functions.insert(
            defn.name.as_bytes().to_vec(),
            Def::FunctionDefinition(id, defn.clone()),
        );
        swanky_error::ensure!(
            old.is_none(),
            ErrorKind::OtherError,
            "{:?} has duplicate definitions",
            defn.name
        );
        self.current_chunk.new_functions.push((id, defn));
        Ok(())
    }

    fn add_mux(&mut self, defn: MuxDefinition) -> swanky_error::Result<()> {
        let defn = Arc::new(defn);
        let old = self
            .functions
            .insert(defn.name.as_bytes().to_vec(), Def::Mux(defn.clone()));
        swanky_error::ensure!(
            old.is_none(),
            ErrorKind::OtherError,
            "{:?} has duplicate definitions",
            defn.name
        );
        Ok(())
    }

    fn add_iter(&mut self, defn: MapDefinition) -> swanky_error::Result<()> {
        let defn = Arc::new(defn);
        let old = self
            .functions
            .insert(defn.name.as_bytes().to_vec(), Def::Map(defn.clone()));
        swanky_error::ensure!(
            old.is_none(),
            ErrorKind::OtherError,
            "{:?} has duplicate definitions",
            defn.name
        );
        Ok(())
    }

    fn update_size_hint(&mut self, delta: SizeHint) -> swanky_error::Result<()> {
        const THRESHOLD: SizeHint = 10_000;
        self.current_chunk_size_hint += delta;
        if self.current_chunk_size_hint >= THRESHOLD {
            self.flush()?;
        }
        Ok(())
    }
}
