use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use color_eyre::Help;
use eyre::{Context, ContextCompat};
use mac_n_cheese_sieve_parser::{
    FunctionBodyVisitor, Identifier, Number, PluginBinding, PluginType, RelationReader,
    RelationVisitor, TypeId, TypedWireRange, ValueStreamKind, ValueStreamReader, WireId,
    WireRange as ParserWireRange,
};
use rustc_hash::FxHashMap;

use crate::sieve_compiler::{
    circuit_ir::{FieldInstruction, FieldInstructions, FunctionId, Type, WireRange},
    supported_fields::{
        CompilerField, CompilerFieldVisitor, FieldGenericCoproduct, FieldIndexedArray, FieldType,
        InvariantType,
    },
    Inputs,
};

use super::{
    CircuitChunk, FieldInstructionsTy, FunctionDefinition, Instruction, MuxDefinition,
    Permissiveness, PublicInputsNeeded, SizeHint, UserDefinedFunction, UserDefinedFunctonId,
};

fn circuit_reader_thread<RR: RelationReader, VSR: ValueStreamReader>(
    mut relation: PathBuf,
    public_inputs: Vec<PathBuf>,
    out: &flume::Sender<eyre::Result<CircuitChunk>>,
) -> eyre::Result<()> {
    let relation = RR::open(&relation)?;
    let public_inputs = Inputs::<VSR>::open(ValueStreamKind::Public, &public_inputs)?;
    let mut types: Vec<Type> = Vec::new();
    for ty in relation.header().types.iter() {
        match ty {
            mac_n_cheese_sieve_parser::Type::Field { modulus } => types.push(Type::Field(
                FieldType::from_modulus(modulus)
                    .with_context(|| format!("Unknown modulus {modulus}"))?,
            )),
            mac_n_cheese_sieve_parser::Type::PluginType(PluginType {
                name,
                operation,
                args,
            }) => match name.as_bytes() {
                variant @ (b"ram_v0" | b"ram_arith_v0") => match operation.as_bytes() {
                    b"ram" => todo!("Check args based on variant, put the type somewhere useful"),
                    _ => eyre::bail!("Plugin {name} has no {operation} type"),
                },
                _ => eyre::bail!("Plugin {name} doesn't provide any types"),
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
) -> flume::Receiver<eyre::Result<CircuitChunk>> {
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

type FunctionDefinitions = FxHashMap<Vec<u8>, (UserDefinedFunctonId, UserDefinedFunction)>;

trait InstructionSink {
    fn types(&self) -> &[Type];
    // TODO: this doesn't need to return a result
    fn push(&mut self, instruction: Instruction) -> eyre::Result<&mut Instruction>;
    fn last_mut(&mut self) -> Option<&mut Instruction>;
    fn needs_public_input(&mut self, field: FieldType, count: u64) -> eyre::Result<()>;
    fn functions(&self) -> &FunctionDefinitions;
    fn add_function(&mut self, defn: FunctionDefinition) -> eyre::Result<()>;
    fn add_mux(&mut self, defn: MuxDefinition) -> eyre::Result<()>;
    fn update_size_hint(&mut self, delta: SizeHint) -> eyre::Result<()>;
}

struct Visitor<S: InstructionSink> {
    sink: S,
}
impl<S: InstructionSink> Visitor<S> {
    fn lookup_type(&self, ty: TypeId) -> eyre::Result<Type> {
        usize::try_from(ty)
            .ok()
            .and_then(|ty| self.sink.types().get(ty))
            .copied()
            .with_context(|| format!("invalid type id {ty}"))
    }
    fn per_field<CFV>(&mut self, ty: TypeId, v: CFV) -> eyre::Result<()>
    where
        for<'a> CFV: CompilerFieldVisitor<
            &'a mut FieldInstructionsTy,
            Output = InvariantType<eyre::Result<()>>,
        >,
    {
        match self.lookup_type(ty)? {
            Type::Field(field) => {
                struct V<'a, S, T>(&'a mut S, T);
                impl<'a, S: InstructionSink, T> CompilerFieldVisitor<()> for V<'a, S, T>
                where
                    for<'b> T: CompilerFieldVisitor<
                        &'b mut FieldInstructionsTy,
                        Output = InvariantType<eyre::Result<()>>,
                    >,
                {
                    type Output = InvariantType<eyre::Result<()>>;
                    fn visit<FE: crate::sieve_compiler::supported_fields::CompilerField>(
                        self,
                        (): (),
                    ) -> eyre::Result<()> {
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
            type Output = InvariantType<eyre::Result<()>>;
            fn visit<$FE: CompilerField>(self, insn: &'a mut FieldInstructions<$FE>) -> eyre::Result<()> {
                $(let $k = self.$k;)*
                let block_out: eyre::Result<FieldInstruction<FE>> = $block;
                insn.push(&block_out?);
                Ok(())
            }
        }
        $self.per_field($ty_id, V {$($k),*})
    }};
}
impl<S: InstructionSink> FunctionBodyVisitor for Visitor<S> {
    fn new(&mut self, ty: TypeId, first: WireId, last: WireId) -> eyre::Result<()> {
        push_field_insn!(ty, |<FE> self, first: WireId, last: WireId| {
            Ok(FieldInstruction::Alloc { first, last })
        })?;
        self.sink.update_size_hint(0)?;
        Ok(())
    }
    fn delete(&mut self, ty: TypeId, first: WireId, last: WireId) -> eyre::Result<()> {
        push_field_insn!(ty, |<FE> self, first: WireId, last: WireId| {
            Ok(FieldInstruction::Free { first, last })
        })?;
        self.sink.update_size_hint(0)?;
        Ok(())
    }
    fn add(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()> {
        push_field_insn!(ty, |<FE> self, dst: WireId, left: WireId, right: WireId| {
            Ok(FieldInstruction::Add { dst, left, right })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn mul(&mut self, ty: TypeId, dst: WireId, left: WireId, right: WireId) -> eyre::Result<()> {
        push_field_insn!(ty, |<FE> self, dst: WireId, left: WireId, right: WireId| {
            Ok(FieldInstruction::Mul { dst, left, right })
        })?;
        self.sink.update_size_hint(2)?;
        Ok(())
    }
    fn addc(&mut self, ty: TypeId, dst: WireId, left: WireId, right: &Number) -> eyre::Result<()> {
        let right = *right;
        push_field_insn!(ty, |<FE> self, dst: WireId, left: WireId, right: Number| {
            Ok(FieldInstruction::AddConstant { dst, left, right: FE::parse_sieve_value(&right)? })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn mulc(&mut self, ty: TypeId, dst: WireId, left: WireId, right: &Number) -> eyre::Result<()> {
        let right = *right;
        push_field_insn!(ty, |<FE> self, dst: WireId, left: WireId, right: Number| {
            Ok(FieldInstruction::MulConstant { dst, left, right: FE::parse_sieve_value(&right)? })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn copy(&mut self, ty: TypeId, dst: WireId, src: WireId) -> eyre::Result<()> {
        push_field_insn!(ty, |<FE> self, dst: WireId, src: WireId| {
            Ok(FieldInstruction::Copy { dst, src })
        })?;
        self.sink.update_size_hint(0)?;
        Ok(())
    }
    fn constant(&mut self, ty: TypeId, dst: WireId, src: &Number) -> eyre::Result<()> {
        let src = *src;
        push_field_insn!(ty, |<FE> self, dst: WireId, src: Number| {
            Ok(FieldInstruction::Constant { dst, src: FE::parse_sieve_value(&src)? })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn public_input(&mut self, ty: TypeId, dst: WireId) -> eyre::Result<()> {
        match self.lookup_type(ty)? {
            Type::Field(field) => self.sink.needs_public_input(field, 1)?,
            Type::Ram { .. } => eyre::bail!("No public inputs for RAM types"),
        }
        push_field_insn!(ty, |<FE> self, dst: WireId| {
            Ok(FieldInstruction::GetPublicInput { dst })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn private_input(&mut self, ty: TypeId, dst: WireId) -> eyre::Result<()> {
        push_field_insn!(ty, |<FE> self, dst: WireId| {
            Ok(FieldInstruction::GetWitness { dst })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn assert_zero(&mut self, ty: TypeId, src: WireId) -> eyre::Result<()> {
        push_field_insn!(ty, |<FE> self, src: WireId| {
            Ok(FieldInstruction::AssertZero { src })
        })?;
        self.sink.update_size_hint(1)?;
        Ok(())
    }
    fn convert(&mut self, dst: TypedWireRange, src: TypedWireRange) -> eyre::Result<()> {
        todo!()
    }
    fn call(
        &mut self,
        dst: &[ParserWireRange],
        name: Identifier,
        args: &[ParserWireRange],
    ) -> eyre::Result<()> {
        let name_str = || String::from_utf8_lossy(name);
        let (id, def) = self
            .sink
            .functions()
            .get(name)
            .with_context(|| format!("Unknown function {:?}", name_str()))?;
        fn make_ranges(
            label: &str,
            fn_sizes: &[(Type, u64)],
            ranges: &[ParserWireRange],
        ) -> eyre::Result<FieldIndexedArray<Vec<WireRange>>> {
            eyre::ensure!(
                ranges.len() == fn_sizes.len(),
                "need {} {label} ranges, but only {} were given",
                fn_sizes.len(),
                ranges.len()
            );
            let mut out = FieldIndexedArray::<Vec<WireRange>>::default();
            for (i, ((ty, sz), range)) in fn_sizes.iter().zip(ranges.iter()).enumerate() {
                eyre::ensure!(
                    *sz == range.len(),
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
            UserDefinedFunction::FunctionDefinition(definition) => {
                let out_ranges = make_ranges("output", &definition.output_sizes, dst)
                    .with_note(|| format!("When calling function {:?}", name_str()))?;
                let in_ranges = make_ranges("input", &definition.input_sizes, args)
                    .with_note(|| format!("When calling function {:?}", name_str()))?;
                let public_input_needs = definition.public_inputs_needed;
                let size_hint = definition.size_hint;
                self.sink.push(Instruction::FunctionCall {
                    function_id: FunctionId::UserDefined(*id),
                    out_ranges,
                    in_ranges,
                })?;
                for field in FieldType::ALL {
                    self.sink
                        .needs_public_input(*field, public_input_needs[*field])?;
                }
                self.sink.update_size_hint(size_hint + 1)?;
            }
            UserDefinedFunction::MuxDefinition(definition) => {
                // Unfortunately need a slightly different version of this function than the one above
                fn make_ranges(
                    label: &str,
                    fn_sizes: &[u64],
                    ranges: &[ParserWireRange],
                ) -> eyre::Result<Vec<WireRange>> {
                    eyre::ensure!(
                        ranges.len() == fn_sizes.len(),
                        "need {} {label} ranges, but only {} were given",
                        fn_sizes.len(),
                        ranges.len()
                    );
                    let mut out = Vec::new();
                    for (i, (sz, range)) in fn_sizes.iter().zip(ranges.iter()).enumerate() {
                        eyre::ensure!(
                            *sz == range.len(),
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
                    .with_note(|| format!("When calling mux {:?}", name_str()))?;

                let input_sizes = vec![definition.cond_count]
                    .into_iter()
                    .chain(
                        std::iter::repeat(definition.branch_sizes.iter().copied())
                            .take(definition.num_branches)
                            .flatten(),
                    )
                    .collect::<Vec<_>>();
                let in_ranges = make_ranges("input", &input_sizes, args)
                    .with_note(|| format!("When calling mux {:?}", name_str()))?;

                self.sink.push(Instruction::MuxCall {
                    function_id: FunctionId::UserDefined(*id),
                    field_type: definition.field_type,
                    out_ranges,
                    in_ranges,
                })?;
                // TODO: Not sure if this is the right delta
                self.sink.update_size_hint(1)?;
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
        outputs: &[mac_n_cheese_sieve_parser::TypedCount],
        inputs: &[mac_n_cheese_sieve_parser::TypedCount],
        body: BodyCb,
    ) -> eyre::Result<()>
    where
        for<'a, 'b> BodyCb: FnOnce(&'a mut Self::FBV<'b>) -> eyre::Result<()>,
    {
        let name = std::str::from_utf8(name)
            .context("Function name isn't UTF-8")?
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
                .collect::<eyre::Result<Vec<_>>>()?,
            output_sizes: outputs
                .iter()
                .map(|count| Ok((self.lookup_type(count.ty)?, count.count)))
                .collect::<eyre::Result<Vec<_>>>()?,
            body: sink.instructions,
            public_inputs_needed: sink.public_inputs,
            size_hint: sink.size_hint,
        })?;
        Ok(())
    }

    fn define_plugin_function(
        &mut self,
        name: Identifier,
        outputs: &[mac_n_cheese_sieve_parser::TypedCount],
        inputs: &[mac_n_cheese_sieve_parser::TypedCount],
        body: mac_n_cheese_sieve_parser::PluginBinding,
    ) -> eyre::Result<()> {
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
            .context("Function name isn't UTF-8")?
            .to_string();

        match plugin_name.as_bytes() {
            b"mux_v0" => {
                // TODO: Should these maybe be debug_assert instead? Not sure
                // we should assume the plugin use is spec-compliant (or if the
                // spec is even complete enough to rely on...)
                eyre::ensure!(args.is_empty(), "mux plugin binding takes no arguments");

                eyre::ensure!(
                    private_counts.is_empty(),
                    "mux does not read private inputs"
                );
                eyre::ensure!(public_counts.is_empty(), "mux does not read public inputs");

                let permissiveness = match operation.as_bytes() {
                    b"permissive" => Permissiveness::Permissive,
                    b"strict" => Permissiveness::Strict,
                    _ => eyre::bail!("Invalid permissiveness {operation}"),
                };

                let cond_tc = inputs
                    .get(0)
                    .context("mux requires an input wire range for the condition")?;

                // let-else <3
                let (Type::Field(field_type), cond_count) = (self.lookup_type(cond_tc.ty)?, cond_tc.count) else {
                    eyre::bail!("mux only operates over field types")
                };

                if field_type != FieldType::F2 {
                    eyre::ensure!(
                        cond_count == 1,
                        "mux requires only one condition wire for non-boolean fields"
                    )
                }

                let branch_inputs = &inputs[1..];
                let num_ranges_per_branch = outputs.len();

                eyre::ensure!(
                    branch_inputs.len() % num_ranges_per_branch == 0,
                    "The number of branch inputs must be a multiple of the number of output wire ranges"
                );

                // TODO: Need clarification if the same type can be defined multiple times; if so,
                // this check is too strict.
                eyre::ensure!(
                    outputs
                        .iter()
                        .chain(branch_inputs)
                        .all(|tc| tc.ty == cond_tc.ty),
                    "mux requires all output/input wire types to match the condition"
                );

                for branch_tcs in inputs.chunks_exact(num_ranges_per_branch) {
                    eyre::ensure!(
                        outputs
                            .iter()
                            .zip(branch_tcs)
                            .all(|(o, i)| o.count == i.count),
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
            b"iter_v0" => todo!(),
            _ => eyre::bail!("Unknown plugin {plugin_name}"),
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
    fn push(&mut self, instruction: Instruction) -> eyre::Result<&mut Instruction> {
        self.instructions.push(instruction);
        Ok(self.instructions.last_mut().unwrap())
    }

    fn last_mut(&mut self) -> Option<&mut Instruction> {
        self.instructions.last_mut()
    }

    fn needs_public_input(&mut self, field: FieldType, count: u64) -> eyre::Result<()> {
        self.public_inputs[field] += count;
        Ok(())
    }

    fn functions(&self) -> &FunctionDefinitions {
        self.functions
    }

    fn add_function(&mut self, _defn: FunctionDefinition) -> eyre::Result<()> {
        eyre::bail!("Functions cannot be nested")
    }

    fn add_mux(&mut self, _defn: MuxDefinition) -> eyre::Result<()> {
        eyre::bail!("Functions cannot be nested")
    }

    fn types(&self) -> &[Type] {
        self.types
    }

    fn update_size_hint(&mut self, delta: SizeHint) -> eyre::Result<()> {
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
    sender: flume::Sender<eyre::Result<CircuitChunk>>,
}

impl<VSR: ValueStreamReader> GlobalSink<VSR> {
    fn flush(&mut self) -> eyre::Result<()> {
        if let Err(_) = self
            .sender
            .send(Ok(std::mem::take(&mut self.current_chunk)))
        {
            eyre::bail!("circuit chunk recieved closed prematurely");
        }
        self.current_chunk_size_hint = 0;
        Ok(())
    }
}
impl<VSR: ValueStreamReader> InstructionSink for GlobalSink<VSR> {
    fn types(&self) -> &[Type] {
        &self.types
    }

    fn push(&mut self, instruction: Instruction) -> eyre::Result<&mut Instruction> {
        self.current_chunk.new_root_instructions.push(instruction);
        Ok(self.current_chunk.new_root_instructions.last_mut().unwrap())
    }

    fn last_mut(&mut self) -> Option<&mut Instruction> {
        self.current_chunk.new_root_instructions.last_mut()
    }

    fn needs_public_input(&mut self, field: FieldType, count: u64) -> eyre::Result<()> {
        struct V<'a, VSR: ValueStreamReader>(&'a mut Inputs<VSR>, &'a mut CircuitChunk, usize);
        impl<'a, VSR: ValueStreamReader> CompilerFieldVisitor<()> for V<'a, VSR> {
            type Output = InvariantType<eyre::Result<()>>;
            fn visit<FE: CompilerField>(self, (): ()) -> eyre::Result<()> {
                self.0
                    .read_into::<FE>(self.2, self.1.public_inputs.as_mut().get::<FE>())
            }
        }
        field.visit(V(
            &mut self.public_inputs_reader,
            &mut self.current_chunk,
            usize::try_from(count)?,
        ))
    }

    fn functions(&self) -> &FunctionDefinitions {
        &self.functions
    }

    fn add_function(&mut self, defn: FunctionDefinition) -> eyre::Result<()> {
        let defn = Arc::new(defn);
        let id = self.functions.len();
        let old = self.functions.insert(
            defn.name.as_bytes().to_vec(),
            (id, UserDefinedFunction::FunctionDefinition(defn.clone())),
        );
        eyre::ensure!(old.is_none(), "{:?} has duplicate definitions", defn.name);
        self.current_chunk
            .new_functions
            .push((id, UserDefinedFunction::FunctionDefinition(defn)));
        Ok(())
    }

    fn add_mux(&mut self, defn: MuxDefinition) -> eyre::Result<()> {
        let defn = Arc::new(defn);
        let id = self.functions.len();
        let old = self.functions.insert(
            defn.name.as_bytes().to_vec(),
            (id, UserDefinedFunction::MuxDefinition(defn.clone())),
        );
        eyre::ensure!(old.is_none(), "{:?} has duplicate definitions", defn.name);
        self.current_chunk
            .new_functions
            .push((id, UserDefinedFunction::MuxDefinition(defn)));
        Ok(())
    }

    fn update_size_hint(&mut self, delta: SizeHint) -> eyre::Result<()> {
        const THRESHOLD: SizeHint = 10_000;
        self.current_chunk_size_hint += delta;
        if self.current_chunk_size_hint >= THRESHOLD {
            self.flush()?;
        }
        Ok(())
    }
}
