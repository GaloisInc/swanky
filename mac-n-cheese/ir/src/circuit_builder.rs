use eyre::WrapErr;
use flatbuffers::FlatBufferBuilder;
use rustc_hash::{FxHashMap, FxHashSet};
use scuttlebutt::field::FiniteField;
use scuttlebutt::serialization::SequenceSerializer;
use smallvec::SmallVec;
use std::any::TypeId;
use std::fs::File;
use std::io::{BufWriter, Seek, Write};

use std::ops::RangeBounds;
use std::path::Path;

use crate::{compilation_format::*, MAC_N_CHEESE_VERSION};

#[derive(Debug, Clone, Copy)]
pub struct Shape {
    ty_encoded: NumericalEnumType,
    count: u32,
}
impl Shape {
    fn new(ty: Type, count: u32) -> Self {
        Self {
            ty_encoded: ty.into(),
            count,
        }
    }
    pub fn ty(&self) -> Type {
        Type::try_from(self.ty_encoded).expect("the type in the shape is valid")
    }
    pub fn count(&self) -> u32 {
        self.count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CircuitBuilderId(u16);
impl CircuitBuilderId {
    fn random() -> Self {
        Self(rand::random())
    }
}

#[derive(Debug, Clone)]
pub struct TaskPrototypeRef {
    circuit_builder_id: CircuitBuilderId,
    prototype_id: TaskPrototypeId,
    // TODO: make this a bumpalo-allocated slice?
    single_array_inputs: SmallVec<[Shape; 4]>,
    multi_array_inputs: SmallVec<[Shape; 1]>,
    outputs: SmallVec<[Shape; 1]>,
    num_rounds_communication: u16,
    prototype_kind_encoded: NumericalEnumType,
}
impl TaskPrototypeRef {
    pub fn single_array_inputs(&self) -> &[Shape] {
        &self.single_array_inputs
    }
    pub fn multi_array_inputs(&self) -> &[Shape] {
        &self.multi_array_inputs
    }
    pub fn outputs(&self) -> &[Shape] {
        &self.outputs
    }
    pub fn prototype_kind(&self) -> TaskKind {
        self.prototype_kind_encoded.try_into().unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct TaskOutputRef {
    circuit_builder_id: CircuitBuilderId,
    task_id: TaskId,
    prototype_kind_encoded: NumericalEnumType,
    outputs: SmallVec<[Shape; 1]>,
}
impl TaskOutputRef {
    // panics if ty isn't outputted
    pub fn outputs(&self, ty: Type) -> WireSlice {
        let ty_encoded: NumericalEnumType = ty.into();
        WireSlice {
            circuit_builder_id: self.circuit_builder_id,
            source: self.task_id,
            range_start: 0,
            range_end: match self
                .outputs
                .iter()
                .find(|shape| shape.ty_encoded == ty_encoded)
            {
                Some(shape) => shape.count,
                None => panic!(
                    "Task {} doesn't contain any outputs of type {ty:?}",
                    self.task_id
                ),
            },
            ty_encoded,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WireSlice {
    circuit_builder_id: CircuitBuilderId,
    source: TaskId,
    range_start: TaskOutputIndex,
    range_end: TaskOutputIndex,
    ty_encoded: NumericalEnumType,
}
impl WireSlice {
    pub fn len(&self) -> WireSize {
        self.range_end - self.range_start
    }
    pub fn slice(&self, bounds: impl RangeBounds<WireSize>) -> Self {
        let start = match bounds.start_bound() {
            std::ops::Bound::Included(x) => *x,
            std::ops::Bound::Excluded(x) => x.checked_add(1).unwrap(),
            std::ops::Bound::Unbounded => 0,
        };
        let end = match bounds.end_bound() {
            std::ops::Bound::Included(x) => x.checked_add(1).unwrap(),
            std::ops::Bound::Excluded(x) => *x,
            std::ops::Bound::Unbounded => self.len(),
        };
        let range_start = self.range_start.checked_add(start).unwrap();
        let range_end = self.range_start.checked_add(end).unwrap();
        assert!(range_start <= range_end);
        assert!(self.range_start <= range_start);
        assert!(range_end <= self.range_end);
        WireSlice {
            circuit_builder_id: self.circuit_builder_id,
            source: self.source,
            range_start,
            range_end,
            ty_encoded: self.ty_encoded,
        }
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
enum AllocationType {
    Bytes,
    Type(NumericalEnumType),
}
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct AllocationSize {
    ty: AllocationType,
    count: u32,
}

pub(crate) struct PrototypeBuilder<'a, 'b> {
    f: DataChunkWriter<'a, 'b>,
    first_sender: Option<fb::TaskCommuniqueSender>,
    communication_rounds: &'a mut Vec<fb::TaskCommunicationRound>,
    allocation_sizes: &'a mut FxHashSet<AllocationSize>,
    last_send_was_prover: Option<bool>,
    tpr: TaskPrototypeRef,
    bytes_written: usize,
}

impl PrototypeBuilder<'_, '_> {
    fn send(&mut self, who: fb::TaskCommuniqueSender, size: u32) {
        assert_ne!(size, 0);
        let first_sender = if let Some(first_sender) = self.first_sender {
            first_sender
        } else {
            self.first_sender = Some(who);
            who
        };
        if first_sender == who {
            self.communication_rounds
                .push(fb::TaskCommunicationRound::new(size, 0));
        } else {
            self.communication_rounds
                .last_mut()
                .unwrap()
                .set_size_b(size);
        }
        self.allocation_sizes.insert(AllocationSize {
            ty: AllocationType::Bytes,
            count: size,
        });
    }
    pub(crate) fn prover_sends(&mut self, size: u32) {
        assert_ne!(self.last_send_was_prover, Some(true));
        self.last_send_was_prover = Some(true);
        self.send(fb::TaskCommuniqueSender::Prover, size);
    }
    pub(crate) fn verifier_sends(&mut self, size: u32) {
        assert_ne!(self.last_send_was_prover, Some(false));
        self.last_send_was_prover = Some(false);
        self.send(fb::TaskCommuniqueSender::Verifier, size);
    }
    pub(crate) fn output(&mut self, ty: Type, size: TaskOutputIndex) {
        assert_ne!(size, 0);
        let ty_encoded: NumericalEnumType = ty.into();
        for shape in self.tpr.outputs.iter() {
            assert_ne!(shape.ty_encoded, ty_encoded);
        }
        self.tpr.outputs.push(Shape::new(ty, size));
        self.allocation_sizes.insert(AllocationSize {
            ty: AllocationType::Type(ty_encoded),
            count: size,
        });
    }
    pub(crate) fn add_single_array_input(&mut self, ty: Type, size: TaskOutputIndex) {
        assert_ne!(size, 0);
        self.tpr.single_array_inputs.push(Shape::new(ty, size));
    }
    pub(crate) fn add_multi_array_input(&mut self, ty: Type, size: TaskOutputIndex) {
        assert_ne!(size, 0);
        self.tpr.multi_array_inputs.push(Shape::new(ty, size));
    }
}
impl Write for PrototypeBuilder<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.f.write(buf)?;
        self.bytes_written += n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

struct WIPTask<'a> {
    prototype_id: u32,
    inferred_priority: i32,
    inferred_dependents: bumpalo::collections::Vec<'a, TaskId>,
    dependencies: &'a [TaskId],
    single_array_inputs_fb: flatbuffers::WIPOffset<flatbuffers::Vector<'a, fb::TaskInput>>,
    multi_array_inputs_fb: flatbuffers::WIPOffset<
        flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<fb::MultiArrayTaskInput<'a>>>,
    >,
    name: Option<flatbuffers::WIPOffset<&'a str>>,
}

pub struct CircuitBuilder<'a> {
    arena: &'a bumpalo::Bump,
    id: CircuitBuilderId,
    builder: FlatBufferBuilder<'a>,
    output_file: BufWriter<File>,
    task_prototypes: Vec<flatbuffers::WIPOffset<fb::TaskPrototype<'a>>>,
    wip_tasks: Vec<WIPTask<'a>>,
    // Buffers which are only used to cache memory allocations
    round_buffer: Vec<fb::TaskCommunicationRound>,
    multi_array_task_input_buffer: Vec<flatbuffers::WIPOffset<fb::MultiArrayTaskInput<'a>>>,
    task_id_buffer: Vec<TaskId>,
    allocation_sizes: FxHashSet<AllocationSize>,
    encoded_task_kinds_used: FxHashSet<NumericalEnumType>,
}

impl CircuitBuilder<'_> {
    pub(crate) fn register_prototype<F>(&mut self, thunk: F) -> eyre::Result<TaskPrototypeRef>
    where
        for<'a, 'b, 'c> F: FnOnce(&'a mut PrototypeBuilder<'b, 'c>) -> eyre::Result<TaskKind>,
    {
        let mut pb_out = None;
        self.round_buffer.clear();
        let data_chunk = write_data_chunk(&mut self.output_file, |f| {
            let mut pb = PrototypeBuilder {
                f,
                first_sender: None,
                communication_rounds: &mut self.round_buffer,
                allocation_sizes: &mut self.allocation_sizes,
                last_send_was_prover: None,
                tpr: TaskPrototypeRef {
                    circuit_builder_id: self.id,
                    prototype_id: TaskPrototypeId::try_from(self.task_prototypes.len()).context(
                        "Too many prototypes created! It number of prototypes overflowed!",
                    )?,
                    single_array_inputs: Default::default(),
                    multi_array_inputs: Default::default(),
                    outputs: Default::default(),
                    num_rounds_communication: 0,
                    prototype_kind_encoded: 0,
                },
                bytes_written: 0,
            };
            let kind = thunk(&mut pb)?;
            pb.tpr.prototype_kind_encoded = kind.into();
            pb_out = Some((pb.tpr, pb.first_sender));
            Ok(())
        })
        .context("writing data for task prototype")?;
        let (mut tpr, first_sender) = pb_out.unwrap();
        self.encoded_task_kinds_used
            .insert(tpr.prototype_kind_encoded);
        let rounds = self.builder.create_vector(&self.round_buffer);
        let single_array_inputs = self.builder.create_vector_from_iter(
            tpr.single_array_inputs
                .iter()
                .map(|shape| fb::Shape::new(&fb::Type::new(shape.ty_encoded), shape.count)),
        );
        let multi_array_inputs = self.builder.create_vector_from_iter(
            tpr.multi_array_inputs
                .iter()
                .map(|shape| fb::Shape::new(&fb::Type::new(shape.ty_encoded), shape.count)),
        );
        let outputs = self.builder.create_vector_from_iter(
            tpr.outputs
                .iter()
                .map(|shape| fb::Shape::new(&fb::Type::new(shape.ty_encoded), shape.count)),
        );
        tpr.num_rounds_communication = self
            .round_buffer
            .len()
            .try_into()
            .expect("too many communication rounds");
        self.task_prototypes.push(fb::TaskPrototype::create(
            &mut self.builder,
            &fb::TaskPrototypeArgs {
                kind_encoding: tpr.prototype_kind_encoded,
                data: Some(&data_chunk),
                party_a: first_sender.unwrap_or_default(),
                rounds: Some(rounds),
                single_array_inputs: Some(single_array_inputs),
                multi_array_inputs: Some(multi_array_inputs),
                outputs: Some(outputs),
                name: None,
            },
        ));
        Ok(tpr)
    }
    // TODO: add name_prototype function
    pub fn name_task(&mut self, task: &TaskOutputRef, name: &str) {
        assert_eq!(task.circuit_builder_id, self.id);
        self.wip_tasks[task.task_id as usize].name = Some(self.builder.create_string(name));
    }
    pub fn instantiate(
        &mut self,
        prototype: &TaskPrototypeRef,
        single_array_inputs: &[WireSlice],
        multi_array_inputs: &[&[WireSlice]],
    ) -> eyre::Result<TaskOutputRef> {
        assert_eq!(prototype.circuit_builder_id, self.id);
        assert_eq!(
            prototype.single_array_inputs.len(),
            single_array_inputs.len()
        );
        assert_eq!(prototype.multi_array_inputs.len(), multi_array_inputs.len());
        let single_array_inputs_fb = self.builder.create_vector_from_iter(
            single_array_inputs
                .iter()
                .zip(prototype.single_array_inputs.iter())
                .map(|(ws, shape)| {
                    assert_eq!(ws.circuit_builder_id, self.id);
                    assert_eq!(ws.ty_encoded, shape.ty_encoded);
                    assert!(ws.range_start < ws.range_end);
                    assert_eq!(ws.range_end - ws.range_start, shape.count);
                    fb::TaskInput::new(
                        &fb::Type::new(ws.ty_encoded),
                        &fb::TaskId::new(ws.source),
                        ws.range_start,
                        ws.range_end,
                    )
                }),
        );
        self.multi_array_task_input_buffer.clear();
        self.multi_array_task_input_buffer.extend(
            multi_array_inputs
                .iter()
                .zip(prototype.multi_array_inputs.iter())
                .map(|(wire_slices, shape)| {
                    let mut total_count: u32 = 0;
                    let v = self
                        .builder
                        .create_vector_from_iter(wire_slices.iter().map(|ws| {
                            assert_eq!(ws.circuit_builder_id, self.id);
                            assert_eq!(ws.ty_encoded, shape.ty_encoded);
                            assert!(ws.range_start < ws.range_end);
                            let len = ws.range_end - ws.range_start;
                            total_count = total_count.checked_add(len).unwrap();
                            fb::TaskInputTributary::new(
                                &fb::TaskId::new(ws.source),
                                ws.range_start,
                                ws.range_end,
                            )
                        }));
                    assert_eq!(total_count, shape.count);
                    fb::MultiArrayTaskInput::create(
                        &mut self.builder,
                        &fb::MultiArrayTaskInputArgs {
                            ty: Some(&fb::Type::new(shape.ty_encoded)),
                            inputs: Some(v),
                        },
                    )
                }),
        );
        let multi_array_inputs_fb = self
            .builder
            .create_vector(&self.multi_array_task_input_buffer);
        self.task_id_buffer.clear();
        self.task_id_buffer
            .extend(single_array_inputs.iter().map(|ws| ws.source));
        self.task_id_buffer.extend(
            multi_array_inputs
                .iter()
                .flat_map(|wses| wses.iter())
                .map(|ws| ws.source),
        );
        let task_id = TaskId::try_from(self.wip_tasks.len()).expect("too many tasks!");
        for dep_tid in self.task_id_buffer.iter().copied() {
            let dep_tid = usize::try_from(dep_tid).expect("sizeof(usize) >= sizeof(TaskId)");
            self.wip_tasks[dep_tid].inferred_dependents.push(task_id);
        }
        self.wip_tasks.push(WIPTask {
            prototype_id: prototype.prototype_id,
            inferred_priority: -TaskPriority::from(prototype.num_rounds_communication) - 1,
            inferred_dependents: bumpalo::collections::Vec::new_in(self.arena),
            dependencies: self.arena.alloc_slice_copy(&self.task_id_buffer),
            name: None,
            single_array_inputs_fb,
            multi_array_inputs_fb,
        });
        Ok(TaskOutputRef {
            prototype_kind_encoded: prototype.prototype_kind_encoded,
            circuit_builder_id: self.id,
            task_id,
            outputs: prototype.outputs.clone(),
        })
    }
    fn finish(mut self) -> eyre::Result<()> {
        // Compute priority
        // To compute the task priority, we want to visit the tasks in topological order. The
        // reversed WIPTasks are a valid topological order.
        // We can't easily use an iter() here since we want to mutate other elements in the `Vec`
        // as we iterate.
        let mut initially_ready_tasks: Vec<fb::TaskId> = Vec::new();
        for i in (0..self.wip_tasks.len()).rev() {
            // P(t) = max(P(d) for d in dependents(t)) - max(1, # of communication rounds in t)
            // inferred_priority has already been set to -max(1, # of communication rounds in t)
            let delta = self.wip_tasks[i]
                .inferred_dependents
                .iter()
                .map(|dependent| {
                    let dependent =
                        usize::try_from(*dependent).expect("this is a valid task index");
                    self.wip_tasks[dependent].inferred_priority
                })
                .max()
                .unwrap_or(0);
            let ip = &mut self.wip_tasks[i].inferred_priority;
            *ip = ip.checked_add(delta).unwrap();
            if self.wip_tasks[i].dependencies.is_empty() {
                initially_ready_tasks.push(fb::TaskId::new(u32::try_from(i).unwrap()));
            }
        }
        // Write dependency and dependent lists
        let dependent_counts = write_data_chunk(&mut self.output_file, |mut f| {
            for task in self.wip_tasks.iter() {
                let num_dependents: GraphDegreeCount = task
                    .inferred_dependents
                    .len()
                    .try_into()
                    .expect("too many graph dependents");
                f.write_all(&num_dependents.to_le_bytes())?;
            }
            Ok(())
        })?;
        let dependency_counts = write_data_chunk(&mut self.output_file, |mut f| {
            for task in self.wip_tasks.iter() {
                let num_dependencies: GraphDegreeCount = task
                    .dependencies
                    .len()
                    .try_into()
                    .expect("too many graph dependents");
                f.write_all(&num_dependencies.to_le_bytes())?;
            }
            Ok(())
        })?;
        // Write the manifest
        let prototypes = self.builder.create_vector(&self.task_prototypes);
        let tasks: Vec<_> = self
            .wip_tasks
            .iter_mut()
            .map(|task| {
                // We sort these to try to optimize for cache hits when updating dependent launch
                // counts.
                task.inferred_dependents.sort_unstable();
                let inferred_dependents = self.builder.create_vector_from_iter(
                    task.inferred_dependents
                        .iter()
                        .copied()
                        .map(fb::TaskId::new),
                );
                fb::Task::create(
                    &mut self.builder,
                    &fb::TaskArgs {
                        prototype_id: task.prototype_id,
                        single_array_inputs: Some(task.single_array_inputs_fb),
                        multi_array_inputs: Some(task.multi_array_inputs_fb),
                        inferred_priority: task.inferred_priority,
                        inferred_dependents: Some(inferred_dependents),
                        name: task.name,
                    },
                )
            })
            .collect();
        let tasks = self.builder.create_vector(&tasks);
        // Write the flatbuffer to disk
        let initially_ready_tasks = self.builder.create_vector(&initially_ready_tasks);
        let allocation_sizes: Vec<_> = self
            .allocation_sizes
            .iter()
            .map(|asz| {
                fb::AllocationSize::create(
                    &mut self.builder,
                    &fb::AllocationSizeArgs {
                        type_: match asz.ty {
                            AllocationType::Bytes => None,
                            AllocationType::Type(ty) => Some(fb::Type::new(ty)),
                        }
                        .as_ref(),
                        count: asz.count,
                    },
                )
            })
            .collect();
        let allocation_sizes = self.builder.create_vector(&allocation_sizes);
        let encoded_task_kinds_used = self.builder.create_vector(
            &self
                .encoded_task_kinds_used
                .iter()
                .copied()
                .collect::<Vec<_>>(),
        );
        let manifest = fb::Manifest::create(
            &mut self.builder,
            &fb::ManifestArgs {
                tasks: Some(tasks),
                prototypes: Some(prototypes),
                initially_ready_tasks: Some(initially_ready_tasks),
                dependent_counts: Some(&dependent_counts),
                dependency_counts: Some(&dependency_counts),
                allocation_sizes: Some(allocation_sizes),
                task_kinds_used: Some(encoded_task_kinds_used),
            },
        );
        self.builder.finish_minimal(manifest);
        let manifest_start = self.output_file.stream_position()?;
        let mut compressor = lz4::EncoderBuilder::new().build(&mut self.output_file)?;
        compressor.write_all(self.builder.finished_data())?;
        compressor.finish().1?;
        self.output_file.write_all(&manifest_start.to_le_bytes())?;
        self.output_file.write_all(
            &u64::try_from(self.builder.finished_data().len())
                .unwrap()
                .to_le_bytes(),
        )?;
        const MANIFEST_HASH_SEED: u64 = 0xab21cc575f95137;
        let mut h = twox_hash::Xxh3Hash64::with_seed(MANIFEST_HASH_SEED);
        std::hash::Hasher::write(&mut h, self.builder.finished_data());
        std::hash::Hasher::write(&mut h, &MAC_N_CHEESE_VERSION.to_le_bytes());
        self.output_file
            .write_all(&std::hash::Hasher::finish(&h).to_le_bytes())?;
        self.output_file
            .write_all(&MAC_N_CHEESE_VERSION.to_le_bytes())?;
        Ok(())
    }
}

pub fn build_circuit<F>(dst: impl AsRef<Path>, thunk: F) -> eyre::Result<()>
where
    for<'a> F: FnOnce(&'a mut CircuitBuilder) -> eyre::Result<()>,
{
    let dst = dst.as_ref();
    let arena = bumpalo::Bump::new();
    let mut cb = CircuitBuilder {
        arena: &arena,
        id: CircuitBuilderId::random(),
        builder: FlatBufferBuilder::new(),
        output_file: BufWriter::with_capacity(
            1024 * 1024 * 16,
            File::create(dst).with_context(|| format!("Opening {dst:?} for writing"))?,
        ),
        task_prototypes: Vec::new(),
        wip_tasks: Vec::new(),
        round_buffer: Vec::new(),
        multi_array_task_input_buffer: Vec::new(),
        task_id_buffer: Vec::new(),
        allocation_sizes: Default::default(),
        encoded_task_kinds_used: Default::default(),
    };
    thunk(&mut cb).context("calling circuit builder thunk")?;
    cb.finish()
}

pub(crate) struct DataChunkWriter<'a, 'b> {
    hasher: &'a mut twox_hash::Xxh3Hash64,
    // TODO: we might want to do BufWriter<lz4::Encoder<File>> instead
    t: &'a mut lz4::Encoder<&'b mut BufWriter<File>>,
    uncompressed_length: &'a mut u64,
}

impl Write for DataChunkWriter<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.t.write(buf)?;
        *self.uncompressed_length += n as u64;
        std::hash::Hasher::write(self.hasher, &buf[0..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.t.flush()
    }
}
pub(crate) fn write_data_chunk<F>(
    t: &mut BufWriter<File>,
    f: F,
) -> eyre::Result<fb::DataChunkAddress>
where
    for<'b, 'c> F: FnOnce(DataChunkWriter<'b, 'c>) -> eyre::Result<()>,
{
    const DATA_CHUNK_HASH_SEED: u64 = 0x2849d23fa51e9690;
    let start = t.stream_position()?;
    let mut hasher = twox_hash::Xxh3Hash64::with_seed(DATA_CHUNK_HASH_SEED);
    let mut uncompressed_length = 0;
    let mut compressor = lz4::EncoderBuilder::new().build(t)?;
    f(DataChunkWriter {
        t: &mut compressor,
        hasher: &mut hasher,
        uncompressed_length: &mut uncompressed_length,
    })?;
    let hash_code = std::hash::Hasher::finish(&hasher);
    let (t, result) = compressor.finish();
    result?;
    let compressed_length = u32::try_from(t.stream_position()? - start)
        .context("data chunk length exceeds u32 size!")?;
    let uncompressed_length =
        u32::try_from(uncompressed_length).context("data chunk length exceeds u32 size!")?;
    Ok(fb::DataChunkAddress::new(
        start,
        uncompressed_length,
        hash_code,
        compressed_length,
    ))
}

pub struct FixWriter<'a, FE: FiniteField> {
    serializer: FE::Serializer,
    dst: &'a mut BufWriter<File>,
    count: u32,
}

impl<FE: FiniteField> FixWriter<'_, FE> {
    pub fn add(&mut self, x: FE) -> eyre::Result<()> {
        self.count += 1;
        self.serializer.write(self.dst, x)?;
        Ok(())
    }
}

pub struct FixData {
    data: PrivateDataAddress,
    count: WireSize,
    value_field: TypeId,
}

pub struct PrivateBuilder {
    f: BufWriter<File>,
    manifest: FxHashMap<TaskId, PrivateDataAddress>,
}
impl PrivateBuilder {
    pub fn write_unassociated_fix_data<F, FE: FiniteField>(&mut self, f: F) -> eyre::Result<FixData>
    where
        for<'a, 'b> F: FnOnce(&'a mut FixWriter<'b, FE>) -> eyre::Result<()>,
    {
        let start = self.f.stream_position()?;
        let serializer = FE::Serializer::new(&mut self.f)?;
        let mut s = FixWriter {
            serializer,
            dst: &mut self.f,
            count: 0,
        };
        f(&mut s)?;
        s.serializer.finish(&mut s.dst)?;
        Ok(FixData {
            data: PrivateDataAddress {
                offset: start,
                len: u32::try_from(s.dst.stream_position()? - start).unwrap(),
            },
            value_field: TypeId::of::<FE>(),
            count: s.count,
        })
    }
    pub fn associate_fix_data(&mut self, task: &TaskOutputRef, data: FixData) -> eyre::Result<()> {
        let ty = match TaskKind::try_from(task.prototype_kind_encoded).unwrap() {
            TaskKind::Fix(ty) => {
                struct V(TypeId);
                impl FieldTypeMacVisitor for V {
                    type Output = ();
                    fn visit<
                        VF: FiniteField + scuttlebutt::field::IsSubFieldOf<TF>,
                        TF: FiniteField,
                        S: mac_n_cheese_vole::specialization::FiniteFieldSpecialization<VF, TF>,
                    >(
                        self,
                    ) -> Self::Output {
                        assert_eq!(TypeId::of::<VF>(), self.0);
                    }
                }
                ty.visit(V(data.value_field));
                Type::Mac(ty)
            }
            k => panic!("{k:?} isn't a Fix task!"),
        };
        let shape = *task.outputs.first().unwrap();
        assert_eq!(shape.ty(), ty);
        assert_eq!(data.count, shape.count());
        let old = self.manifest.insert(task.task_id, data.data);
        assert!(old.is_none());
        Ok(())
    }
    pub fn write_fix_data<F, FE: FiniteField>(
        &mut self,
        task: &TaskOutputRef,
        f: F,
    ) -> eyre::Result<()>
    where
        for<'a, 'b> F: FnOnce(&'a mut FixWriter<'b, FE>) -> eyre::Result<()>,
    {
        let data = self.write_unassociated_fix_data(f)?;
        self.associate_fix_data(task, data)?;
        Ok(())
    }
}

pub fn build_privates<F>(dst: impl AsRef<Path>, thunk: F) -> eyre::Result<()>
where
    for<'a> F: FnOnce(&'a mut PrivateBuilder) -> eyre::Result<()>,
{
    let dst = dst.as_ref();
    let mut pb = PrivateBuilder {
        f: BufWriter::new(
            File::create(dst).with_context(|| format!("trying to create {:?}", dst))?,
        ),
        manifest: Default::default(),
    };
    thunk(&mut pb)?;
    let pos = pb.f.stream_position()?;
    pb.f.write_all(
        &u32::try_from(pb.manifest.len())
            .expect("Task ID is only 32 bits")
            .to_le_bytes(),
    )?;
    for (tid, addr) in pb.manifest.iter() {
        pb.f.write_all(bytemuck::bytes_of(&PrivatesManifestEntry {
            offset: addr.offset,
            length: addr.len,
            task_id: *tid,
        }))?;
    }
    pb.f.write_all(&pos.to_le_bytes())?;
    pb.f.flush()?;
    Ok(())
}

pub mod tasks;
pub mod vole_supplier;
