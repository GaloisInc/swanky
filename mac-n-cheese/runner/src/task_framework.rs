use std::{io::Cursor, marker::PhantomData, sync::Arc};

use eyre::ContextCompat;
use mac_n_cheese_ir::compilation_format::{
    fb::{Task, TaskPrototype},
    wire_format::{
        simd_batched,
        simple::{self, ReadWire},
    },
    FieldMacType, TaskId, Type,
};
use mac_n_cheese_party::{
    either::PartyEither,
    private::{ProverPrivate, ProverPrivateCopy},
    Party, WhichParty,
};
use mac_n_cheese_vole::{
    mac::{Mac, MacTypes},
    specialization::SmallBinaryFieldSpecialization,
};
use rustc_hash::FxHashMap;
use scuttlebutt::{
    field::{FiniteField, IsSubFieldOf, SmallBinaryField, F2},
    serialization::{CanonicalSerialize, SequenceDeserializer, SequenceSerializer},
    AesRng,
};
use smallvec::SmallVec;
use vectoreyes::{
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
    I32x4, SimdBase, SimdBaseGatherable, U32x4, U64x4,
};

use crate::{
    alloc::{
        AlignedBytes, AlignedBytesMut, AlignedSlice, BytesFromDisk, ErasedOwnedAligned,
        OwnedAlignedBytes, TaskDataBuffer,
    },
    base_vole::VoleContexts,
    flatbuffers_ext::FbVectorExt,
    tls::TlsConnection,
    types::assert_type_is,
};

pub enum NoContinuation {}

#[derive(Default)]
pub struct TaskOutput<P: Party> {
    contents: SmallVec<[ErasedOwnedAligned; 1]>,
    phantom: PhantomData<P>,
}
impl<P: Party> TaskOutput<P> {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn new_with<T: 'static + Send + Sync + Copy>(x: TaskDataBuffer<T>) -> Self {
        let mut out = Self::new();
        out.insert(x);
        out
    }
    #[allow(unused)]
    pub fn len(&self) -> usize {
        self.contents.len()
    }
    // panics if inserting more than once
    pub fn insert<T: 'static + Send + Sync + Copy>(&mut self, x: TaskDataBuffer<T>) {
        for old in self.contents.iter() {
            assert!(old.get::<T>().is_none());
        }
        self.contents.push(x.erased());
    }
    pub fn get<T: 'static + Send + Sync + Copy>(&self) -> &AlignedSlice<T> {
        for x in self.contents.iter() {
            if let Some(out) = x.get::<T>() {
                return out;
            }
        }
        panic!("{} not found in TaskOutput", std::any::type_name::<T>())
    }
}

pub enum TaskResult<P: Party, T> {
    NeedsCommunication(T),
    Finished(Arc<TaskOutput<P>>),
}

pub struct TaskContext<'a> {
    // A task can migrate between threads during its lifetime.
    pub thread_id: usize,
    pub task_id: TaskId,
    pub rng: &'a mut AesRng,
    pub arena: &'a bumpalo::Bump,
    pub prototype_has_been_verified: bool,
    pub task: Task<'a>,
    pub task_prototype: TaskPrototype<'a>,
}

pub type Challenge = [u8; 32];
// TODO: don't use a hashmap here?
pub type TaskDependencies<P> = FxHashMap<TaskId, Arc<TaskOutput<P>>>;

pub struct TaskInput<P: Party> {
    pub challenge: Option<Challenge>,
    pub task_data: Option<BytesFromDisk>,
    pub prover_private_data: ProverPrivate<P, Option<BytesFromDisk>>,
    // don't read this directly
    pub task_dependencies: TaskDependencies<P>,
}
impl<P: Party> TaskInput<P> {
    pub fn task_data(&self) -> AlignedBytes {
        self.task_data
            .as_ref()
            .map::<AlignedBytes, _>(|x| <OwnedAlignedBytes as AsRef<AlignedSlice<u8>>>::as_ref(x))
            .unwrap_or_default()
    }
    pub fn multi_array_inputs<'a, T: 'static + Send + Sync + Copy>(
        &self,
        ctx: &TaskContext<'a>,
        idx: usize,
    ) -> eyre::Result<&'a [&[T]]> {
        let input = ctx
            .task
            .multi_array_inputs()
            .get_opt(idx)
            .context("Missing single array input")?;
        #[cfg(debug_assertions)]
        {
            assert_type_is::<P, T>(Type::try_from(*input.ty())?);
        }
        let out = ctx.arena.alloc_slice_fill_default(input.inputs().len());
        for (tributary, out) in input.inputs().iter().zip(out.iter_mut()) {
            let dependency_output = self
                .task_dependencies
                .get(&tributary.source().id())
                .context("Missing input source in task dependency map")?;
            let start = usize::try_from(tributary.start()).unwrap();
            let end = usize::try_from(tributary.end()).unwrap();
            *out = dependency_output
                .get::<T>()
                .get(start..end)
                .context("input out of bounds")?;
        }
        Ok(out)
    }
    pub fn single_array_input<T: 'static + Send + Sync + Copy>(
        &self,
        ctx: &TaskContext,
        idx: usize,
    ) -> eyre::Result<&[T]> {
        let input = ctx
            .task
            .single_array_inputs()
            .get_opt(idx)
            .context("Missing single array input")?;
        let dependency_output = self
            .task_dependencies
            .get(&input.source().id())
            .context("Missing input source in task dependency map")?;
        #[cfg(debug_assertions)]
        {
            assert_type_is::<P, T>(Type::try_from(*input.ty())?);
        }
        let start = usize::try_from(input.start()).unwrap();
        let end = usize::try_from(input.end()).unwrap();
        let count = end.checked_sub(start).context("slice end > start")?;
        eyre::ensure!(
            usize::try_from(
                ctx.task_prototype
                    .single_array_inputs()
                    .get_opt(idx)
                    .context("missing single array input in prototype")?
                    .count()
            )
            .unwrap()
                == count,
            "prototype count matches input count"
        );
        dependency_output
            .get::<T>()
            .get(start..end)
            .context("input out of bounds")
    }
    pub fn single_array_inputs<'a, T: 'static + Send + Sync + Copy>(
        &self,
        ctx: &TaskContext<'a>,
    ) -> eyre::Result<&'a [&[T]]> {
        let out = ctx
            .arena
            .alloc_slice_fill_default(ctx.task.single_array_inputs().len());
        for (i, dst) in out.iter_mut().enumerate() {
            *dst = self.single_array_input(ctx, i)?;
        }
        Ok(out)
    }
    fn simple_wire_task_inner<
        const NARGS: usize,
        const NOUTPUT: usize,
        const VERIFIED: bool,
        T: 'static + Sync + Send + Copy,
        Data: CanonicalSerialize,
    >(
        &self,
        ctx: &TaskContext,
        _format: simple::WireFormat<Data, NARGS>,
        mut f: impl FnMut([(T, Data); NARGS]) -> eyre::Result<[T; NOUTPUT]>,
    ) -> eyre::Result<TaskResult<P, NoContinuation>>
    where
        ArrayUnrolledOps: UnrollableArraySize<NARGS>,
    {
        let mut out = TaskDataBuffer::<T>::with_capacity(
            ctx.task_prototype
                .outputs()
                .get_opt(0)
                .map(|x| x.count() as usize)
                .unwrap_or_default(),
        );
        let inputs = self.single_array_inputs::<T>(ctx)?;
        // We want to append an extra slice to the end for own wires.
        let input_ptrs = ctx.arena.alloc_slice_fill_with(inputs.len() + 1, |i| {
            if i < inputs.len() {
                inputs[i].as_ptr()
            } else {
                out.as_ptr()
            }
        });
        // This is ignored once we've verified the prototype.
        let input_sizes = ctx.arena.alloc_slice_fill_with(inputs.len() + 1, |i| {
            if i < inputs.len() {
                inputs[i].len()
            } else {
                out.len()
            }
        });
        let mut r = simple::Reader::<Data, NARGS>::new(self.task_data())?;
        while r.len_remaining() > 0 {
            let args = r.next()?;
            let args = args.array_map_result(
                #[inline(always)]
                |ReadWire {
                     which_input,
                     which_wire,
                     data,
                 }| {
                    if !VERIFIED {
                        eyre::ensure!(
                            (which_input as usize) < input_sizes.len(),
                            "which_input {which_input} is out of range of {input_sizes:?}"
                        );
                        eyre::ensure!(
                            (which_wire as usize) < input_sizes[which_input as usize],
                            "which_wire ({which_wire}) is out of range of {which_input}: {}",
                            input_sizes[which_input as usize]
                        );
                    }
                    Ok((
                        unsafe {
                            let input_ptr = *input_ptrs.get_unchecked(which_input as usize);
                            input_ptr.add(which_wire as usize).read()
                        },
                        data,
                    ))
                },
            )?;
            let outputs = f(args)?;
            for x in outputs {
                out.push(x);
            }
            if !VERIFIED {
                *input_sizes.last_mut().unwrap() = out.len();
            }
        }
        Ok(TaskResult::Finished(Arc::new(TaskOutput::new_with(out))))
    }
    pub fn simple_wire_task<
        const NARGS: usize,
        const NOUTPUT: usize,
        T: 'static + Sync + Send + Copy,
        Data: CanonicalSerialize,
    >(
        &self,
        ctx: &TaskContext,
        format: simple::WireFormat<Data, NARGS>,
        f: impl FnMut([(T, Data); NARGS]) -> eyre::Result<[T; NOUTPUT]>,
    ) -> eyre::Result<TaskResult<P, NoContinuation>>
    where
        ArrayUnrolledOps: UnrollableArraySize<NARGS>,
    {
        eyre::ensure!(
            ctx.task_prototype.outputs().len() <= 1,
            "only one task output"
        );
        if ctx.prototype_has_been_verified {
            self.simple_wire_task_inner::<NARGS, NOUTPUT, true, T, Data>(ctx, format, f)
        } else {
            self.simple_wire_task_inner::<NARGS, NOUTPUT, false, T, Data>(ctx, format, f)
        }
    }
    fn small_binary_mac_task_inner<
        const NARGS: usize,
        const NOUTPUT: usize,
        const VERIFIED: bool,
        T: MacTypes<VF = F2, S = SmallBinaryFieldSpecialization>,
    >(
        &self,
        ctx: &TaskContext,
        _format: simd_batched::WireFormat<NARGS>,
        mut f: impl FnMut([U64x4; NARGS]) -> eyre::Result<[U64x4; NOUTPUT]>,
    ) -> eyre::Result<TaskResult<P, NoContinuation>>
    where
        T::TF: SmallBinaryField,
        F2: IsSubFieldOf<T::TF>,
        ArrayUnrolledOps: UnrollableArraySize<NARGS>,
    {
        let num_outs = ctx
            .task_prototype
            .outputs()
            .get_opt(0)
            .map(|x| x.count() as usize)
            .unwrap_or_default();
        let mut out = TaskDataBuffer::<Mac<P, T>>::with_capacity(num_outs);
        let chunks = simd_batched::read(bytemuck::cast_slice(self.task_data()))?;
        eyre::ensure!(
            num_outs == chunks.len() * NOUTPUT * 4,
            "output length is incorrect"
        );
        let inputs = self.single_array_inputs::<Mac<P, T>>(ctx)?;
        // We want to append an extra slice to the end for own wires.
        let input_ptrs = ctx.arena.alloc_slice_fill_with(inputs.len() + 1, |i| {
            if i < inputs.len() {
                inputs[i].as_ptr()
            } else {
                out.as_ptr()
            }
        });
        // This is ignored once we've verified the prototype.
        let input_sizes = ctx.arena.alloc_slice_fill_with(inputs.len() + 1, |i| {
            if i < inputs.len() {
                u32::try_from(inputs[i].len()).unwrap()
            } else {
                u32::try_from(out.len()).unwrap()
            }
        });
        for x in input_sizes.iter() {
            assert!(*x < i32::MAX as u32);
        }
        assert!(num_outs < i32::MAX as usize);
        // This is ensured because we've allocated an aligned buffer.
        assert_eq!(
            out.as_mut_ptr() as usize % std::mem::align_of::<[U64x4; NOUTPUT]>(),
            0
        );
        if NOUTPUT > 0 {
            assert_eq!(num_outs % NOUTPUT, 0);
        }
        let mut write_ptr = out.as_mut_ptr() as *mut [U64x4; NOUTPUT];
        eyre::ensure!(input_sizes.len() < (i32::MAX as usize), "too many inputs");
        let num_lengths = U32x4::broadcast(input_sizes.len().try_into()?);
        const ONES: U32x4 = U32x4::from_array([u32::MAX; 4]);
        for chunk in chunks {
            if !VERIFIED {
                chunk.array_map_result(
                    #[inline(always)]
                    |simd_batched::ReadWire {
                         which_input,
                         which_wire,
                     }| {
                        eyre::ensure!(
                            num_lengths.cmp_gt(which_input) == ONES,
                            "which_input is out of bounds"
                        );
                        let retrieved_lengths = unsafe {
                            // SAFETY: we just did the bounds check
                            U32x4::gather(input_sizes.as_ptr(), I32x4::from(which_input))
                        };
                        eyre::ensure!(
                            retrieved_lengths.cmp_gt(which_wire) == ONES,
                            "which_wire is out of bounds"
                        );
                        Ok(())
                    },
                )?;
            }
            let args = unsafe {
                debug_assert_eq!(
                    std::mem::size_of::<*const i32>(),
                    std::mem::size_of::<u64>()
                );
                let bases = chunk.array_map(
                    #[inline(always)]
                    |simd_batched::ReadWire {
                         which_input,
                         which_wire: _,
                     }| {
                        U64x4::gather(input_ptrs.as_ptr() as *const u64, I32x4::from(which_input))
                    },
                );
                // TODO: portably come up with a way to talk about gathering pointers using vectoreyes.
                #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                unsafe fn gather_pointers(ptrs: U64x4) -> U64x4 {
                    use std::arch::x86_64::_mm256_i64gather_epi64;
                    bytemuck::cast(_mm256_i64gather_epi64(
                        std::ptr::null(),
                        bytemuck::cast(ptrs),
                        1,
                    ))
                }
                #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
                unsafe fn gather_pointers(ptrs: U64x4) -> U64x4 {
                    ptrs.as_array()
                        .array_map(
                            #[inline(always)]
                            |ptr| unsafe { *(ptr as *const u64) },
                        )
                        .into()
                }
                chunk.array_zip(bases).array_map(
                    #[inline(always)]
                    |(
                        simd_batched::ReadWire {
                            which_input: _,
                            which_wire,
                        },
                        bases,
                    )| {
                        gather_pointers(bases + U64x4::from(which_wire).shift_left::<3>())
                    },
                )
            };
            let out = f(args)?;
            if NOUTPUT > 0 {
                unsafe {
                    write_ptr.write(out);
                    write_ptr = write_ptr.add(1);
                }
                if !VERIFIED {
                    *input_sizes.last_mut().unwrap() += (NOUTPUT * 4) as u32;
                }
            }
        }
        if !VERIFIED {
            debug_assert_eq!(num_outs, (*input_sizes.last().unwrap()) as usize);
        }
        unsafe {
            out.set_len(num_outs);
        }
        Ok(TaskResult::Finished(Arc::new(TaskOutput::new_with(out))))
    }
    pub fn small_binary_mac_task<
        const NARGS: usize,
        const NOUTPUT: usize,
        T: MacTypes<VF = F2, S = SmallBinaryFieldSpecialization>,
    >(
        &self,
        ctx: &TaskContext,
        format: simd_batched::WireFormat<NARGS>,
        f: impl FnMut([U64x4; NARGS]) -> eyre::Result<[U64x4; NOUTPUT]>,
    ) -> eyre::Result<TaskResult<P, NoContinuation>>
    where
        T::TF: SmallBinaryField,
        F2: IsSubFieldOf<T::TF>,
        ArrayUnrolledOps: UnrollableArraySize<NARGS>,
    {
        eyre::ensure!(
            ctx.task_prototype.outputs().len() <= 1,
            "only one task output"
        );
        if ctx.prototype_has_been_verified {
            self.small_binary_mac_task_inner::<NARGS, NOUTPUT, true, T>(ctx, format, f)
        } else {
            self.small_binary_mac_task_inner::<NARGS, NOUTPUT, false, T>(ctx, format, f)
        }
    }
}

pub struct ProverPrivateFieldElementCommunicator<'a, P: Party, FE: FiniteField> {
    content: PartyEither<
        P,
        (Cursor<&'a mut [u8]>, FE::Serializer),
        (Cursor<&'a [u8]>, FE::Deserializer),
    >,
}
impl<'a, P: Party, FE: FiniteField> ProverPrivateFieldElementCommunicator<'a, P, FE> {
    pub fn new(incoming: &'a [u8], outgoing: &'a mut [u8]) -> eyre::Result<Self> {
        Ok(Self {
            content: match P::WHICH {
                WhichParty::Prover(e) => {
                    let mut cursor = Cursor::new(outgoing);
                    let s = FE::Serializer::new(&mut cursor)?;
                    PartyEither::prover_new(e, (cursor, s))
                }
                WhichParty::Verifier(e) => {
                    let mut cursor = Cursor::new(incoming);
                    let d = FE::Deserializer::new(&mut cursor)?;
                    PartyEither::verifier_new(e, (cursor, d))
                }
            },
        })
    }
    pub fn communicate(&mut self, x: ProverPrivateCopy<P, FE>) -> eyre::Result<FE> {
        Ok(match P::WHICH {
            WhichParty::Prover(e) => {
                let x = x.into_inner(e);
                let (cursor, s) = self.content.as_mut().prover_into(e);
                s.write(cursor, x)?;
                x
            }
            WhichParty::Verifier(e) => {
                let (cursor, d) = self.content.as_mut().verifier_into(e);
                d.read(cursor)?
            }
        })
    }
    pub fn finish(self) -> eyre::Result<()> {
        if let WhichParty::Prover(e) = P::WHICH {
            let (mut cursor, s) = self.content.prover_into(e);
            s.finish(&mut cursor)?;
        }
        Ok(())
    }
}

pub type GlobalVolesNeeded = FxHashMap<FieldMacType, usize>;
pub trait TaskDefinition<P: Party>: 'static + Sized + Send + Sync {
    const NEEDS_CHALLENGE: bool;
    fn global_vole_support_needed() -> GlobalVolesNeeded;
    fn initialize(
        c: &mut TlsConnection<P>,
        rng: &mut AesRng,
        vc: VoleContexts<P>,
        num_runner_threads: usize,
    ) -> eyre::Result<Self>;
    type TaskContinuation: 'static + Send;
    fn finalize(self, c: &mut TlsConnection<P>, rng: &mut AesRng) -> eyre::Result<()>;
    fn start_task(
        &self,
        ctx: &mut TaskContext,
        input: &TaskInput<P>,
        incoming_data: OwnedAlignedBytes,
        outgoing_data: AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Self::TaskContinuation>>;
    fn continue_task(
        &self,
        tc: Box<Self::TaskContinuation>,
        ctx: &mut TaskContext,
        input: &TaskInput<P>,
        incoming_data: OwnedAlignedBytes,
        outgoing_data: AlignedBytesMut,
    ) -> eyre::Result<TaskResult<P, Self::TaskContinuation>>;
}
