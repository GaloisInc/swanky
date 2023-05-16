use std::{
    any::{type_name, Any},
    hash::BuildHasherDefault,
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use bumpalo::Bump;
use eyre::{Context, ContextCompat};
use mac_n_cheese_ir::compilation_format::{
    fb, AtomicGraphDegreeCount, Manifest, NumericalEnumType, PrivatesManifest, TaskId, TaskKind,
    Type,
};
use mac_n_cheese_party::{private::ProverPrivate, Party, WhichParty};
use parking_lot::{Condvar, Mutex, RwLock};
use rustc_hash::FxHashMap;
use scuttlebutt::AesRng;

use crate::{
    alloc::OwnedAlignedBytes,
    base_vole::{self, VoleContexts},
    event_log,
    flatbuffers_ext::FbVectorExt,
    reactor::{Reactor, ReactorRequest, ReactorResponse},
    task_definitions::{visit_task_definition, TaskDefinitionVisitor},
    task_framework::{
        GlobalVolesNeeded, TaskContext, TaskDefinition, TaskInput, TaskOutput, TaskResult,
    },
    task_queue::{RunningTaskId, TaskQueue, TaskQueueEntry},
    thread_spawner::ThreadSpawner,
    tls::TlsConnection,
    types::{visit_type, TypeVisitor},
};

use self::{erased_task_definition::ErasedTaskDefinition, limited_use_arcs::LimitedUseArcs};

mod erased_task_definition;
mod limited_use_arcs;

pub type RunQueue<P> = Arc<TaskQueue<Box<(ReactorResponse, ReactorCallback<P>)>>>;
// TODO: change this name
pub struct ReactorCallback<P: Party> {
    task_input: TaskInput<P>,
    task_continuation: Option<Box<dyn Any + Send>>,
    step_number: usize,
}

fn sender_is<P: Party>(tcs: fb::TaskCommuniqueSender) -> bool {
    match P::WHICH {
        WhichParty::Prover(_) => tcs == fb::TaskCommuniqueSender::Prover,
        WhichParty::Verifier(_) => tcs == fb::TaskCommuniqueSender::Verifier,
    }
}
#[derive(Default)]
struct CommunicatonSizes {
    incoming: usize,
    outgoing: usize,
}
impl CommunicatonSizes {
    // step = on call into task code. It's the same as the round except for the first and last
    // steps of party A.
    fn of<P: Party>(prototype: fb::TaskPrototype, step: usize) -> Self {
        if sender_is::<P>(prototype.party_a()) {
            // We are party A
            CommunicatonSizes {
                incoming: step
                    .checked_sub(1)
                    .and_then(|idx| prototype.rounds().get_opt(idx))
                    .map(|round| round.size_b() as usize)
                    .unwrap_or_default(),
                outgoing: prototype
                    .rounds()
                    .get_opt(step)
                    .map(|round| round.size_a() as usize)
                    .unwrap_or_default(),
            }
        } else {
            // We are party B
            prototype
                .rounds()
                .get_opt(step)
                .map(|round| CommunicatonSizes {
                    incoming: round.size_a() as usize,
                    outgoing: round.size_b() as usize,
                })
                .unwrap_or_default()
        }
    }
}

pub struct PerRunnerThread {
    thread_idx: usize,
    arena: Bump,
    rng: AesRng,
}

pub struct RunnerThread<P: Party> {
    run_queue: RunQueue<P>,
    manifest_owned: Arc<Manifest>,
    task_definitions: FxHashMap<NumericalEnumType, RwLock<ErasedTaskDefinition<P>>>,
    reactor: Arc<dyn Reactor<P>>,
    privates_manifest: ProverPrivate<P, PrivatesManifest>,
    num_tasks_remaining: AtomicUsize,
    no_tasks_remain: Mutex<bool>,
    no_tasks_remain_waiter: Condvar,
    remaining_dependencies: Vec<AtomicGraphDegreeCount>,
    task_outputs: LimitedUseArcs<TaskOutput<P>>,
}
impl<P: Party> RunnerThread<P> {
    fn run(&self, thread_idx: usize, rng: AesRng) -> eyre::Result<()> {
        let mut per_runner_thread = PerRunnerThread {
            thread_idx,
            arena: Bump::with_capacity(1024 * 1024 * 2),
            rng,
        };
        while let Some(entry) = self.run_queue.blocking_dequeue() {
            let span = event_log::RunnerProcessingTask {
                task_id: entry.id.task_id,
                priority: entry.id.priority,
            }
            .start();
            per_runner_thread.arena.reset();
            let id = entry.id;
            self.step_task(entry, &mut per_runner_thread)
                .with_context(|| format!("Running task callback for {:?}", id))?;
            span.finish();
        }
        Ok(())
    }
    // panics if task_id is out of range.
    fn launch_task(&self, task_id: TaskId) -> eyre::Result<()> {
        event_log::LaunchTask { task_id }.submit();
        let manifest = self.manifest_owned.manifest();
        let task = manifest.tasks().get(task_id as usize);
        eyre::ensure!(
            (task.prototype_id() as usize) < manifest.prototypes().len(),
            "prototype id is invalid"
        );
        let prototype = manifest.prototypes().get(task.prototype_id() as usize);
        let defn = self
            .task_definitions
            .get(&prototype.kind_encoding())
            .context("Task kind was not listed as used")?
            .read();
        let req = ReactorRequest {
            want_challenge: defn.needs_challenge(),
            // party_a sends first. We want incoming network data from whoever sends first, so long
            // as the party which sends first isn't us.
            want_incoming_network: prototype
                .rounds()
                .get_opt(0)
                .map(|round| round.size_a())
                .filter(|_| !sender_is::<P>(prototype.party_a()))
                .is_some(),
            want_task_data: Some(prototype.data())
                .filter(|chunk| chunk.length() > 0)
                .copied(),
            want_private_data: self
                .privates_manifest
                .as_ref()
                .map(|pm| pm.get(&task_id).copied().filter(|chunk| chunk.len > 0))
                .unwrap_or_else(|| None),
        };
        let task_id = RunningTaskId {
            task_id,
            priority: task.inferred_priority(),
        };
        // Because inputs can be duplicated, the hash map might not be filled to capacity.
        let mut task_dependencies = FxHashMap::with_capacity_and_hasher(
            task.single_array_inputs().len()
                + task
                    .multi_array_inputs()
                    .iter()
                    .map(|mai| mai.inputs().len())
                    .sum::<usize>(),
            BuildHasherDefault::default(),
        );
        // If a task is listed multiple times as an input, we'll end up overwriting that entry in
        // the hash map. It's important that we call take_one() on self.task_outputs for each input
        // even if that input is duplicated, since dependent_counts doesn't de-duplicate. Thus, in
        // order for a task output to be freed, we must invoke take_one() once for each input.
        for task_id in task
            .single_array_inputs()
            .iter()
            .map(|input| input.source())
            .chain(
                task.multi_array_inputs()
                    .iter()
                    .flat_map(|input| input.inputs().iter().map(|tributary| tributary.source())),
            )
        {
            let task_id = task_id.id();
            task_dependencies.insert(task_id, self.task_outputs.take_one(task_id));
        }
        self.reactor.request(
            task_id,
            req,
            ReactorCallback {
                task_input: TaskInput {
                    challenge: None,
                    task_data: None,
                    prover_private_data: ProverPrivate::new(None),
                    task_dependencies,
                },
                step_number: 0,
                task_continuation: None,
            },
        )?;
        Ok(())
    }

    fn step_task(
        &self,
        entry: TaskQueueEntry<Box<(ReactorResponse, ReactorCallback<P>)>>,
        per_runner_thread: &mut PerRunnerThread,
    ) -> eyre::Result<()> {
        let mut task_id = entry.id;
        let (
            resp,
            ReactorCallback {
                mut task_input,
                step_number,
                task_continuation,
            },
        ) = *entry.metadata;
        let manifest = self.manifest_owned.manifest();
        let task = manifest.tasks().get(task_id.task_id as usize);
        let prototype = manifest.prototypes().get(task.prototype_id() as usize);
        let defn = self
            .task_definitions
            .get(&prototype.kind_encoding())
            .context("Task kind was not listed as used")?
            .read();
        let prototype_has_been_verified = defn.verified().load(Ordering::Relaxed);
        // TODO: check that response values which shoudln't be provided aren't provided.
        task_input.challenge = task_input.challenge.or(resp.challenge);
        task_input.task_data = task_input.task_data.or(resp.task_data);
        task_input.prover_private_data = task_input
            .prover_private_data
            .map(|old| old.or(resp.private_data));
        let mut ctx = TaskContext {
            thread_id: per_runner_thread.thread_idx,
            task_id: task_id.task_id,
            rng: &mut per_runner_thread.rng,
            // The arena has been reset before any callbacks get called.
            arena: &per_runner_thread.arena,
            prototype_has_been_verified,
            task,
            task_prototype: prototype,
        };
        let sizes = CommunicatonSizes::of::<P>(prototype, step_number);
        let incoming_data = resp.incoming_bytes.unwrap_or_default();
        eyre::ensure!(
            incoming_data.len() == sizes.incoming,
            "incoming data size mismatch"
        );
        let mut outgoing_data = OwnedAlignedBytes::zeroed(sizes.outgoing);
        let tr = if let Some(task_continuation) = task_continuation {
            defn.continue_task(
                task_continuation,
                &mut ctx,
                &task_input,
                incoming_data,
                outgoing_data.as_mut(),
            )?
        } else {
            defn.start_task(&mut ctx, &task_input, incoming_data, outgoing_data.as_mut())?
        };
        if !outgoing_data.is_empty() {
            // It's important that we submit any outgoing data _before_ launching any other tasks.
            // That way we can ensure that outgoing data is sent in topological order.
            self.reactor.send_outgoing(task_id, outgoing_data)?;
        }
        let expected_to_finish_in_steps = if sender_is::<P>(prototype.party_a()) {
            // We are party a
            if prototype.rounds().is_empty() {
                // Even if there's no communication, we still need to run a single step for the
                // computation.
                1
            } else {
                // If party A sends last, then the number of steps for party A equals the number of
                // rounds. If party B sends last then (while the number of steps for party B will
                // remain the number of rounds) the number of steps for party A will increase by
                // one.
                prototype.rounds().len()
                    + (if prototype
                        .rounds()
                        .get(prototype.rounds().len() - 1)
                        .size_b()
                        > 0
                    {
                        1
                    } else {
                        0
                    })
            }
        } else {
            // We are party b
            prototype.rounds().len().max(1)
        };
        debug_assert!(expected_to_finish_in_steps > 0);
        match tr {
            TaskResult::NeedsCommunication(task_continuation) => {
                assert!(step_number < expected_to_finish_in_steps - 1);
                // Increment the priority, since working on later steps takes precedence over prior steps.
                task_id.priority += 1;
                self.reactor.request(
                    task_id,
                    ReactorRequest {
                        want_challenge: false,
                        want_incoming_network: true,
                        want_task_data: None,
                        want_private_data: None,
                    },
                    ReactorCallback {
                        task_input,
                        task_continuation: Some(task_continuation),
                        step_number: step_number + 1,
                    },
                )?;
            }
            TaskResult::Finished(out) => {
                assert_eq!(step_number, expected_to_finish_in_steps - 1);
                event_log::TaskFinished {
                    task_id: task_id.task_id,
                }
                .submit();
                // First mark the prototype as verified.
                // We use the if statement to avoid cache contention if the definition has already
                // been verified.
                if !defn.verified().load(Ordering::Relaxed) {
                    defn.verified().store(true, Ordering::Relaxed);
                }
                // Assert that the output counts are accurate.
                for shape in prototype.outputs().iter() {
                    struct V<'a, P: Party>(&'a TaskOutput<P>, usize);
                    impl<P: Party> TypeVisitor for V<'_, P> {
                        type Output = ();
                        fn visit<T: 'static + Send + Sync + Copy>(self) {
                            assert_eq!(self.1, self.0.get::<T>().len());
                        }
                    }
                    visit_type::<P, V<P>>(
                        Type::try_from(*shape.ty())?,
                        V::<P>(&out, shape.count() as usize),
                    );
                }
                // Insert the output into the map. If this task has no dependents, then its output
                // will be immediately freed.
                self.task_outputs.insert(task_id.task_id, out);
                // Notify dependents that this task is finished.
                for dependent in task.inferred_dependents().iter() {
                    let dependent = dependent.id();
                    match self
                        .remaining_dependencies
                        .get(dependent as usize)
                        .context("invalid dependent id")?
                        .fetch_sub(1, Ordering::Relaxed)
                    {
                        0 => panic!("remaining_dependencies count underflowed"),
                        1 => {
                            // This task has had all its dependencies satisified. We can launch it!
                            self.launch_task(dependent)?;
                        }
                        _ => {
                            // This task isn't ready to launch yet.
                        }
                    }
                }
                // Decrement the task remaining count
                match self.num_tasks_remaining.fetch_sub(1, Ordering::Relaxed) {
                    0 => panic!("num_tasks_remaining underflow"),
                    1 => {
                        // We're the last task!
                        let mut guard = self.no_tasks_remain.lock();
                        *guard = true;
                        self.no_tasks_remain_waiter.notify_all();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

pub fn run_proof_background<P: Party>(
    num_threads: usize,
    mut rng: AesRng,
    ts: &mut ThreadSpawner,
    mut root_conn: TlsConnection<P>,
    run_queue: RunQueue<P>,
    manifest_owned: Arc<Manifest>,
    reactor: Arc<dyn Reactor<P>>,
    privates_manifest: ProverPrivate<P, PrivatesManifest>,
    dependent_counts: Vec<AtomicGraphDegreeCount>,
    dependency_counts: Vec<AtomicGraphDegreeCount>,
) -> eyre::Result<()> {
    eyre::ensure!(
        num_threads >= 1,
        "there needs to be at least one runner thread"
    );
    let manifest = manifest_owned.manifest();
    // TODO: initialize task kinds in parallel.
    // First we need to do vole initialization.
    let span = event_log::VoleInitialization.start();
    let mut voles_needed: Vec<GlobalVolesNeeded> =
        Vec::with_capacity(manifest.task_kinds_used().len());
    for tk in manifest.task_kinds_used().iter() {
        struct V<'a>(&'a mut Vec<GlobalVolesNeeded>);
        impl<P: Party> TaskDefinitionVisitor<P> for V<'_> {
            type Output = ();
            fn visit<T: TaskDefinition<P>>(self) {
                let gvn = T::global_vole_support_needed();
                self.0.push(gvn);
            }
        }
        let tk = TaskKind::try_from(tk)?;
        visit_task_definition::<P, V>(tk, V(&mut voles_needed));
    }
    let vole_contexts = base_vole::init_base_vole::<P, _>(&voles_needed, &mut rng, &mut root_conn)
        .context("base vole")?;
    span.finish();
    // initialize task kinds
    let mut task_definitions = FxHashMap::with_capacity_and_hasher(
        manifest.task_kinds_used().len(),
        BuildHasherDefault::default(),
    );
    debug_assert_eq!(manifest.task_kinds_used().len(), vole_contexts.len());
    for (tk_encoded, vc) in manifest
        .task_kinds_used()
        .iter()
        .zip(vole_contexts.into_iter())
    {
        struct V<'a, P: Party>(
            VoleContexts<P>,
            &'a mut AesRng,
            &'a mut TlsConnection<P>,
            usize,
        );
        impl<P: Party> TaskDefinitionVisitor<P> for V<'_, P> {
            type Output = eyre::Result<ErasedTaskDefinition<P>>;
            fn visit<T: TaskDefinition<P>>(self) -> eyre::Result<ErasedTaskDefinition<P>> {
                Ok(ErasedTaskDefinition::new(
                    T::initialize(self.2, self.1, self.0, self.3)
                        .with_context(|| format!("Initializing task kind {}", type_name::<T>()))?,
                ))
            }
        }
        let tk = TaskKind::try_from(tk_encoded)?;
        let etd =
            visit_task_definition::<P, V<'_, P>>(tk, V(vc, &mut rng, &mut root_conn, num_threads))?;
        root_conn.flush()?;
        let old = task_definitions.insert(tk_encoded, RwLock::new(etd));
        eyre::ensure!(old.is_none(), "Duplicate task kind {tk:?} listed");
    }
    // spin up the runner threads
    let num_tasks_remaining = AtomicUsize::new(manifest.tasks().len());
    let runner_thread = Arc::new(RunnerThread {
        run_queue,
        manifest_owned,
        task_definitions,
        num_tasks_remaining,
        reactor,
        privates_manifest,
        no_tasks_remain: Mutex::new(false),
        no_tasks_remain_waiter: Condvar::new(),
        remaining_dependencies: dependency_counts,
        task_outputs: LimitedUseArcs::new(dependent_counts),
    });
    for i in 0..num_threads {
        let runner_thread = runner_thread.clone();
        let rng = rng.fork();
        ts.spawn(format!("Runner thread {i}"), move || {
            runner_thread.run(i, rng)
        });
    }
    ts.spawn("runner main thread".to_string(), move || {
        // Ask the reactor to launch all the tasks that have no dependencies.
        let manifest = runner_thread.manifest_owned.manifest();
        for tid in manifest.initially_ready_tasks().iter() {
            let tid = tid.id();
            eyre::ensure!(
                (tid as usize) < manifest.tasks().len(),
                "task id is out of range"
            );
            runner_thread.launch_task(tid)?;
        }
        // Wait until the tasks have finished running.
        {
            let mut guard = runner_thread.no_tasks_remain.lock();
            runner_thread
                .no_tasks_remain_waiter
                .wait_while(&mut guard, |no_tasks_remain| !*no_tasks_remain);
        }
        runner_thread.reactor.close();
        runner_thread.run_queue.close();
        // TODO: parallelize the finalization.
        root_conn.flush()?;
        for tk in manifest.task_kinds_used().iter() {
            let span = event_log::FinalizingTaskKind { task_kind: tk }.start();
            runner_thread.task_definitions[&tk]
                .write()
                .finalize(&mut root_conn, &mut rng)
                .with_context(|| {
                    format!("Finalizing task {:?}", TaskKind::try_from(tk).unwrap())
                })?;
            root_conn.flush()?;
            span.finish();
        }
        Ok(())
    });
    Ok(())
}
