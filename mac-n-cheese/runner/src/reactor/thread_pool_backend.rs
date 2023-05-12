use std::{
    fs::File,
    hash::BuildHasherDefault,
    io::{Read, Write},
    net::TcpStream,
    os::unix::prelude::FileExt,
    sync::Arc,
    time::Duration,
};

use aes_gcm::{AeadCore, AeadInPlace, Aes128Gcm, Nonce};

use bytemuck::Zeroable;
use generic_array::GenericArray;
use mac_n_cheese_ir::compilation_format::{
    fb::DataChunkAddress, Manifest, PrivateDataAddress, TaskId, TaskPriority,
};
use mac_n_cheese_party::{either::PartyEither, private::ProverPrivate, Party, WhichParty};
use moka::sync::SegmentedCache;
use parking_lot::Mutex;
use rand::RngCore;
use rustc_hash::FxHashMap;

use crate::{
    alloc::{BytesFromDisk, OwnedAlignedBytes},
    bounded_queue::Queue,
    event_log,
    keys::{Keys, TaskDataHeader},
    runner::ReactorCallback,
    task_framework::Challenge,
    task_queue::{
        RunningTaskId, TaskQueue, TaskQueueEntry, QUEUE_NAME_THREAD_POOL_FILE_READ_REQUEST,
    },
    thread_spawner::ThreadSpawner,
};

use super::{Reactor, ReactorRequest, ReactorResponse, RunQueue};

// TODO: is this too low?
// TODO: with the new backpressure methodology, is this needed?
const OUTGOING_DATA_QUEUE_CAPACITY: usize = 512;
const TIME_TO_IDLE_DISK_CACHE: Duration = Duration::from_millis(2500);
const NUM_DISK_THREADS: usize = 8;

#[derive(Debug, Clone, Copy)]
struct PublicReadRequest {
    chunk: DataChunkAddress,
}
impl std::cmp::Eq for PublicReadRequest {}
impl std::cmp::PartialEq for PublicReadRequest {
    fn eq(&self, other: &Self) -> bool {
        (&self.chunk.0) == (&other.chunk.0)
    }
}
impl std::hash::Hash for PublicReadRequest {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.chunk.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FileReadRequest {
    Public(PublicReadRequest),
    Private(PrivateDataAddress),
}

struct OutgoingData {
    task_id: TaskId,
    payload: OwnedAlignedBytes,
}

struct IncomingRequest<P: Party> {
    priority: TaskPriority,
    request: ReactorRequest,
    cb: ReactorCallback<P>,
}

#[derive(Default)]
struct IncomingSlotData<P: Party> {
    request: Option<IncomingRequest<P>>,
    response: ReactorResponse,
}

#[derive(Default)]
struct IncomingSlot<P: Party> {
    // None means that the task was launched.
    data: Mutex<Option<IncomingSlotData<P>>>,
}
const INCOMING_SLOTS_DEFAULT_CAPACITY: usize = 8192;

struct ThreadPoolReactor<P: Party> {
    run_queue: RunQueue<P>,
    // It's okay for this to be a task queue since it occurs _before_ task run
    file_read_requests: TaskQueue<FileReadRequest>,
    // This SHOULD NOT be in priority order. If we did that, then outgoing data would not be sent
    // in topological order.
    outgoing_data: Queue<OutgoingData>,
    manifest: Arc<Manifest>,
    privates_file: ProverPrivate<P, File>,
    keys: Keys<P>,
    incoming_slots: Mutex<FxHashMap<TaskId, Arc<IncomingSlot<P>>>>,
    // This should be in topological order for the same reason that outgoing data should be.
    outgoing_challenges: PartyEither<P, (), Queue<(TaskId, Challenge)>>,
    // We should only cache public data. Privates won't be reused.
    disk_cache: SegmentedCache<FileReadRequest, BytesFromDisk>,
}

impl<P: Party> ThreadPoolReactor<P> {
    fn get_incoming_slot(&self, task_id: TaskId) -> (Arc<IncomingSlot<P>>, bool) {
        let mut guard = event_log::IncomingSlotsLock.lock(&self.incoming_slots);
        let entry = guard.entry(task_id);
        let fresh = matches!(&entry, std::collections::hash_map::Entry::Vacant(_));
        (
            entry
                .or_insert_with(|| {
                    Arc::new(IncomingSlot {
                        data: Mutex::new(Some(IncomingSlotData::default())),
                    })
                })
                .clone(),
            fresh,
        )
    }
    fn update_incoming_slot(
        &self,
        task_id: TaskId,
        f: impl for<'a> FnOnce(&'a mut IncomingSlotData<P>),
    ) {
        let (incoming_slot, fresh) = self.get_incoming_slot(task_id);
        let mut guard = event_log::IncomingSlotLock { task_id, fresh }.lock(&incoming_slot.data);
        let data = guard.as_mut().expect("task was not already launched");
        f(data);
        self.maybe_launch_incoming(task_id, &mut guard);
    }

    fn outgoing_thread(&self, mut conn: TcpStream, connection_idx: u64) -> eyre::Result<()> {
        while let Some(mut data) = self.outgoing_data.dequeue() {
            let span = event_log::EncryptingOutgoingData {
                task_id: data.task_id,
                length: data.payload.len() as u64,
            }
            .start();
            let tdh = self.keys.encrypt_outgoing(data.task_id, &mut data.payload);
            span.finish();
            let span = event_log::SendingOutgoingData {
                task_id: data.task_id,
                length: data.payload.len() as u64,
                connection_idx,
            }
            .start();
            // TODO: do a vectored send
            conn.write_all(bytemuck::bytes_of(&tdh))?;
            conn.write_all(&data.payload)?;
            conn.flush()?; // shouldn't actually do anything
            span.finish();
        }
        Ok(())
    }
    fn incoming_thread(&self, mut conn: TcpStream, connection_idx: u64) -> eyre::Result<()> {
        loop {
            let mut tdh = TaskDataHeader::zeroed();
            if conn.read(&mut bytemuck::bytes_of_mut(&mut tdh)[0..1])? == 0 {
                return Ok(());
            }
            conn.read_exact(&mut bytemuck::bytes_of_mut(&mut tdh)[1..])?;
            let mut buf = OwnedAlignedBytes::zeroed(tdh.length as usize);
            conn.read_exact(&mut buf)?;
            self.keys.decrypt_incoming(tdh, &mut buf)?;
            event_log::ReadIncomingData {
                task_id: tdh.task_id,
                length: tdh.length,
                connection_idx,
            }
            .submit();
            self.update_incoming_slot(tdh.task_id, move |data| {
                debug_assert!(data.response.incoming_bytes.is_none());
                data.response.incoming_bytes = Some(buf);
            });
        }
    }
    fn challenge_thread(&self, mut conn: TcpStream) -> eyre::Result<()> {
        // TODO: enable nagle's algorithm and disable delayed ack?
        #[repr(C)]
        #[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
        struct ChallengeData {
            task_id: TaskId,
            challenge: Challenge,
        }
        // We use a simple AES-GCM with an incrementing nonce. Our data is small enough, and we
        // have a small enough (under 2^32) number of tasks, that we should never need to rekey.
        match P::WHICH {
            WhichParty::Prover(_) => {
                let mut ctr = 0_u64;
                loop {
                    let mut buf = [0; std::mem::size_of::<ChallengeData>()
                        + std::mem::size_of::<aes_gcm::Tag>()];
                    if conn.read(&mut buf[0..1])? == 0 {
                        break;
                    }
                    conn.read_exact(&mut buf[1..])?;
                    let (data, tag) = buf.split_at_mut(std::mem::size_of::<ChallengeData>());
                    let mut nonce: Nonce<<Aes128Gcm as AeadCore>::NonceSize> = Default::default();
                    nonce[0..8].copy_from_slice(&ctr.to_le_bytes());
                    self.keys
                        .challenges_key()
                        .decrypt_in_place_detached(&nonce, &[], data, GenericArray::from_slice(tag))
                        .map_err(|_| eyre::eyre!("Error decrypting challenge"))?;
                    let mut cd = ChallengeData::zeroed();
                    bytemuck::bytes_of_mut(&mut cd).copy_from_slice(data);
                    ctr += 1;
                    event_log::GotChallenge {
                        task_id: cd.task_id,
                    }
                    .submit();
                    self.update_incoming_slot(cd.task_id, |data| {
                        debug_assert!(data.response.challenge.is_none());
                        data.response.challenge = Some(cd.challenge);
                    });
                }
            }
            WhichParty::Verifier(e) => {
                let mut ctr = 0_u64;
                while let Some((id, challenge)) =
                    self.outgoing_challenges.as_ref().verifier_into(e).dequeue()
                {
                    let span = event_log::SendingChallenge { task_id: id }.start();
                    let cd = ChallengeData {
                        task_id: id,
                        challenge,
                    };
                    let mut buf = [0; std::mem::size_of::<ChallengeData>()
                        + std::mem::size_of::<aes_gcm::Tag>()];
                    let (data, tag_dst) = buf.split_at_mut(std::mem::size_of::<ChallengeData>());
                    data.copy_from_slice(bytemuck::bytes_of(&cd));
                    let mut nonce: Nonce<<Aes128Gcm as AeadCore>::NonceSize> = Default::default();
                    nonce[0..8].copy_from_slice(&ctr.to_le_bytes());
                    let tag = self
                        .keys
                        .challenges_key()
                        .encrypt_in_place_detached(&nonce, &[], data)
                        .unwrap();
                    tag_dst.copy_from_slice(&tag);
                    ctr += 1;
                    conn.write_all(&buf)?;
                    conn.flush()?; // shouldn't actually do anything
                    span.finish();
                }
            }
        }
        Ok(())
    }
    fn fulfill_read_request(&self, req: FileReadRequest) -> eyre::Result<BytesFromDisk> {
        match req {
            FileReadRequest::Public(req) => {
                let mut out = OwnedAlignedBytes::zeroed(usize::try_from(req.chunk.length())?);
                self.manifest.read_data_chunk(&req.chunk, &mut out)?;
                Ok(Arc::new(out))
            }
            FileReadRequest::Private(req) => {
                let mut out = OwnedAlignedBytes::zeroed(req.len as usize);
                match P::WHICH {
                    WhichParty::Prover(e) => self
                        .privates_file
                        .as_ref()
                        .into_inner(e)
                        .read_exact_at(&mut out, req.offset)?,
                    WhichParty::Verifier(_) => {
                        panic!("The verifier shouldn't be reading private data")
                    }
                }
                Ok(Arc::new(out))
            }
        }
    }
    fn disk_thread(&self) -> eyre::Result<()> {
        while let Some(job) = self.file_read_requests.blocking_dequeue() {
            let span = event_log::ReadingFromDisk {
                task_id: job.id.task_id,
                priority: job.id.priority,
                public_file: matches!(job.metadata, FileReadRequest::Public(_)),
            }
            .start();
            let out = match job.metadata {
                FileReadRequest::Public(_) => {
                    match self
                        .disk_cache
                        .try_get_with(job.metadata, || self.fulfill_read_request(job.metadata))
                    {
                        Ok(x) => x,
                        Err(e) => {
                            eprintln!("Error reading from disk {e:?}");
                            eyre::bail!("Error reading from disk")
                        }
                    }
                }
                FileReadRequest::Private(_) => self.fulfill_read_request(job.metadata)?,
            };
            self.update_incoming_slot(job.id.task_id, |data| {
                let dst = match job.metadata {
                    FileReadRequest::Public(_) => &mut data.response.task_data,
                    FileReadRequest::Private(_) => &mut data.response.private_data,
                };
                debug_assert!(dst.is_none());
                *dst = Some(out);
            });
            span.finish();
        }
        Ok(())
    }
    fn maybe_launch_incoming(&self, task_id: TaskId, slot: &mut Option<IncomingSlotData<P>>) {
        let data = slot.as_ref().unwrap();
        if let Some(req) = &data.request {
            if data.response.satisifies(&req.request) {
                event_log::IncomingSlotsLock
                    .lock(&self.incoming_slots)
                    .remove(&task_id);
                let data = std::mem::take(slot).unwrap();
                let IncomingRequest {
                    priority,
                    request: req,
                    cb,
                } = data.request.unwrap();
                let resp = data.response;
                debug_assert_eq!(req.want_private_data.is_some(), resp.private_data.is_some());
                debug_assert_eq!(req.want_task_data.is_some(), resp.task_data.is_some());
                debug_assert_eq!(req.want_incoming_network, resp.incoming_bytes.is_some());
                debug_assert_eq!(req.want_challenge, resp.challenge.is_some());
                self.run_queue.enqueue(TaskQueueEntry {
                    id: RunningTaskId { task_id, priority },
                    metadata: Box::new((resp, cb)),
                })
            }
        }
    }
}

impl<P: Party> Reactor<P> for ThreadPoolReactor<P> {
    fn send_outgoing(
        &self,
        task_id: RunningTaskId,
        payload: OwnedAlignedBytes,
    ) -> eyre::Result<()> {
        let task_id = task_id.task_id;
        let length = payload.len();
        let od = OutgoingData { task_id, payload };
        let span = event_log::EnqueuingOutgoingData {
            task_id,
            length: length as u64,
        }
        .start();
        self.outgoing_data.enqueue(od);
        span.finish();
        Ok(())
    }

    fn request(
        &self,
        task_id: RunningTaskId,
        req: ReactorRequest,
        cb: ReactorCallback<P>,
    ) -> eyre::Result<()> {
        // Request data from disk
        let new_task_data = if let Some(addr) = req.want_task_data {
            let frr = FileReadRequest::Public(PublicReadRequest { chunk: addr });
            if let Some(data) = self.disk_cache.get(&frr) {
                event_log::DiskCacheHitOnRequest {
                    task_id: task_id.task_id,
                    priority: task_id.priority,
                }
                .submit();
                Some(data)
            } else {
                self.file_read_requests.enqueue(TaskQueueEntry {
                    id: task_id,
                    metadata: frr,
                });
                None
            }
        } else {
            None
        };
        if let Some(addr) = req.want_private_data {
            // We don't cache private data requests
            self.file_read_requests.enqueue(TaskQueueEntry {
                id: task_id,
                metadata: FileReadRequest::Private(addr),
            });
        }
        // Request challenges
        let new_challenge = if req.want_challenge {
            match P::WHICH {
                WhichParty::Prover(_) => {
                    // There's nothing for the prover to do but sit and wait for a challenge to roll
                    // in.
                    None
                }
                WhichParty::Verifier(e) => {
                    let mut challenge: Challenge = Default::default();
                    rand::thread_rng().fill_bytes(&mut challenge);
                    self.outgoing_challenges
                        .as_ref()
                        .verifier_into(e)
                        .enqueue((task_id.task_id, challenge));
                    Some(challenge)
                }
            }
        } else {
            None
        };
        event_log::ProvidedReactorRequest {
            task_id: task_id.task_id,
            priority: task_id.priority,
        }
        .submit();
        self.update_incoming_slot(task_id.task_id, move |data| {
            debug_assert!(data.request.is_none());
            data.request = Some(IncomingRequest {
                priority: task_id.priority,
                request: req,
                cb,
            });
            debug_assert!(!(data.response.challenge.is_some() && new_challenge.is_some()));
            data.response.challenge = data.response.challenge.or(new_challenge);
            debug_assert!(!(data.response.task_data.is_some() && new_task_data.is_some()));
            // task_data might be set since we don't hold this lock when we enqueue the request to
            // load task data above.
            if data.response.task_data.is_none() {
                data.response.task_data = new_task_data;
            }
        });
        Ok(())
    }
    fn close(&self) {
        // Don't close run_queue. We just consume it.
        self.file_read_requests.close();
        self.outgoing_data.close();
        if let WhichParty::Verifier(e) = P::WHICH {
            self.outgoing_challenges.as_ref().verifier_into(e).close();
        }
    }
}

pub fn new_reactor<P: Party>(
    ts: &mut ThreadSpawner,
    circuit_manifest: Arc<Manifest>,
    private_data: ProverPrivate<P, File>,
    mut extra_connections: Vec<TcpStream>,
    run_queue: RunQueue<P>,
    keys: Keys<P>,
) -> eyre::Result<Arc<dyn Reactor<P>>> {
    let challenge_connection = extra_connections.pop().expect("at least two connections");
    assert!(!extra_connections.is_empty());
    let tpr: Arc<ThreadPoolReactor<P>> = Arc::new(ThreadPoolReactor {
        run_queue,
        file_read_requests: TaskQueue::new(QUEUE_NAME_THREAD_POOL_FILE_READ_REQUEST),
        outgoing_data: Queue::bounded(OUTGOING_DATA_QUEUE_CAPACITY),
        keys,
        incoming_slots: Mutex::new(FxHashMap::with_capacity_and_hasher(
            INCOMING_SLOTS_DEFAULT_CAPACITY,
            BuildHasherDefault::default(),
        )),
        outgoing_challenges: match P::WHICH {
            WhichParty::Prover(e) => PartyEither::prover_new(e, ()),
            WhichParty::Verifier(e) => PartyEither::verifier_new(e, Queue::unbounded(8192)),
        },
        disk_cache: moka::sync::SegmentedCache::builder(4)
            .thread_pool_enabled(true)
            .time_to_idle(TIME_TO_IDLE_DISK_CACHE)
            .build(),
        manifest: circuit_manifest,
        privates_file: private_data,
    });
    // Spin up the outgoing network threads.
    for (i, conn) in extra_connections.iter().enumerate() {
        let tpr = tpr.clone();
        let conn = conn.try_clone()?;
        ts.spawn(format!("Outgoing network thread {i}"), move || {
            tpr.outgoing_thread(conn, i as u64)
        });
    }
    for (i, conn) in extra_connections.into_iter().enumerate() {
        let tpr = tpr.clone();
        ts.spawn_daemon(format!("Incoming network thread {i}"), move || {
            tpr.incoming_thread(conn, i as u64)
        });
    }
    {
        let tpr = tpr.clone();
        ts.spawn("Challenge thread".to_string(), move || {
            tpr.challenge_thread(challenge_connection)
        });
    }
    for i in 0..NUM_DISK_THREADS {
        let tpr = tpr.clone();
        ts.spawn(format!("Disk reader thread {i}"), move || tpr.disk_thread());
    }
    Ok(tpr)
}
