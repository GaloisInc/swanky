use std::{net::TcpStream, sync::Arc};

use crate::{
    alloc::{BytesFromDisk, OwnedAlignedBytes},
    keys::Keys,
    runner::{ReactorCallback, RunQueue},
    task_framework::Challenge,
    task_queue::RunningTaskId,
    thread_spawner::ThreadSpawner,
};
use mac_n_cheese_ir::compilation_format::{fb::DataChunkAddress, Manifest, PrivateDataAddress};
use mac_n_cheese_party::{private::ProverPrivate, Party};
use std::fs::File;

#[derive(Clone, Copy, Default, Debug)]
pub struct ReactorRequest {
    pub want_challenge: bool,
    pub want_incoming_network: bool,
    pub want_task_data: Option<DataChunkAddress>,
    pub want_private_data: Option<PrivateDataAddress>,
}

#[derive(Default)]
pub struct ReactorResponse {
    pub challenge: Option<Challenge>,
    pub incoming_bytes: Option<OwnedAlignedBytes>,
    pub task_data: Option<BytesFromDisk>,
    pub private_data: Option<BytesFromDisk>,
}
impl ReactorResponse {
    pub fn satisifies(&self, req: &ReactorRequest) -> bool {
        let unsatisified = (req.want_challenge && self.challenge.is_none())
            || (req.want_incoming_network && self.incoming_bytes.is_none())
            || (req.want_task_data.is_some() && self.task_data.is_none())
            || (req.want_private_data.is_some() && self.private_data.is_none());
        !unsatisified
    }
}

pub trait Reactor<P: Party>: 'static + Send + Sync {
    // This may block
    // This must be sent in topological order
    fn send_outgoing(&self, task_id: RunningTaskId, payload: OwnedAlignedBytes)
        -> eyre::Result<()>;
    fn request(
        &self,
        task_id: RunningTaskId,
        req: ReactorRequest,
        cb: ReactorCallback<P>,
    ) -> eyre::Result<()>;
    fn close(&self);
}

pub fn new_reactor<P: Party>(
    ts: &mut ThreadSpawner,
    circuit_manifest: Arc<Manifest>,
    private_data: ProverPrivate<P, File>,
    extra_connections: Vec<TcpStream>,
    run_queue: RunQueue<P>,
    keys: Keys<P>,
) -> eyre::Result<Arc<dyn Reactor<P>>> {
    thread_pool_backend::new_reactor(
        ts,
        circuit_manifest,
        private_data,
        extra_connections,
        run_queue,
        keys,
    )
}

mod thread_pool_backend;
