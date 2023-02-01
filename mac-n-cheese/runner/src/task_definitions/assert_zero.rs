use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;

use mac_n_cheese_ir::compilation_format::wire_format::AssertZeroPrototypeWireFormat;
use mac_n_cheese_party::Party;
use mac_n_cheese_vole::mac::Mac;
use mac_n_cheese_vole::mac::MacTypes;
use parking_lot::Mutex;
use scuttlebutt::serialization::CanonicalSerialize;
use vectoreyes::SimdBase;
use vectoreyes::U8x32;

use crate::task_framework::{NoContinuation, TaskDefinition};

pub struct AssertZeroTask<P: Party, T: MacTypes> {
    hash_outputs: Vec<Mutex<U8x32>>,
    phantom: PhantomData<(P, T)>,
}

impl<P: Party, T: MacTypes> TaskDefinition<P> for AssertZeroTask<P, T> {
    const NEEDS_CHALLENGE: bool = false;

    fn global_vole_support_needed() -> crate::task_framework::GlobalVolesNeeded {
        Default::default()
    }

    fn initialize(
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut scuttlebutt::AesRng,
        _vc: crate::base_vole::VoleContexts<P>,
        num_runner_threads: usize,
    ) -> eyre::Result<Self> {
        Ok(Self {
            hash_outputs: Vec::from_iter(
                std::iter::repeat_with(Default::default).take(num_runner_threads),
            ),
            phantom: PhantomData,
        })
    }

    type TaskContinuation = NoContinuation;

    fn finalize(
        mut self,
        c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut scuttlebutt::AesRng,
    ) -> eyre::Result<()> {
        let mut acu = U8x32::ZERO;
        for out in self.hash_outputs.iter_mut() {
            acu ^= *out.get_mut();
        }
        match P::WHICH {
            mac_n_cheese_party::WhichParty::Prover(_) => c.write_all(bytemuck::bytes_of(&acu))?,
            mac_n_cheese_party::WhichParty::Verifier(_) => {
                let mut got = U8x32::ZERO;
                c.read_exact(bytemuck::bytes_of_mut(&mut got))?;
                eyre::ensure!(got == acu, "Assert zero hash mismatch.");
            }
        }
        Ok(())
    }

    fn start_task(
        &self,
        ctx: &mut crate::task_framework::TaskContext,
        input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        // TODO: try using a larger size to update
        let mut hash_key = [0; 32];
        hash_key[0..4].copy_from_slice(&ctx.task_id.to_le_bytes());
        let mut h = blake3::Hasher::new_keyed(&hash_key);
        let out = input.simple_wire_task::<1, 0, Mac<P, T>, _>(
            ctx,
            AssertZeroPrototypeWireFormat::default(),
            |[(mac, ())]| {
                let fe = match P::WHICH {
                    mac_n_cheese_party::WhichParty::Prover(e) => mac.beta().into_inner(e),
                    mac_n_cheese_party::WhichParty::Verifier(e) => mac.tag(e),
                };
                h.update(&fe.to_bytes());
                Ok([])
            },
        )?;
        let hash_output = U8x32::from(*h.finalize().as_bytes());
        *self.hash_outputs[ctx.thread_id].lock() ^= hash_output;
        Ok(out)
    }

    fn continue_task(
        &self,
        _tc: Box<Self::TaskContinuation>,
        _ctx: &mut crate::task_framework::TaskContext,
        _input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> eyre::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        unreachable!()
    }
}
