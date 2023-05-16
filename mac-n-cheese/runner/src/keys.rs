use std::marker::PhantomData;

// We use the aes_gcm library because ring doesn't have an API to provide a separate tag on decrypt
use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
use mac_n_cheese_ir::compilation_format::TaskId;
use mac_n_cheese_party::{Party, WhichParty};
use rand::RngCore;
use vectoreyes::{Aes128, AesBlockCipher, AesBlockCipherDecrypt, U8x16};

#[repr(C)]
#[derive(bytemuck::Zeroable, bytemuck::Pod, Clone, Copy, Debug)]
pub struct TaskDataHeader {
    pub task_id: TaskId,
    pub length: u32,
    pub nonce: [u8; 16],
    pub tag: [u8; 16],
}

pub struct Keys<P: Party> {
    connection_index_key: Aes128,
    task_data_incoming_key: [u8; 32],
    task_data_outgoing_key: [u8; 32],
    challenges_key: Aes128Gcm,
    phantom: PhantomData<P>,
}
impl<P: Party> Keys<P> {
    pub fn from_base_key(base_key: &[u8; 32]) -> Self {
        let mut h = blake3::Hasher::new_derive_key("galois full fat mac n'cheese v1 2020/12/23");
        h.update(base_key);
        let mut material = h.finalize_xof();
        let mut connection_index_key = [0; 16];
        material.fill(&mut connection_index_key);
        let mut task_data_prover_key = [0; 32];
        material.fill(&mut task_data_prover_key);
        let mut task_data_verifier_key = [0; 32];
        material.fill(&mut task_data_verifier_key);
        let (task_data_incoming_key, task_data_outgoing_key) = match P::WHICH {
            WhichParty::Prover(_) => (task_data_verifier_key, task_data_prover_key),
            WhichParty::Verifier(_) => (task_data_prover_key, task_data_verifier_key),
        };
        let connection_index_key = Aes128::new_with_key(connection_index_key.into());
        let mut challenges_key = [0; 16];
        material.fill(&mut challenges_key);
        let challenges_key = Aes128Gcm::new(&challenges_key.into());
        Self {
            connection_index_key,
            task_data_incoming_key,
            task_data_outgoing_key,
            challenges_key,
            phantom: PhantomData,
        }
    }
    pub fn challenges_key(&self) -> &Aes128Gcm {
        &self.challenges_key
    }
    pub fn produce_connection_index_token(&self, idx: usize) -> U8x16 {
        self.connection_index_key
            .encrypt(U8x16::from((idx as u128).to_le_bytes()))
    }
    pub fn decode_connection_index_token(
        &self,
        token: U8x16,
        num_connections: usize,
    ) -> eyre::Result<usize> {
        let idx = u128::from_le_bytes(self.connection_index_key.decrypt(token).into());
        if idx < num_connections as u128 {
            Ok(idx as usize)
        } else {
            eyre::bail!("bad connection index token. Got {idx} with {num_connections} connections");
        }
    }
    fn task_key(
        &self,
        base_key: &[u8; 32],
        task_id: TaskId,
        length: u32,
    ) -> (TaskDataHeader, Aes128Gcm) {
        // We use this nonce to ensure that we don't re-use a key with AES-GCM.
        let mut nonce = [0; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let tdh = TaskDataHeader {
            task_id,
            length,
            nonce,
            tag: [0; 16],
        };
        let key = blake3::keyed_hash(base_key, bytemuck::bytes_of(&tdh));
        (
            tdh,
            Aes128Gcm::new_from_slice(&key.as_bytes()[0..16]).unwrap(),
        )
    }
    pub fn encrypt_outgoing(&self, task_id: TaskId, payload: &mut [u8]) -> TaskDataHeader {
        let (mut tdh, key) = self.task_key(
            &self.task_data_outgoing_key,
            task_id,
            u32::try_from(payload.len()).unwrap(),
        );
        let tag = key
            .encrypt_in_place_detached(&Default::default(), bytemuck::bytes_of(&tdh), payload)
            .unwrap();
        tdh.tag = tag.into();
        tdh
    }
    pub fn decrypt_incoming(
        &self,
        mut tdh: TaskDataHeader,
        payload: &mut [u8],
    ) -> eyre::Result<()> {
        let tag = aes_gcm::Tag::from(tdh.tag);
        tdh.tag = Default::default();
        let key = blake3::keyed_hash(&self.task_data_incoming_key, bytemuck::bytes_of(&tdh));
        let key = Aes128Gcm::new_from_slice(&key.as_bytes()[0..16]).unwrap();
        if key
            .decrypt_in_place_detached(&Default::default(), bytemuck::bytes_of(&tdh), payload, &tag)
            .is_err()
        {
            eyre::bail!("Failed to decrypt {tdh:?}");
        }
        Ok(())
    }
}

#[test]
fn test_task_encryption() {
    use mac_n_cheese_party::{Prover, Verifier};
    let key = [45; 32];
    let pk: Keys<Prover> = Keys::from_base_key(&key);
    let pv: Keys<Verifier> = Keys::from_base_key(&key);
    let original_buffer = [1, 2, 3, 4];
    let mut buf = original_buffer;
    let tdh = pk.encrypt_outgoing(2, &mut buf);
    pv.decrypt_incoming(tdh, &mut buf).unwrap();
    assert_eq!(buf, original_buffer);
    let mut buf = original_buffer;
    let tdh = pv.encrypt_outgoing(2, &mut buf);
    pk.decrypt_incoming(tdh, &mut buf).unwrap();
    assert_eq!(buf, original_buffer);
}
