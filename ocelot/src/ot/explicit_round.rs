//! This is an implementation of the KOS oblivious transfer protocol, written so that each stage
//! and round of the protocol is written out as an explicit function. That is, all steps of this
//! implementation of the protocol involve pure computation, and the caller must handle all network
//! I/O.

use crate::Error;
use keyed_arena::{AllocationKey, BorrowedAllocation, KeyedArena};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, AesRng, Block, AES_HASH};
use std::convert::TryInto;
use vectoreyes::{array_utils::ArrayUnrolledExt, Aes128EncryptOnly, AesBlockCipher, U64x2, U8x16};

// TODO: alsz and kos should be based on this file?

const NROWS: usize = 128;

/// Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
/// extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).
struct AlszSender {
    /// These are the choices that we made in the underlying OT.
    s: u128,
    /// The results of the OT, after AES key expansion has been applied. There are 128 of these.
    rngs: Vec<Aes128EncryptOnly>,
}

fn fill_rng_with_selector(aes: &Aes128EncryptOnly, selector: u64, mut dst: &mut [u8]) {
    let mut ctr = 0;
    while !dst.is_empty() {
        let blocks = <[U8x16; Aes128EncryptOnly::BLOCK_COUNT_HINT]>::array_generate(
            #[inline(always)]
            |_| {
                let x = ctr;
                ctr += 1;
                U8x16::from(U64x2::from([selector, x]))
            },
        );
        let blocks: [U8x16; Aes128EncryptOnly::BLOCK_COUNT_HINT] = aes.encrypt_many(blocks);
        let bytes: [u8; Aes128EncryptOnly::BLOCK_COUNT_HINT * 16] = bytemuck::cast(blocks);
        let to_take = bytes.len().min(dst.len());
        dst[0..to_take].copy_from_slice(&bytes[0..to_take]);
        dst = &mut dst[to_take..];
    }
}

impl AlszSender {
    pub(super) fn init<
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
        BaseOtReceiver: crate::ot::Receiver<Msg = Block>,
    >(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let s: u128 = rng.gen();
        let mut ot = BaseOtReceiver::init(channel, rng)?;
        // We need to make a vector of bools in order to use the BaseOt API.
        let mut s_bit_vec = Vec::with_capacity(128);
        for i in 0..128 {
            s_bit_vec.push(((s >> i) & 1) != 0);
        }
        let seeds = ot.receive(channel, &s_bit_vec, rng)?;
        let rngs = seeds
            .into_iter()
            .map(|seed| Aes128EncryptOnly::new_with_key(seed.0))
            .collect();
        Ok(AlszSender { s, rngs })
    }
    const fn send_setup_input_bytes(m: usize) -> usize {
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let u_len = ncols / 8;
        u_len * 128
    }
    pub(super) fn send_setup<'a>(
        &self,
        arena: &'a KeyedArena,
        m: usize,
        selector: u64,
        mut incoming_bytes: &[u8],
    ) -> Result<BorrowedAllocation<'a, u8>, Error> {
        const NROWS: usize = 128;
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut qs = arena.alloc_slice_fill_with(NROWS * ncols / 8, |_| 0);
        let u_len = ncols / 8;
        for (j, aes) in self.rngs.iter().enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let q = &mut qs[range];
            if incoming_bytes.len() < u_len {
                return Err(Error::Other(format!(
                    "{} bytes were need for AlszSender::send_setup, but only {} remain",
                    u_len,
                    incoming_bytes.len()
                )));
            }
            let u = &incoming_bytes[0..u_len];
            incoming_bytes = &incoming_bytes[u_len..];
            fill_rng_with_selector(aes, selector, q);
            let b = ((self.s >> j) & 1) != 0;
            // TODO: constant-time
            if b {
                scuttlebutt::utils::xor_inplace(q, u);
            }
        }
        if !incoming_bytes.is_empty() {
            return Err(Error::Other(format!(
                "{} extra bytes were given to AlszSender::send_setup",
                incoming_bytes.len()
            )));
        }
        let mut dst = arena.alloc_slice_fill_with(qs.len(), |_| 0);
        crate::utils::transpose_pre_allocated(&qs, &mut dst, NROWS, ncols);
        Ok(dst)
    }
}

/// Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
/// extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).
struct AlszReceiver {
    /// AES key expansion applied to the 128 pairs of 128-bit seeds.
    rngs: Vec<(Aes128EncryptOnly, Aes128EncryptOnly)>,
}
impl AlszReceiver {
    pub(super) fn init<
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
        BaseOtSender: crate::ot::Sender<Msg = Block>,
    >(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = BaseOtSender::init(channel, rng)?;
        let mut seeds = Vec::with_capacity(128);
        for _ in 0..128 {
            let a = rng.gen::<Block>();
            let b = rng.gen::<Block>();
            seeds.push((a, b));
        }
        ot.send(channel, &seeds, rng)?;
        Ok(AlszReceiver {
            rngs: seeds
                .into_iter()
                .map(|(a, b)| {
                    (
                        Aes128EncryptOnly::new_with_key(a.0),
                        Aes128EncryptOnly::new_with_key(b.0),
                    )
                })
                .collect(),
        })
    }
    pub(super) fn receive_setup<'a>(
        &self,
        arena: &'a KeyedArena,
        r: &[u8],
        m: usize,
        mut outgoing_bytes: &mut [u8],
        selector: u64,
    ) -> Result<BorrowedAllocation<'a, u8>, Error> {
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut ts = arena.alloc_slice_fill_with(NROWS * ncols / 8, |_| 0);
        let g_len = ncols / 8;
        for (j, (rng0, rng1)) in self.rngs.iter().enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let t = &mut ts[range];
            if outgoing_bytes.len() < g_len {
                return Err(Error::Other(format!(
                    "{} bytes were need for AlszReceiver::receive_setup(), but only {} remain",
                    g_len,
                    outgoing_bytes.len()
                )));
            }
            let (g, remaining) = outgoing_bytes.split_at_mut(g_len);
            outgoing_bytes = remaining;
            fill_rng_with_selector(rng0, selector, t);
            fill_rng_with_selector(rng1, selector, g);
            scuttlebutt::utils::xor_inplace(g, t);
            scuttlebutt::utils::xor_inplace(g, r);
        }
        if !outgoing_bytes.is_empty() {
            return Err(Error::Other(format!(
                "{} extra bytes were given to AlszReceiver::receive_setup",
                outgoing_bytes.len()
            )));
        }
        let mut dst = arena.alloc_slice_fill_with(ts.len(), |_| 0);
        crate::utils::transpose_pre_allocated(&ts, &mut dst, NROWS, ncols);
        Ok(dst)
    }
}

// The statistical security parameter.
const SSP: usize = 40;

/// Implementation of the Keller-Orsini-Scholl oblivious transfer extension
/// protocol (cf. <https://eprint.iacr.org/2015/546>).
pub struct KosSender {
    alsz: AlszSender,
}
impl KosSender {
    /// Initialize the KOS OT protocol on the provided channel.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(KosSender {
            alsz: AlszSender::init::<_, _, super::ChouOrlandiReceiver>(channel, rng)?,
        })
    }

    /// How many incoming bytes is this stage expecting, for the given `num_inputs`
    pub const fn send_incoming_bytes(num_inputs: usize) -> usize {
        let m = if num_inputs % 8 != 0 {
            num_inputs + (8 - num_inputs % 8)
        } else {
            num_inputs
        };
        let ncols = m + 128 + SSP;
        let alsz_bytes = AlszSender::send_setup_input_bytes(ncols);
        alsz_bytes + 32 /* cointoss commitment */
    }
    /// How many incoming bytes will this stage emit expecting, for the given `num_inputs`
    pub const fn send_outgoing_bytes(num_inputs: usize) -> usize {
        16 /* cointoss random */ + 32 * num_inputs
    }

    /// Start an OT.
    ///
    /// The `incoming_bytes` should've been populated with data sent by the KosReceiver.
    /// `outgoing_bytes` will be populated with the outgoing data to send to the `KosReceiver`. The
    /// `selector` must be consistent between the sender and receiver and MUST NOT BE REPEATED
    /// for the same `init` step. Because `selector` is only 64-bits, it's too small to be randomly
    /// selected (safely) and it's recommended that some sort of monotonic counter be used instead.
    ///
    /// The inputs will be sent _before_ it's been shown that the receiver wasn't cheating.
    /// This might not be secure for all applications.
    pub fn send(
        &self,
        arena: &KeyedArena,
        selector: u64,
        inputs: &[(Block, Block)],
        rng: &mut (impl Rng + CryptoRng),
        mut incoming_bytes: &[u8],
        mut outgoing_bytes: &mut [u8],
    ) -> Result<KosSenderStage2, Error> {
        let num_inputs = inputs.len();
        let m = if num_inputs % 8 != 0 {
            num_inputs + (8 - num_inputs % 8)
        } else {
            num_inputs
        };
        if incoming_bytes.len() != Self::send_incoming_bytes(num_inputs) {
            return Err(Error::Other(format!(
                "KosSender::send unexpected incoming_bytes length {}",
                incoming_bytes.len()
            )));
        }
        if outgoing_bytes.len() != Self::send_outgoing_bytes(num_inputs) {
            return Err(Error::Other(format!(
                "KosSender::send unexpected outgoing length {}",
                outgoing_bytes.len()
            )));
        }
        let ncols = m + 128 + SSP;
        let alsz_bytes = AlszSender::send_setup_input_bytes(ncols);
        let qs = self
            .alsz
            .send_setup(arena, ncols, selector, &incoming_bytes[0..alsz_bytes])?;
        incoming_bytes = &incoming_bytes[alsz_bytes..];
        let mut incoming_commitment = [0; 32];
        incoming_commitment.copy_from_slice(incoming_bytes);
        let mut our_seed = [0; 16];
        rng.fill_bytes(&mut our_seed);
        outgoing_bytes[0..16].copy_from_slice(&our_seed);
        outgoing_bytes = &mut outgoing_bytes[16..];
        debug_assert!(inputs.len() * 16 <= qs.len());
        for (j, (input, q)) in inputs.iter().zip(qs.chunks_exact(16)).enumerate() {
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let y0 = AES_HASH.tccr_hash(Block::from(j as u128), q) ^ input.0;
            let q = q ^ Block::from(self.alsz.s);
            let y1 = AES_HASH.tccr_hash(Block::from(j as u128), q) ^ input.1;
            outgoing_bytes[0..16].copy_from_slice(bytemuck::bytes_of(&y0));
            outgoing_bytes[16..32].copy_from_slice(bytemuck::bytes_of(&y1));
            outgoing_bytes = &mut outgoing_bytes[32..];
        }
        debug_assert!(outgoing_bytes.is_empty());
        Ok(KosSenderStage2 {
            incoming_commitment,
            our_seed,
            qs: qs.key(),
            ncols,
            ot_s: Block::from(self.alsz.s),
        })
    }
}
/// The second communicattion round of the `KosSender`
pub struct KosSenderStage2 {
    incoming_commitment: [u8; 32],
    our_seed: [u8; 16],
    qs: AllocationKey<u8>,
    ncols: usize,
    ot_s: Block,
}
impl KosSenderStage2 {
    /// How many incoming bytes is this round expecting?
    pub const INCOMING_BYTES: usize = 16 * 4; // cointoss reveal, x, t0, t1
    /// Execute round two of the `KosSender` protocol. `incoming` contains the incoming bytes sent
    /// from the receiver. `arena` must be the same arena passed to the `send` function.
    pub fn stage2(self, arena: &KeyedArena, incoming: &[u8]) -> Result<(), Error> {
        if incoming.len() != Self::INCOMING_BYTES {
            return Err(Error::Other(format!(
                "Unexpected incoming bytes to KosSenderStage2: {}",
                incoming.len()
            )));
        }
        let incoming_seed: [u8; 16] = incoming[0..16].try_into().unwrap();
        let x: [u8; 16] = incoming[16..32].try_into().unwrap();
        let t0: [u8; 16] = incoming[32..48].try_into().unwrap();
        let t1: [u8; 16] = incoming[48..64].try_into().unwrap();
        let x = Block::from(x);
        let t0 = Block::from(t0);
        let t1 = Block::from(t1);
        // This isn't doing a constant-time comparison, and that's okay.
        // The commitment that the other party gave us isn't private to them (they gave it to us).
        if blake3::hash(&incoming_seed).as_bytes() != self.incoming_commitment.as_slice() {
            return Err(Error::Other(
                "KosSenderStage2 reciever lied in cointoss".to_string(),
            ));
        }
        let mut rng = AesRng::from_seed(Block::from(self.our_seed) ^ Block::from(incoming_seed));
        let mut check = (Block::default(), Block::default());
        let mut chi = Block::default();
        let qs = arena.borrow_mut(self.qs);
        debug_assert_eq!(qs.len(), self.ncols * 16);
        for q in qs.chunks_exact(16) {
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            rng.fill_bytes(chi.as_mut());
            let tmp = q.clmul(chi);
            check = crate::utils::xor_two_blocks(&check, &tmp);
        }
        let tmp = x.clmul(self.ot_s);
        let check = crate::utils::xor_two_blocks(&check, &tmp);
        if check != (t0, t1) {
            return Err(Error::Other(
                "KosSenderStage2 consistency check failed".to_string(),
            ));
        }
        Ok(())
    }
}

/// Implementation of the Keller-Orsini-Scholl oblivious transfer extension
/// protocol (cf. <https://eprint.iacr.org/2015/546>).
pub struct KosReceiver {
    alsz: AlszReceiver,
}
impl KosReceiver {
    /// Initialize a fresh receiver state.
    pub fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        Ok(KosReceiver {
            alsz: AlszReceiver::init::<_, _, super::ChouOrlandiSender>(channel, rng)?,
        })
    }

    /// How many outgoing bytes will be sent from the receiver in the first stage?
    pub const fn receive_outgoing_bytes(nchoices: usize) -> usize {
        KosSender::send_incoming_bytes(nchoices)
    }

    /// Setup a receive operation. See [`KosSender::send`] for more info.
    pub fn receive<RNG: CryptoRng + Rng>(
        &self,
        arena: &KeyedArena,
        selector: u64,
        choices: BorrowedAllocation<bool>,
        rng: &mut RNG,
        mut outgoing_bytes: &mut [u8],
    ) -> Result<KosReceiverStage2, Error> {
        if outgoing_bytes.len() != Self::receive_outgoing_bytes(choices.len()) {
            return Err(Error::Other(format!(
                "KosReceiver::receive unexpected outgoing length {}",
                outgoing_bytes.len()
            )));
        }
        let m = choices.len();
        let m = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let m_ = m + 128 + SSP;
        //let mut r = crate::utils::boolvec_to_u8vec(&choices);
        let mut r = arena.alloc_slice_fill_with(
            (choices.len() / 8) + (if choices.len() % 8 == 0 { 0 } else { 1 }) + ((m_ - m) / 8),
            |_| 0,
        );
        for (i, b) in choices.iter().enumerate() {
            r[i / 8] |= (*b as u8) << (i % 8);
        }
        let r_len = r.len();
        rng.fill_bytes(&mut r[r_len - ((m_ - m) / 8)..]);
        let alsz_bytes = AlszSender::send_setup_input_bytes(m_);
        let ts =
            self.alsz
                .receive_setup(arena, &r, m_, &mut outgoing_bytes[0..alsz_bytes], selector)?;
        outgoing_bytes = &mut outgoing_bytes[alsz_bytes..];
        let our_seed = rng.gen::<Block>();
        outgoing_bytes.copy_from_slice(
            blake3::hash(bytemuck::bytes_of(&our_seed))
                .as_bytes()
                .as_slice(),
        );
        Ok(KosReceiverStage2 {
            choices: choices.key(),
            ts: ts.key(),
            our_seed,
            r_: arena
                .alloc_slice_fill_with(r.len() * 8, |i| {
                    let which_byte = i / 8;
                    let which_bit = i % 8;
                    (r[which_byte] & (1 << which_bit)) != 0
                })
                .key(),
        })
    }
}

/// The state for the second round of the Kos receiver
pub struct KosReceiverStage2 {
    our_seed: Block,
    choices: AllocationKey<bool>,
    ts: AllocationKey<u8>,
    r_: AllocationKey<bool>,
}
impl KosReceiverStage2 {
    /// How many bytes will the receiver send this round?
    pub const OUTGOING_BYTES: usize = KosSenderStage2::INCOMING_BYTES;
    /// How many bytes will the reciever expect to receive this round?
    pub fn incoming_bytes(nchoices: usize) -> usize {
        KosSender::send_outgoing_bytes(nchoices)
    }
    /// Execute this round of the protocol.
    pub fn stage2<'a>(
        self,
        arena: &'a KeyedArena,
        mut incoming: &[u8],
        outgoing: &mut [u8],
    ) -> Result<BorrowedAllocation<'a, Block>, Error> {
        let choices = arena.borrow_mut(self.choices);
        let ts = arena.borrow_mut(self.ts);
        let r_ = arena.borrow_mut(self.r_);
        if outgoing.len() != Self::OUTGOING_BYTES {
            return Err(Error::Other(format!(
                "KosReceiverStage2::stage2 unexpected outgoing length {}",
                outgoing.len()
            )));
        }
        if incoming.len() != Self::incoming_bytes(choices.len()) {
            return Err(Error::Other(format!(
                "KosReceiverStage2::stage2 unexpected incoming length {}",
                incoming.len()
            )));
        }
        let their_seed: [u8; 16] = incoming[0..16].try_into().unwrap();
        incoming = &incoming[16..];
        let mut rng = AesRng::from_seed(Block::from(their_seed) ^ self.our_seed);
        let out = arena.alloc_slice_fill_with(choices.len(), |j| {
            let b = choices[j];
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y0: [u8; 16] = incoming[0..16].try_into().unwrap();
            let y1: [u8; 16] = incoming[16..32].try_into().unwrap();
            let y0 = Block::from(y0);
            let y1 = Block::from(y1);
            incoming = &incoming[32..];
            // TODO: constant-time
            let y = if b { y1 } else { y0 };

            y ^ AES_HASH.tccr_hash(Block::from(j as u128), Block::from(t))
        });
        debug_assert!(incoming.is_empty());
        let mut x = Block::default();
        let mut t = (Block::default(), Block::default());
        let mut chi = Block::default();
        for (j, xj) in r_.iter().copied().enumerate() {
            let tj = &ts[j * 16..(j + 1) * 16];
            let tj: [u8; 16] = tj.try_into().unwrap();
            let tj = Block::from(tj);
            rng.fill_bytes(chi.as_mut());
            x ^= if xj { chi } else { Block::default() };
            let tmp = tj.clmul(chi);
            t = crate::utils::xor_two_blocks(&t, &tmp);
        }
        let outgoing_blocks = [self.our_seed, x, t.0, t.1];
        debug_assert_eq!(outgoing.len(), outgoing_blocks.len() * 16);
        for (dst, src) in outgoing.chunks_exact_mut(16).zip(outgoing_blocks.iter()) {
            dst.copy_from_slice(bytemuck::bytes_of(src));
        }
        Ok(out)
    }
}

#[test]
fn test_kos_ot() {
    use scuttlebutt::Channel;
    use std::io::{BufReader, BufWriter};
    use std::os::unix::net::UnixStream;
    let (a, b) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        let mut rng = AesRng::from_seed(Block::from(456));
        let mut channel = Channel::new(
            BufReader::new(a.try_clone().unwrap()),
            BufWriter::new(a.try_clone().unwrap()),
        );
        let out = KosSender::init(&mut channel, &mut rng).unwrap();
        channel.flush().unwrap();
        out
    });
    let receiver = {
        let mut rng = AesRng::from_seed(Block::from(864));
        let mut channel = Channel::new(
            BufReader::new(b.try_clone().unwrap()),
            BufWriter::new(b.try_clone().unwrap()),
        );
        let out = KosReceiver::init(&mut channel, &mut rng).unwrap();
        channel.flush().unwrap();
        out
    };
    let sender = sender.join().unwrap();
    let arena = KeyedArena::with_capacity(0, 0);
    let run_test = move |inputs: Vec<(Block, Block)>, choices: Vec<bool>, selector: u64| {
        assert_eq!(inputs.len(), choices.len());
        let mut receiver_initial_outgoing =
            vec![0; KosReceiver::receive_outgoing_bytes(choices.len())];
        let receiver_stage2 = receiver
            .receive(
                &arena,
                selector,
                arena.alloc_slice_fill_with(choices.len(), |i| choices[i]),
                &mut AesRng::from_seed(Block::from(12)),
                &mut receiver_initial_outgoing,
            )
            .unwrap();
        let mut sender_outgoing_bytes = vec![0; KosSender::send_outgoing_bytes(inputs.len())];
        let sender_stage2 = sender
            .send(
                &arena,
                selector,
                &inputs,
                &mut AesRng::from_seed(Block::from(85412)),
                &receiver_initial_outgoing,
                &mut sender_outgoing_bytes,
            )
            .unwrap();
        let mut receiver_final_outgoing = vec![0; KosReceiverStage2::OUTGOING_BYTES];
        let received_output = receiver_stage2
            .stage2(&arena, &sender_outgoing_bytes, &mut receiver_final_outgoing)
            .unwrap();
        sender_stage2
            .stage2(&arena, &receiver_final_outgoing)
            .unwrap();
        assert_eq!(received_output.len(), inputs.len());
        for (ro, (choice, inputs)) in received_output
            .iter()
            .zip(choices.iter().zip(inputs.iter()))
        {
            let expected = if *choice { inputs.1 } else { inputs.0 };
            assert_eq!(ro, &expected);
        }
    };
    run_test(vec![], vec![], 100000000);
    run_test(
        vec![(Block::from(1), Block::from(2))],
        vec![true],
        100000001,
    );
    run_test(
        vec![(Block::from(1), Block::from(2))],
        vec![false],
        100000002,
    );
    for (i, len) in [32, 33, 65, 65, 5873, 8582].iter().copied().enumerate() {
        let mut rng = AesRng::from_seed(Block::from(u128::from((i as u64) + 25903468354)));
        let choices = (0..len).map(|_| rng.gen::<bool>()).collect();
        let inputs = (0..len)
            .map(|_| (rng.gen::<Block>(), rng.gen::<Block>()))
            .collect();
        run_test(inputs, choices, i as u64);
    }
}
