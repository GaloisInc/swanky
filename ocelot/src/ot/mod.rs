//! Oblivious transfer traits + instantiations.
//!
//! This module provides traits for standard oblivious transfer (OT), correlated
//! OT, and random OT, alongside implementations of the following OT protocols:
//!
//! * `dummy`: a dummy and completely insecure OT for testing purposes.
//! * `naor_pinkas`: Naor-Pinkas semi-honest OT.
//! * `chou_orlandi`: Chou-Orlandi malicious OT.
//! * `alsz`: Asharov-Lindell-Schneider-Zohner semi-honest OT extension (+ correlated and random OT).
//! * `kos`: Keller-Orsini-Scholl malicious OT extension (+ correlated and random OT).
//!

pub mod alsz;
pub mod chou_orlandi;
pub mod dummy;
pub mod explicit_round;
pub mod kos;
pub mod kos_delta;
pub mod naor_pinkas;

use crate::errors::Error;
use rand::{CryptoRng, Rng};
use scuttlebutt::AbstractChannel;

/// Instantiation of the Chou-Orlandi OT sender.
pub type ChouOrlandiSender = chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub type ChouOrlandiReceiver = chou_orlandi::Receiver;
/// Instantiation of the dummy OT sender.
pub type DummySender = dummy::Sender;
/// Instantiation of the dummy OT receiver.
pub type DummyReceiver = dummy::Receiver;
/// Instantiation of the Naor-Pinkas OT sender.
pub type NaorPinkasSender = naor_pinkas::Sender;
/// Instantiation of the Naor-Pinkas OT receiver.
pub type NaorPinkasReceiver = naor_pinkas::Receiver;
/// Instantiation of the ALSZ OT extension sender, using Chou-Orlandi as the base OT.
pub type AlszSender = alsz::Sender<ChouOrlandiReceiver>;
/// Instantiation of the ALSZ OT extension receiver, using Chou-Orlandi as the base OT.
pub type AlszReceiver = alsz::Receiver<ChouOrlandiSender>;
/// Instantiation of the KOS OT extension sender, using Chou-Orlandi as the base OT.
pub type KosSender = kos::Sender<ChouOrlandiReceiver>;
/// Instantiation of the KOS OT extension receiver, using Chou-Orlandi as the base OT.
pub type KosReceiver = kos::Receiver<ChouOrlandiSender>;
/// Instantiation of the KOS Delta-OT extension sender, using Chou-Orlandi as the base OT.
pub type KosDeltaSender = kos_delta::Sender<ChouOrlandiReceiver>;
/// Instantiation of the KOS Delta-OT extension receiver, using Chou-Orlandi as the base OT.
pub type KosDeltaReceiver = kos_delta::Receiver<ChouOrlandiSender>;

/// Trait for one-out-of-two oblivious transfer from the sender's point-of-view.
pub trait Sender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization to create the oblivious transfer
    /// object.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Sends messages.
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        rng: &mut RNG,
    ) -> Result<(), Error>;
}

/// Trait for initializing an oblivious transfer object with a fixed key.
pub trait FixedKeyInitializer
where
    Self: Sized,
{
    /// Runs any one-time initialization to create the oblivious transfer
    /// object with a fixed key.
    fn init_fixed_key<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
    ) -> Result<Self, Error>;
}

/// Trait for one-out-of-two oblivious transfer from the receiver's
/// point-of-view.
pub trait Receiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization to create the oblivious transfer
    /// object.
    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error>;
    /// Receives messages.
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the sender's
/// point-of-view.
pub trait CorrelatedSender: Sender
where
    Self: Sized,
{
    /// Correlated oblivious transfer send. Takes as input an array `deltas`
    /// which specifies the offset between the zero and one message.
    fn send_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        deltas: &[Self::Msg],
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the receiver's
/// point-of-view.
pub trait CorrelatedReceiver: Receiver
where
    Self: Sized,
{
    /// Correlated oblivious transfer receive.
    fn receive_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// Trait for one-out-of-two _random_ oblivious transfer from the sender's
/// point-of-view.
pub trait RandomSender: Sender
where
    Self: Sized,
{
    /// Random oblivious transfer send. Returns a vector of tuples containing
    /// the two random messages.
    fn send_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        m: usize,
        rng: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error>;
}

/// Trait for one-out-of-two _random_ oblivious transfer from the receiver's
/// point-of-view.
pub trait RandomReceiver: Receiver
where
    Self: Sized,
{
    /// Random oblivious transfer receive.
    fn receive_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        deltas: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use scuttlebutt::{AesRng, Block, Channel};
    use std::{
        fmt::Display,
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
        sync::{Arc, Mutex},
    };

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    fn test_ot<OTSender: Sender<Msg = Block>, OTReceiver: Receiver<Msg = Block> + Display>() {
        let m0s = rand_block_vec(128);
        let m1s = rand_block_vec(128);
        let bs = rand_bool_vec(128);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut ot = OTSender::init(&mut channel, &mut rng).unwrap();
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
            ot.send(&mut channel, &ms, &mut rng).unwrap();
            ot.send(&mut channel, &ms, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut ot = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let result = ot.receive(&mut channel, &bs, &mut rng).unwrap();
        for j in 0..128 {
            assert_eq!(result[j], if bs[j] { m1s_[j] } else { m0s_[j] });
        }
        let result = ot.receive(&mut channel, &bs, &mut rng).unwrap();
        for j in 0..128 {
            assert_eq!(result[j], if bs[j] { m1s_[j] } else { m0s_[j] });
        }
        handle.join().unwrap();
    }

    fn test_otext<OTSender: Sender<Msg = Block>, OTReceiver: Receiver<Msg = Block> + Display>(
        ninputs: usize,
    ) {
        let m0s = rand_block_vec(ninputs);
        let m1s = rand_block_vec(ninputs);
        let bs = rand_bool_vec(ninputs);
        let m0s_ = m0s.clone();
        let m1s_ = m1s.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();
            let ms = m0s
                .into_iter()
                .zip(m1s.into_iter())
                .collect::<Vec<(Block, Block)>>();
            otext.send(&mut channel, &ms, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let results = otext.receive(&mut channel, &bs, &mut rng).unwrap();
        handle.join().unwrap();
        for j in 0..ninputs {
            assert_eq!(results[j], if bs[j] { m1s_[j] } else { m0s_[j] })
        }
    }

    fn test_cotext<
        OTSender: CorrelatedSender<Msg = Block>,
        OTReceiver: CorrelatedReceiver<Msg = Block> + Display,
    >(
        ninputs: usize,
    ) {
        let deltas = rand_block_vec(ninputs);
        let bs = rand_bool_vec(ninputs);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();
            let mut out = out.lock().unwrap();
            *out = otext
                .send_correlated(&mut channel, &deltas, &mut rng)
                .unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let results = otext
            .receive_correlated(&mut channel, &bs, &mut rng)
            .unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..ninputs {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    fn test_rotext<
        OTSender: RandomSender<Msg = Block>,
        OTReceiver: RandomReceiver<Msg = Block> + Display,
    >(
        ninputs: usize,
    ) {
        let bs = rand_bool_vec(ninputs);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();
            let mut out = out.lock().unwrap();
            *out = otext.send_random(&mut channel, ninputs, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let results = otext.receive_random(&mut channel, &bs, &mut rng).unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..ninputs {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    fn test_rotext_fixed_key<
        OTSender: RandomSender<Msg = Block> + FixedKeyInitializer,
        OTReceiver: RandomReceiver<Msg = Block> + Display,
    >(
        ninputs: usize,
    ) {
        let bs = rand_bool_vec(ninputs);
        let out = Arc::new(Mutex::new(vec![]));
        let out_ = out.clone();
        let (sender, receiver) = UnixStream::pair().unwrap();

        let key = [1u8; 16];
        let key_ = key.clone();

        let handle = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);
            let mut otext = OTSender::init_fixed_key(&mut channel, key_, &mut rng).unwrap();
            let mut out = out.lock().unwrap();
            *out = otext.send_random(&mut channel, ninputs, &mut rng).unwrap();
        });
        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);
        let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
        let results = otext.receive_random(&mut channel, &bs, &mut rng).unwrap();
        handle.join().unwrap();
        let out_ = out_.lock().unwrap();
        for j in 0..ninputs {
            assert_eq!(results[j], if bs[j] { out_[j].1 } else { out_[j].0 })
        }
    }

    #[test]
    fn test_dummy() {
        test_ot::<DummySender, DummyReceiver>();
    }

    #[test]
    fn test_naor_pinkas() {
        test_ot::<NaorPinkasSender, NaorPinkasReceiver>();
    }

    #[test]
    fn test_chou_orlandi() {
        test_ot::<ChouOrlandiSender, ChouOrlandiReceiver>();
    }

    #[test]
    fn test_alsz() {
        let ninputs = 1 << 10;
        test_otext::<AlszSender, AlszReceiver>(ninputs);
        test_cotext::<AlszSender, AlszReceiver>(ninputs);
        test_rotext::<AlszSender, AlszReceiver>(ninputs);
        let ninputs = (1 << 10) + 1;
        test_otext::<AlszSender, AlszReceiver>(ninputs);
        test_cotext::<AlszSender, AlszReceiver>(ninputs);
        test_rotext::<AlszSender, AlszReceiver>(ninputs);
    }

    #[test]
    fn test_kos() {
        let ninputs = 1 << 10;
        test_otext::<KosSender, KosReceiver>(ninputs);
        test_cotext::<KosSender, KosReceiver>(ninputs);
        test_rotext::<KosSender, KosReceiver>(ninputs);
        let ninputs = (1 << 10) + 1;
        test_otext::<KosSender, KosReceiver>(ninputs);
        test_cotext::<KosSender, KosReceiver>(ninputs);
        test_rotext::<KosSender, KosReceiver>(ninputs);
    }

    #[test]
    fn test_kos_delta() {
        let ninputs = 1 << 10;
        test_otext::<KosDeltaSender, KosDeltaReceiver>(ninputs);
        test_cotext::<KosDeltaSender, KosDeltaReceiver>(ninputs);
        test_rotext::<KosDeltaSender, KosDeltaReceiver>(ninputs);
        test_rotext_fixed_key::<KosDeltaSender, KosDeltaReceiver>(ninputs);
        let ninputs = (1 << 10) + 1;
        test_otext::<KosDeltaSender, KosDeltaReceiver>(ninputs);
        test_cotext::<KosDeltaSender, KosDeltaReceiver>(ninputs);
        test_rotext::<KosDeltaSender, KosDeltaReceiver>(ninputs);
        test_rotext_fixed_key::<KosDeltaSender, KosDeltaReceiver>(ninputs);
    }
}
