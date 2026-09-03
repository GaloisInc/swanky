#![deny(missing_docs)]
//! Base traits for Obliivious Transfer protocols

use rand::{CryptoRng, Rng};
use swanky_channel_legacy::AbstractChannel;
use swanky_error::Result;

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
    ) -> Result<Self>;
    /// Sends messages.
    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        rng: &mut RNG,
    ) -> Result<()>;
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
    ) -> Result<Self>;
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
    ) -> Result<Self>;
    /// Receives messages.
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the sender's
/// point-of-view.
pub trait CorrelatedSender: Sender
where
    Self: Sized,
{
    /// Correlated oblivious transfer send. Takes as input a $\Delta$ value
    /// which specifies the offset between the zero and one message.
    fn send_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        m: usize,
        delta: Self::Msg,
        rng: &mut RNG,
    ) -> Result<Vec<Self::Msg>>;
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
    ) -> Result<Vec<Self::Msg>>;
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
    ) -> Result<Vec<(Self::Msg, Self::Msg)>>;
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
    ) -> Result<Vec<Self::Msg>>;
}
