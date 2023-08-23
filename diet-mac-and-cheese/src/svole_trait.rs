//! Svole trait and common implementations.

use eyre::Result;
use log::debug;
use ocelot::svole::{LpnParams, Receiver, Sender};
use scuttlebutt::field::IsSubFieldOf;
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng};
use std::marker::PhantomData;
use std::{
    cell::{RefCell, RefMut},
    rc::Rc,
};

/// Svole trait.
///
/// The same trait is used for both the sender and the receiver.
/// The trait is parametric over a type `X`. Typically `X` is `(V,T)` for a sender and `T` for a receiver.
///
pub trait SvoleT<X> {
    /// Initialize function.
    fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self>
    where
        Self: Sized;

    /// Extend function producing more correlations in the `out` vector.
    fn extend<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        out: &mut Vec<X>,
    ) -> Result<()>;

    /// Duplicate the functionality.
    fn duplicate(&self) -> Self;

    /// Return the delta as a receiver.
    /// This function should panic as a sender.
    fn delta(&self) -> X;
}

impl<V: IsSubFieldOf<T>, T: FiniteField> SvoleT<(V, T)> for Sender<T>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        Ok(Sender::init(channel, rng, lpn_setup, lpn_extend)?)
    }

    fn duplicate(&self) -> Self {
        unimplemented!()
    }

    fn extend<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        out: &mut Vec<(V, T)>,
    ) -> Result<()> {
        debug!("prover extend");
        self.send(channel, rng, out)?;
        Ok(())
    }

    fn delta(&self) -> (V, T) {
        panic!("delta should not be called on a Sender")
    }
}

/// Generic Type synonym to Rc<RefCell<X>>.
struct RcRefCell<X>(Rc<RefCell<X>>);

impl<X> RcRefCell<X> {
    /// Create new.
    fn new(x: X) -> Self {
        RcRefCell(Rc::new(RefCell::new(x)))
    }

    /// Get access to the mutable reference.
    fn get_refmut(&self) -> RefMut<X> {
        (*self.0).borrow_mut()
    }
}

impl<X> Clone for RcRefCell<X> {
    fn clone(&self) -> Self {
        RcRefCell(Rc::clone(&self.0))
    }
}

/// Svole sender.
#[repr(transparent)]
pub struct SvoleSender<T: FiniteField> {
    // We use a Rc<RefCell<>> here so that the underlying svole functionality can be shared among
    // other components of diet mac'n'cheese. This is specifically relevant for field switching, where
    // the svole functionality for F2 can be shared while converting from A to B using F2 in the middle, or
    // A to F2 or F2 to B.
    sender: RcRefCell<Sender<T>>,
}

impl<V: IsSubFieldOf<T>, T: FiniteField> SvoleT<(V, T)> for SvoleSender<T>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        Ok(SvoleSender {
            sender: RcRefCell::new(Sender::init(channel, rng, lpn_setup, lpn_extend)?),
        })
    }

    fn duplicate(&self) -> Self {
        SvoleSender {
            sender: self.sender.clone(),
        }
    }

    fn extend<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        out: &mut Vec<(V, T)>,
    ) -> Result<()> {
        debug!("prover extend");
        self.sender.get_refmut().send(channel, rng, out)?;
        Ok(())
    }

    fn delta(&self) -> (V, T) {
        panic!("cannot request delta on the sender side")
    }
}

/// Svole receiver.
pub struct SvoleReceiver<V, T: FiniteField> {
    the_receiver: RcRefCell<Receiver<T>>,
    phantom: PhantomData<V>,
}

impl<V, T: FiniteField> SvoleReceiver<V, T> {
    fn new(recv: RcRefCell<Receiver<T>>) -> Self {
        Self {
            the_receiver: recv,
            phantom: PhantomData,
        }
    }
}

impl<V: IsSubFieldOf<T>, T: FiniteField> SvoleT<T> for SvoleReceiver<V, T>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        Ok(SvoleReceiver::new(RcRefCell::new(Receiver::init(
            channel, rng, lpn_setup, lpn_extend,
        )?)))
    }

    fn duplicate(&self) -> Self {
        SvoleReceiver {
            the_receiver: self.the_receiver.clone(),
            phantom: PhantomData,
        }
    }

    fn extend<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        out: &mut Vec<T>,
    ) -> Result<()> {
        debug!("verifier extend");
        self.the_receiver
            .get_refmut()
            .receive::<_, V>(channel, rng, out)?;
        Ok(())
    }

    fn delta(&self) -> T {
        self.the_receiver.get_refmut().delta()
    }
}
