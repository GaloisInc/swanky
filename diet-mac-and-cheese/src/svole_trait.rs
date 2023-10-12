//! Svole trait and common implementations.

use eyre::Result;
use log::{debug, info};
use ocelot::svole::{LpnParams, Receiver, Sender};
use scuttlebutt::field::IsSubFieldOf;
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng};
use std::any::type_name;
use std::marker::PhantomData;
use std::time::Instant;
use std::{
    cell::{RefCell, RefMut},
    rc::Rc,
};
use swanky_party::either::PartyEither;
use swanky_party::{IsParty, Party, Verifier, WhichParty};

/// Svole trait.
///
/// The same trait is used for both the sender and the receiver.
/// The trait is parametric over a type `M`. Typically `M` is pair value/tag `(V,T)`
/// for a sender and tag `T` for a receiver.
pub trait SvoleT<P: Party, V, T>: SvoleStopSignal {
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
        out: &mut PartyEither<P, &mut Vec<(V, T)>, &mut Vec<T>>,
    ) -> Result<()>;

    /// Duplicate the functionality.
    fn duplicate(&self) -> Self;

    /// Return the delta as a receiver.
    fn delta(&self, ev: IsParty<P, Verifier>) -> T;
}

/// This trait provides an interface function for sending stop signals.
pub trait SvoleStopSignal {
    // NOTE: It is essential to separate this trait and its api function from `SvoleT<M>`,
    // so that the `EvaluatorCirc` can store the `SvoleT<M>` functionalities in
    // `Vec<Box<dyn SvoleStopSignal>>` for different `M`.
    // Otherwise, it would not be possible to store the functionalities with different `M` in the same `EvaluatorCirc`.

    /// Send a stop signal.
    ///
    /// In the context of multithreading, the main thread spawns svole functionalities in child threads.
    /// The svole threads run forever producing voles. When the main thread is done, it sends a signal
    /// to all the child threads so that they know when to stop producing voles and terminate.
    ///
    /// The default implementation panics.
    fn send_stop_signal(&mut self) -> Result<()> {
        panic!("Should not try to send a stop_signal")
    }
}

/// Name of a field
pub(crate) fn field_name<F: FiniteField>() -> &'static str {
    type_name::<F>().split("::").last().unwrap()
}

pub struct Svole<P: Party, V, T: FiniteField>(
    PartyEither<P, RcRefCell<Sender<T>>, RcRefCell<Receiver<T>>>,
    PhantomData<V>,
);

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> SvoleStopSignal for Svole<P, V, T> {}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> SvoleT<P, V, T> for Svole<P, V, T>
where
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<Self> {
        Ok(match P::WHICH {
            WhichParty::Prover(ev) => Self(
                PartyEither::prover_new(
                    ev,
                    RcRefCell::new(Sender::init(channel, rng, lpn_setup, lpn_extend)?),
                ),
                PhantomData,
            ),
            WhichParty::Verifier(ev) => Self(
                PartyEither::verifier_new(
                    ev,
                    RcRefCell::new(Receiver::init(channel, rng, lpn_setup, lpn_extend)?),
                ),
                PhantomData,
            ),
        })
    }

    fn extend<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        out: &mut PartyEither<P, &mut Vec<(V, T)>, &mut Vec<T>>,
    ) -> Result<()> {
        debug!("extend");
        match P::WHICH {
            WhichParty::Prover(ev) => {
                self.0.as_mut().prover_into(ev).get_refmut().send(
                    channel,
                    rng,
                    out.as_mut().prover_into(ev),
                )?;
            }
            WhichParty::Verifier(ev) => {
                let start = Instant::now();
                self.0.as_mut().verifier_into(ev).get_refmut().receive(
                    channel,
                    rng,
                    out.as_mut().verifier_into(ev),
                )?;
                info!("SVOLE<{} {:?}>", field_name::<T>(), start.elapsed());
            }
        }
        Ok(())
    }

    fn duplicate(&self) -> Self {
        Svole(self.0.clone(), PhantomData)
    }

    fn delta(&self, ev: IsParty<P, Verifier>) -> T {
        self.0.as_ref().verifier_into(ev).get_refmut().delta()
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
