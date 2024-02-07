//! Multithreading Svole.

use crate::svole_trait::{field_name, SvoleStopSignal, SvoleT};
use eyre::{ensure, Result};
use log::{debug, info};
use ocelot::svole::{LpnParams, Receiver, Sender};
use scuttlebutt::field::IsSubFieldOf;
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng};
use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use swanky_party::either::PartyEither;
use swanky_party::{IsParty, Party, Verifier, WhichParty};

const SLEEP_TIME: u64 = 1;
const SLEEP_TIME_MAX: u64 = 100;
const SLEEP_TIME_DELTA: u64 = 20;

/// The Multithreading model is to move the production of svoles to individual threads.
/// And for a given field, many threads producing svoles are bundled and consumed in a structure
/// using a round-robin.
/// * `SvoleAtomic` is the atomic structure allowing to produce or consume the voles.
/// * `ThreadVole` is the structure that is spawn in a thread containing the `Sender/Receiver`
///    svole functionality together with a `SvoleAtomic` used at a producer.
/// * `SvoleAtomicRoundRobin` is the structure used by the consumer of svoles which draws the
///    svoles by the threads in a round-robin fashion.

/// Multithreading Svole using some atomic data-structures.
///
/// An Svole functionality can use this structure to store the generated correlations.
/// The stored correlations can be read by a consumer in a synchronized way.
pub struct SvoleAtomic<P: Party, V, T: Copy> {
    voles: Arc<Mutex<PartyEither<P, Vec<(V, T)>, Vec<T>>>>,
    full: Arc<Mutex<bool>>,
    stop_signal: Arc<Mutex<bool>>,
    delta: Arc<Mutex<Option<T>>>,
}

impl<P: Party, V, T: Copy + Default> SvoleAtomic<P, V, T> {
    pub fn create() -> Self {
        Self {
            voles: Arc::new(Mutex::new(PartyEither::default())),
            full: Arc::new(Mutex::new(false)),
            stop_signal: Arc::new(Mutex::new(false)),
            delta: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_delta(&mut self, delta: T) {
        *self.delta.lock().unwrap() = Some(delta);
    }
}

impl<P: Party, V, T: Copy> SvoleStopSignal for SvoleAtomic<P, V, T> {
    fn send_stop_signal(&mut self) -> Result<()> {
        *self.stop_signal.lock().unwrap() = true;
        Ok(())
    }
}

impl<P: Party, V, T: Copy + Default + Debug> SvoleT<P, V, T> for SvoleAtomic<P, V, T> {
    fn init<C: AbstractChannel + Clone>(
        _channel: &mut C,
        _rng: &mut AesRng,
        _lpn_setup: LpnParams,
        _lpn_extend: LpnParams,
        _delta: Option<T>,
    ) -> Result<Self> {
        panic!("Should not be initialized")
    }

    fn duplicate(&self) -> Self {
        Self {
            voles: self.voles.clone(),
            full: self.full.clone(),
            stop_signal: self.stop_signal.clone(),
            delta: self.delta.clone(),
        }
    }

    fn extend<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        _rng: &mut AesRng,
        out: &mut PartyEither<P, &mut Vec<(V, T)>, &mut Vec<T>>,
    ) -> Result<()> {
        let mut sleep_time = SLEEP_TIME;
        loop {
            let full = *self.full.lock().unwrap();

            if full {
                let _start = Instant::now();
                out.as_mut().zip(self.voles.lock().unwrap().as_mut()).map(
                    |(out, candidate)| out.append(candidate),
                    |(out, candidate)| out.append(candidate),
                );
                debug!("COPY<time:{:?} >", _start.elapsed());
                // No need to clear because append() already takes care of it, otherwise
                // self.voles[candidate].lock().unwrap().clear();
                *self.full.lock().unwrap() = false;
                break;
            } else {
                // WARNING!!!! This flush is very important to avoid deadlock!!!!!
                // For example, if the prover inputs a number of values that is larger
                // than the buffer to flush automatically, then it will empty all its voles
                // and start requesting a svole extension in the other thread, but
                // the verifier does not receive the values because it's not flushed,
                // hence it is a deadlock.
                channel.flush()?;
                debug!("SLEEP! VoleInterface {:?}", T::default());
                // exponential backoff sleep
                std::thread::sleep(std::time::Duration::from_millis(sleep_time));
                sleep_time = std::cmp::min(sleep_time + 1 + (sleep_time / 2), SLEEP_TIME_MAX);
            }
        }

        Ok(())
    }

    fn delta(&self, _ev: IsParty<P, Verifier>) -> T {
        // Need to wait for delta to be available
        while (*self.delta.lock().unwrap()).is_none() {
            debug!(
                "Waiting for DELTA: {:?}",
                std::any::type_name::<T>().split("::").last().unwrap()
            );
            std::thread::sleep(std::time::Duration::from_millis(SLEEP_TIME_DELTA));
        }
        (*self.delta.lock().unwrap()).unwrap()
    }
}

/// Svole intended to be run in a separate thread.
pub struct ThreadSvole<P: Party, V, T: FiniteField> {
    vole_comm: PartyEither<P, Sender<T>, Receiver<T>>,
    svole_atomic: SvoleAtomic<P, V, T>,
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField> ThreadSvole<P, V, T> {
    /// Initialize the functionality.
    pub fn init<C: AbstractChannel + Clone>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        mut svole_atomic: SvoleAtomic<P, V, T>,
        delta: Option<T>,
    ) -> Result<Self> {
        let vole_comm = match P::WHICH {
            WhichParty::Prover(ev) => {
                PartyEither::prover_new(ev, Sender::init(channel, rng, lpn_setup, lpn_extend)?)
            }
            WhichParty::Verifier(ev) => PartyEither::verifier_new(
                ev,
                Receiver::init(channel, rng, lpn_setup, lpn_extend, delta)?,
            ),
        };

        match P::WHICH {
            WhichParty::Prover(_) => debug!("INIT MultithreadedSender"),
            WhichParty::Verifier(ev) => {
                svole_atomic.set_delta(vole_comm.as_ref().verifier_into(ev).delta());
                debug!("DELTA is {:?}", svole_atomic.delta(ev));
                debug!("INIT MultithreadedReceiver");
            }
        }

        Ok(Self {
            vole_comm,
            svole_atomic,
        })
    }

    /// Run the functionality.
    pub fn run<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
    ) -> Result<()>
    where
        // This constraint is necessary in order to use `wykw::sole::Sender::send`
        <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
    {
        let mut sleep_time = SLEEP_TIME;
        loop {
            let full = *self.svole_atomic.full.lock().unwrap();

            // We stop when all the svole vectors are full to avoid concurrency issues.
            // In particular if one side decides to fill up an svole while the other has received a
            // stop signal
            if *self.svole_atomic.stop_signal.lock().unwrap() && full {
                info!("Stop running svole functionality for {}", field_name::<T>());
                break;
            }

            if !full {
                match P::WHICH {
                    WhichParty::Prover(ev) => {
                        debug!("multithread prover extend");
                        self.vole_comm.as_mut().prover_into(ev).send(
                            channel,
                            rng,
                            self.svole_atomic
                                .voles
                                .lock()
                                .unwrap()
                                .as_mut()
                                .prover_into(ev),
                        )?;
                        debug!("DONE multithread prover extend");
                    }
                    WhichParty::Verifier(ev) => {
                        debug!("multithread verifier extend");
                        debug!("RUN DELTA is {:?}", self.svole_atomic.delta(ev));
                        let start = Instant::now();
                        self.vole_comm.as_mut().verifier_into(ev).receive::<_, V>(
                            channel,
                            rng,
                            self.svole_atomic
                                .voles
                                .lock()
                                .unwrap()
                                .as_mut()
                                .verifier_into(ev),
                        )?;
                        info!(
                            "SVOLE<{} {:?}>",
                            std::any::type_name::<T>().split("::").last().unwrap(),
                            start.elapsed(),
                        );
                        debug!("DONE multithread verifier extend");
                    }
                }

                *self.svole_atomic.full.lock().unwrap() = true;
                sleep_time = SLEEP_TIME; // reset sleep time
            } else {
                debug!(
                    "SLEEP! multithreaded svole: {:?}",
                    std::any::type_name::<T>()
                );
                // exponential backoff sleep
                std::thread::sleep(std::time::Duration::from_millis(sleep_time));
                sleep_time = std::cmp::min(sleep_time + 1 + (sleep_time / 2), SLEEP_TIME_MAX);
            }
        }
        Ok(())
    }
}

pub struct SvoleAtomicRoundRobin<P: Party, V, T: Copy> {
    svoles: Vec<SvoleAtomic<P, V, T>>,
    current: Rc<RefCell<usize>>,
    num_voles: Rc<RefCell<usize>>,
}

impl<P: Party, V, T: Copy> SvoleStopSignal for SvoleAtomicRoundRobin<P, V, T> {
    fn send_stop_signal(&mut self) -> Result<()> {
        unreachable!()
    }
}

impl<P: Party, V, T: Copy> SvoleAtomicRoundRobin<P, V, T> {
    fn new(svoles: Vec<SvoleAtomic<P, V, T>>) -> Result<Self> {
        ensure!(!svoles.is_empty(), "Round-robin needs some svoles");
        let num_voles = svoles.len();
        Ok(Self {
            svoles,
            current: Rc::new(RefCell::new(0)),
            num_voles: Rc::new(RefCell::new(num_voles)),
        })
    }
}

impl<P: Party, V: IsSubFieldOf<T>, T: FiniteField + Copy + Default + Debug>
    SvoleAtomicRoundRobin<P, V, T>
where
    // This constraint is necessary in order to use `wykw::sole::Sender::send`
    <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
{
    // Create a `SvoleAtomicRounRobin`
    pub(crate) fn create_and_spawn_svole_threads<C2: AbstractChannel + Clone + 'static + Send>(
        channels_vole: Vec<C2>,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
    ) -> Result<(
        Self,
        Vec<SvoleAtomic<P, V, T>>,
        Vec<std::thread::JoinHandle<Result<()>>>,
    )> {
        let mut threads = vec![];
        let mut svoles_atomics: Vec<SvoleAtomic<P, V, T>> = vec![];
        let mut svoles_atomics_to_stop: Vec<SvoleAtomic<P, V, T>> = vec![];

        for (i, mut channel_vole) in channels_vole.into_iter().enumerate() {
            let svole_atomic = SvoleAtomic::<P, V, T>::create();
            let svole_atomic2 = svole_atomic.duplicate();
            let svole_atomic3 = svole_atomic.duplicate();

            let delta = if i != 0 {
                // We get the delta from the first vole.
                match P::WHICH {
                    WhichParty::Verifier(ev) => Some(svoles_atomics[0].delta(ev)),
                    WhichParty::Prover(_) => None,
                }
            } else {
                None
            };

            let svole_thread = std::thread::spawn(move || {
                info!("spawning SVOLE thread for field {:?}", field_name::<T>());
                let mut rng2 = AesRng::new();
                let mut svole = ThreadSvole::<P, V, T>::init(
                    &mut channel_vole,
                    &mut rng2,
                    lpn_setup,
                    lpn_extend,
                    svole_atomic,
                    delta,
                )?;
                svole.run(&mut channel_vole, &mut rng2)?;
                Ok(())
            });
            threads.push(svole_thread);
            svoles_atomics.push(svole_atomic2);
            svoles_atomics_to_stop.push(svole_atomic3)
        }

        let svole_round_robin = SvoleAtomicRoundRobin::<P, V, T>::new(svoles_atomics)?;

        Ok((svole_round_robin, svoles_atomics_to_stop, threads))
    }
}

impl<P: Party, V, T: Copy + Default + Debug> SvoleT<P, V, T> for SvoleAtomicRoundRobin<P, V, T> {
    fn init<C: AbstractChannel + Clone>(
        _channel: &mut C,
        _rng: &mut AesRng,
        _lpn_setup: LpnParams,
        _lpn_extend: LpnParams,
        _delta: Option<T>,
    ) -> Result<Self> {
        panic!("Should not be initialized via init from SvoleT")
    }

    fn duplicate(&self) -> Self {
        // We need the duplicate here because, for the conversion gates, we are currently
        // duplicating the DietMacAndCheese functionality.
        let svoles = self.svoles.iter().map(|c| c.duplicate()).collect();
        Self {
            svoles,
            current: self.current.clone(),
            num_voles: self.num_voles.clone(),
        }
    }

    fn extend<C: AbstractChannel + Clone>(
        &mut self,
        channel: &mut C,
        rng: &mut AesRng,
        out: &mut PartyEither<P, &mut Vec<(V, T)>, &mut Vec<T>>,
    ) -> Result<()> {
        self.svoles[*self.current.borrow()].extend(channel, rng, out)?;
        let mut curr = self.current.borrow_mut();
        *curr = (*curr + 1) % *self.num_voles.borrow();
        Ok(())
    }

    fn delta(&self, ev: IsParty<P, Verifier>) -> T {
        // It is the same delta for all the svoles in the round-robin,
        // so we can pick the current one.
        self.svoles[*self.current.borrow()].delta(ev)
    }
}

#[cfg(test)]
mod test {
    use super::SLEEP_TIME;
    use super::{SvoleAtomic, SvoleAtomicRoundRobin};
    use crate::svole_trait::SvoleT;
    use rand::Rng;
    use scuttlebutt::{AesRng, Channel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };
    use swanky_party::either::PartyEither;
    use swanky_party::{Verifier, IS_VERIFIER};

    fn produce(s: &SvoleAtomic<Verifier, u32, u32>, v: u32) {
        loop {
            if *s.stop_signal.lock().unwrap() {
                break;
            }
            let full = *s.full.lock().unwrap();

            if !full {
                *s.voles.lock().unwrap() = PartyEither::verifier_new(IS_VERIFIER, vec![v, v + 1]);
                *s.full.lock().unwrap() = true;
                break;
            } else {
                std::thread::sleep(std::time::Duration::from_millis(SLEEP_TIME + SLEEP_TIME));
            }
        }
    }

    #[test]
    fn test_svole_atomic_concurrency() {
        // generate some random sequence of produce and consume, and test if it reaches the end without
        // a deadlock
        let t1 = SvoleAtomic::<Verifier, u32, u32>::create();
        let t1_copy = t1.duplicate();

        let t2 = SvoleAtomic::<Verifier, u32, u32>::create();
        let t2_copy = t2.duplicate();

        let how_many = 100;
        const CONST_42: u32 = 42;
        const SHIFT: u32 = 100;
        let handle1 = std::thread::spawn(move || {
            let mut rng = rand::thread_rng();
            for _ in 0..how_many {
                let random_millis = rng.gen_range(0..=SLEEP_TIME);
                produce(&t1, CONST_42);
                std::thread::sleep(std::time::Duration::from_millis(random_millis));
            }
        });

        let handle2 = std::thread::spawn(move || {
            let mut rng = rand::thread_rng();
            for _ in 0..how_many {
                let random_millis = rng.gen_range(0..=SLEEP_TIME);
                produce(&t2, CONST_42 + SHIFT);
                std::thread::sleep(std::time::Duration::from_millis(random_millis));
            }
        });

        let mut round_robin = SvoleAtomicRoundRobin::new(vec![t1_copy, t2_copy]).unwrap();

        let mut rng = AesRng::new();
        let (sender, _receiver) = UnixStream::pair().unwrap();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut v: Vec<u32> = vec![];
        let mut out = PartyEither::verifier_new(IS_VERIFIER, &mut v);
        let mut i = 0;
        let mut other_rng = rand::thread_rng();
        for _ in 0..2 * how_many {
            let random_millis = other_rng.gen_range(0..=SLEEP_TIME);
            round_robin
                .extend::<_>(&mut channel, &mut rng, &mut out)
                .unwrap();
            assert_eq!(out.as_ref().verifier_into(IS_VERIFIER)[0], i + CONST_42);
            assert_eq!(out.as_ref().verifier_into(IS_VERIFIER)[1], i + CONST_42 + 1);
            i = (i + SHIFT) % (2 * SHIFT);
            out.as_mut().verifier_into(IS_VERIFIER).clear();

            std::thread::sleep(std::time::Duration::from_millis(random_millis));
        }
        handle1.join().unwrap();
        handle2.join().unwrap();
    }
}
