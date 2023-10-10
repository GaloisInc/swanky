//! Multithreading Svole.

use crate::svole_trait::{field_name, SvoleStopSignal, SvoleT};
use eyre::Result;
use log::{debug, info, warn};
use ocelot::svole::{LpnParams, Receiver, Sender};
use scuttlebutt::field::IsSubFieldOf;
use scuttlebutt::{field::FiniteField, AbstractChannel, AesRng};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use swanky_party::either::PartyEither;
use swanky_party::{Party, Verifier, WhichParty};

const SLEEP_TIME: u64 = 1;
const SLEEP_TIME_MAX: u64 = 100;

// number of VOLE extension vectors cannot be smaller than 2.
const VOLE_VEC_NUM_MIN: usize = 3;
const VOLE_VEC_NUM: usize = 3;

/// Multithreading Svole using some atomic data-structures.
///
/// An Svole functionality can use this structure to store the generated correlations.
/// The stored correlations can be read by a consumer in a synchronized way.
pub struct SvoleAtomic<P: Party, V, T: Copy> {
    voles: Vec<Arc<Mutex<PartyEither<P, Vec<(V, T)>, Vec<T>>>>>,
    last_done: Arc<Mutex<usize>>,
    next_todo: Arc<Mutex<usize>>,
    stop_signal: Arc<Mutex<bool>>,
    delta: Arc<Mutex<Option<T>>>,
}

impl<P: Party, V, T: Copy + Default> SvoleAtomic<P, V, T> {
    pub fn create() -> Self {
        assert!(VOLE_VEC_NUM_MIN <= VOLE_VEC_NUM_MIN);
        let mut v = vec![];
        for _ in 0..VOLE_VEC_NUM {
            v.push(Arc::new(Mutex::new(PartyEither::default())));
        }
        Self {
            voles: v,
            last_done: Arc::new(Mutex::new(VOLE_VEC_NUM - 1)),
            next_todo: Arc::new(Mutex::new(0)),
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
    fn init<C: AbstractChannel>(
        _channel: &mut C,
        _rng: &mut AesRng,
        _lpn_setup: LpnParams,
        _lpn_extend: LpnParams,
    ) -> Result<Self> {
        panic!("Should not be initialized")
    }

    fn duplicate(&self) -> Self {
        let mut v = vec![];
        for i in 0..VOLE_VEC_NUM {
            v.push(self.voles[i].clone());
        }
        Self {
            voles: v,
            last_done: self.last_done.clone(),
            next_todo: self.next_todo.clone(),
            stop_signal: self.stop_signal.clone(),
            delta: self.delta.clone(),
        }
    }

    fn extend<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        _rng: &mut AesRng,
        out: &mut PartyEither<P, &mut Vec<(V, T)>, &mut Vec<T>>,
    ) -> Result<()> {
        let mut sleep_time = SLEEP_TIME;
        loop {
            let last_done = *self.last_done.lock().unwrap();
            let next_todo = *self.next_todo.lock().unwrap();

            let candidate = (last_done + 1) % VOLE_VEC_NUM;
            if candidate != next_todo {
                let _start = Instant::now();
                out.as_mut()
                    .zip(self.voles[candidate].lock().unwrap().as_mut())
                    .map(
                        |(out, candidate)| out.append(candidate),
                        |(out, candidate)| out.append(candidate),
                    );
                debug!("COPY<time:{:?} >", _start.elapsed());
                // No need to clear because append() already takes care of it, otherwise
                // self.voles[candidate].lock().unwrap().clear();
                *self.last_done.lock().unwrap() = candidate;
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

    fn delta(&self, _ev: swanky_party::IsParty<P, Verifier>) -> T {
        while (*self.delta.lock().unwrap()).is_none() {
            warn!(
                "Waiting for DELTA: {:?}",
                std::any::type_name::<T>().split("::").last().unwrap()
            );
            std::thread::sleep(std::time::Duration::from_millis(SLEEP_TIME));
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
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        rng: &mut AesRng,
        lpn_setup: LpnParams,
        lpn_extend: LpnParams,
        mut svole_atomic: SvoleAtomic<P, V, T>,
    ) -> Result<Self> {
        let vole_comm = match P::WHICH {
            WhichParty::Prover(ev) => {
                PartyEither::prover_new(ev, Sender::init(channel, rng, lpn_setup, lpn_extend)?)
            }
            WhichParty::Verifier(ev) => {
                PartyEither::verifier_new(ev, Receiver::init(channel, rng, lpn_setup, lpn_extend)?)
            }
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
    pub fn run<C: AbstractChannel>(&mut self, channel: &mut C, rng: &mut AesRng) -> Result<()>
    where
        <T as FiniteField>::PrimeField: IsSubFieldOf<V>,
    {
        let mut sleep_time = SLEEP_TIME;
        loop {
            let last_done = *self.svole_atomic.last_done.lock().unwrap();
            let next_todo = *self.svole_atomic.next_todo.lock().unwrap();

            // We stop when all the svole vectors are full to avoid concurrency issues.
            // In particular if one side decides to fill up an svole while the other has received a
            // stop signal
            if *self.svole_atomic.stop_signal.lock().unwrap() && next_todo == last_done {
                info!("Stop running svole functionality for {}", field_name::<T>());
                break;
            }

            if next_todo != last_done {
                match P::WHICH {
                    WhichParty::Prover(ev) => {
                        debug!("multithread prover extend");
                        self.vole_comm.as_mut().prover_into(ev).send(
                            channel,
                            rng,
                            self.svole_atomic.voles[next_todo]
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
                            self.svole_atomic.voles[next_todo]
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

                *self.svole_atomic.next_todo.lock().unwrap() = (next_todo + 1) % VOLE_VEC_NUM;
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

#[cfg(test)]
mod test {
    use super::SvoleAtomic;
    use super::{SLEEP_TIME, VOLE_VEC_NUM};
    use crate::svole_trait::SvoleT;
    use rand::Rng;
    use scuttlebutt::{AesRng, Channel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };
    use swanky_party::either::PartyEither;
    use swanky_party::{Verifier, IS_VERIFIER};

    fn produce(s: &SvoleAtomic<Verifier, u32, u32>) {
        loop {
            if *s.stop_signal.lock().unwrap() {
                break;
            }
            let last_done = *s.last_done.lock().unwrap();
            let next_todo = *s.next_todo.lock().unwrap();

            if next_todo != last_done {
                *s.voles[next_todo].lock().unwrap() =
                    PartyEither::verifier_new(IS_VERIFIER, vec![42, 43]);
                *s.next_todo.lock().unwrap() = (next_todo + 1) % VOLE_VEC_NUM;
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
        let mut t2 = t1.duplicate();

        let how_many = 200;
        let handle = std::thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let random_millis = rng.gen_range(0..=SLEEP_TIME);
            for _ in 0..how_many {
                produce(&t1);
                std::thread::sleep(std::time::Duration::from_millis(random_millis));
                println!("CONS");
            }
        });

        let mut rng = AesRng::new();
        let (sender, _receiver) = UnixStream::pair().unwrap();
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);
        let mut out = PartyEither::verifier_new(IS_VERIFIER, vec![]);
        for _ in 0..how_many {
            let mut other_rng = rand::thread_rng();
            let random_millis = other_rng.gen_range(0..=SLEEP_TIME);
            t2.extend(&mut channel, &mut rng, &mut out.as_mut())
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(random_millis));
            println!("CONS2");
        }
        handle.join().unwrap();
    }
}
