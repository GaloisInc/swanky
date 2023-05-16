use std::{ops::Deref, sync::Arc};

use parking_lot::{Condvar, Mutex};

struct Inner {
    // If None, it signals that a thread has errored out.
    state: Mutex<Option<usize>>,
    condvar: Condvar,
}

pub struct ThreadSpawner {
    inner: Arc<Inner>,
}
impl ThreadSpawner {
    pub fn new() -> Self {
        ThreadSpawner {
            inner: Arc::new(Inner {
                state: Mutex::new(Some(0)),
                condvar: Condvar::new(),
            }),
        }
    }
    // TODO: we should remove this
    pub fn spawn_daemon(
        &mut self,
        name: String,
        f: impl 'static + Send + FnOnce() -> eyre::Result<()>,
    ) {
        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                eprintln!("Starting thread {name:?}");
                match f() {
                    Ok(()) => {
                        eprintln!("Thread {name:?} completed successfully.");
                    }
                    Err(e) => {
                        eprintln!("Thread {name:?} failed with:\n{e:?}");
                        let mut guard = inner.state.lock();
                        *guard = None;
                        inner.condvar.notify_all();
                    }
                }
            })
            .expect("able to spawn thread");
    }
    pub fn spawn(&mut self, name: String, f: impl 'static + Send + FnOnce() -> eyre::Result<()>) {
        if let Some(count) = self.inner.state.lock().as_mut() {
            *count += 1;
        }
        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                eprintln!("Starting thread {name:?}");
                match f() {
                    Ok(()) => {
                        eprintln!("Thread {name:?} completed successfully.");
                        let mut guard = inner.state.lock();
                        if let Some(count) = guard.as_mut() {
                            *count = count
                                .checked_sub(1)
                                .expect("underflow on remaining thread count");
                        }
                        inner.condvar.notify_all();
                    }
                    Err(e) => {
                        eprintln!("Thread {name:?} failed with:\n{e:?}");
                        let mut guard = inner.state.lock();
                        *guard = None;
                        inner.condvar.notify_all();
                    }
                }
            })
            .expect("able to spawn thread");
    }
    pub fn wait_on_threads(self) -> eyre::Result<()> {
        let mut guard = self.inner.state.lock();
        loop {
            if guard.deref().is_none() {
                eyre::bail!("A spawned thread has failed");
            } else if guard.deref() == &Some(0) {
                return Ok(());
            }
            self.inner.condvar.wait(&mut guard);
        }
    }
}
