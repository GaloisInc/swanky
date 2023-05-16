use crossbeam_queue::SegQueue;
use eyre::{Context, ContextCompat};
use parking_lot::{Mutex, MutexGuard, RwLock};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::io::{BufReader, Read};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::thread::LocalKey;
use std::time::Instant;
use std::{cell::Cell, marker::PhantomData, path::Path};
use std::{fs::File, io::BufWriter};
use std::{
    io::{Cursor, Write},
    time::{Duration, SystemTime},
};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventArgumentType {
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
}
impl EventArgumentType {
    pub fn size(&self) -> usize {
        use EventArgumentType::*;
        match self {
            Bool | I8 | U8 | I16 | U16 | I32 | U32 => 1,
            I64 | U64 => 2,
        }
    }
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EventArgument {
    pub name: String,
    pub ty_name: String,
    pub ty: EventArgumentType,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    OneOff,
    Span,
    Lock,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EventDescription {
    pub name: String,
    pub kind: EventKind,
    pub args: Vec<EventArgument>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EventLogSchema {
    pub events: Vec<EventDescription>,
}

// This intentionally doesn't have a drop. Some spans shouldn't complete.
#[must_use]
pub struct SpanFinishNotifier<S: internal::EventLogStatics> {
    evt_id: u64,
    // This type shouldn't be Send.
    phantom: PhantomData<std::rc::Rc<S>>,
}
impl<S: internal::EventLogStatics> SpanFinishNotifier<S> {
    #[inline]
    pub fn finish(self) {
        let now = Instant::now();
        S::LOCAL_KEY.with(|tl| {
            if let Some(tl) = tl {
                tl.submit_event_with_event_id(now, S::INTERNAL_SPAN_FINISH, self.evt_id);
            }
        })
    }
}

pub struct EventLoggingMutexGuard<'a, S: internal::EventLogStatics, T> {
    evt_id: u64,
    guard: MutexGuard<'a, T>,
    // This type shouldn't be Send.
    phantom: PhantomData<std::rc::Rc<S>>,
}

impl<'a, S: internal::EventLogStatics, T> Drop for EventLoggingMutexGuard<'a, S, T> {
    fn drop(&mut self) {
        let now = Instant::now();
        S::LOCAL_KEY.with(|tl| {
            if let Some(tl) = tl {
                tl.submit_event_with_event_id(now, S::INTERNAL_RELEASED_LOCK, self.evt_id);
            }
        });
    }
}

impl<'a, S: internal::EventLogStatics, T> Deref for EventLoggingMutexGuard<'a, S, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}
impl<'a, S: internal::EventLogStatics, T> DerefMut for EventLoggingMutexGuard<'a, S, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

type EventBuffer = Arc<Mutex<Vec<u32>>>;

pub trait EventLoggable {
    const SIZE: usize;
    const TYPE: EventArgumentType;
    fn encode(&self, dst: &mut [u32]);
}
impl EventLoggable for u64 {
    const SIZE: usize = 2;
    const TYPE: EventArgumentType = EventArgumentType::U64;

    #[inline]
    fn encode(&self, dst: &mut [u32]) {
        dst[0] = *self as u32;
        dst[1] = (*self >> 32) as u32;
    }
}
impl EventLoggable for i64 {
    const SIZE: usize = 2;
    const TYPE: EventArgumentType = EventArgumentType::I64;
    #[inline]
    fn encode(&self, dst: &mut [u32]) {
        <u64 as EventLoggable>::encode(&((*self) as u64), dst);
    }
}

macro_rules! single_word_event_loggable {
    ($($ty:ty => $name:ident),*) => {$(
        impl EventLoggable for $ty {
            const SIZE: usize = 1;
            const TYPE: EventArgumentType = EventArgumentType::$name;
            #[inline]
            fn encode(&self, dst: &mut [u32]) {
                dst[0] = (*self) as u32;
            }
        }
    )*};
}
single_word_event_loggable!(
    bool => Bool, i8 => I8, u8 => U8, i16 => I16, u16 => U16, i32 => I32, u32 => U32
);

const DEFAULT_CAPACITY: usize = 1024 * 1024 * 2;
const EVENT_LOG_POLL_DURATION: Duration = Duration::from_millis(1000);

#[doc(hidden)]
pub mod internal {
    use super::*;
    pub struct EventLogWriter {
        dst: lz4::Encoder<BufWriter<File>>,
        sources: Vec<EventBuffer>,
        sources_second_buffer: Vec<Vec<u32>>,
    }

    impl EventLogWriter {
        pub fn flush(&mut self, new_buffers: &SegQueue<EventBuffer>) -> eyre::Result<()> {
            while let Some(buf) = new_buffers.pop() {
                self.sources.push(buf);
            }
            self.sources_second_buffer
                .resize_with(self.sources.len(), || Vec::with_capacity(DEFAULT_CAPACITY));
            debug_assert_eq!(self.sources.len(), self.sources_second_buffer.len());
            for (thread_id, (source, second_source)) in self
                .sources
                .iter()
                .zip(self.sources_second_buffer.iter_mut())
                .enumerate()
            {
                second_source.clear();
                {
                    let mut guard = source.lock();
                    std::mem::swap(guard.deref_mut(), second_source);
                }
                let to_write = second_source;
                if to_write.is_empty() {
                    continue;
                }
                self.dst.write_all(&(thread_id as u64).to_le_bytes())?;
                self.dst.write_all(&(to_write.len() as u64).to_le_bytes())?;
                self.dst.write_all(bytemuck::cast_slice(to_write))?;
            }
            self.dst.flush()?;
            Ok(())
        }
    }
    pub enum GlobalState {
        NotYetOpen,
        Open {
            system_start: Instant,
            new_buffers: SegQueue<EventBuffer>,
            writer: Mutex<EventLogWriter>,
        },
        Closed,
    }
    pub type GlobalStateHandle = RwLock<GlobalState>;

    pub struct ThreadLocal {
        last_timestamp: Cell<Instant>,
        next_event_id: Cell<u64>,
        dst: EventBuffer,
    }
    impl ThreadLocal {
        pub fn new(global: &GlobalStateHandle) -> Option<Self> {
            let global = global.read();
            if let GlobalState::Open {
                system_start,
                new_buffers,
                ..
            } = global.deref()
            {
                let dst = Arc::new(Mutex::new(Vec::with_capacity(DEFAULT_CAPACITY)));
                new_buffers.push(dst.clone());
                Some(ThreadLocal {
                    last_timestamp: Cell::new(*system_start),
                    next_event_id: Cell::new(0),
                    dst,
                })
            } else {
                None
            }
        }
        // Returns event ID
        pub fn submit_raw(&self, now: Instant, args: &[u32]) -> u64 {
            let delta = now - self.last_timestamp.get();
            self.last_timestamp.set(now);
            // This won't overflow unless we run for 500 years!
            let delta = delta.as_nanos() as u64;
            let evt_id = self.next_event_id.get();
            self.next_event_id.set(evt_id + 1);
            {
                let mut guard = self.dst.lock();
                guard.reserve(2 + args.len());
                let mut buf = [0; 2];
                <u64 as EventLoggable>::encode(&delta, &mut buf);
                guard.extend_from_slice(&buf);
                guard.extend_from_slice(args);
            }
            evt_id
        }
        pub fn submit_event_with_event_id(&self, now: Instant, kind: u32, event_id: u64) {
            let mut buf = [0; 3];
            buf[0] = kind;
            // TODO: delta encode event IDs?
            <u64 as EventLoggable>::encode(&event_id, &mut buf[1..]);
            self.submit_raw(now, &buf);
        }
    }

    pub trait EventLogStatics {
        const LOCAL_KEY: &'static LocalKey<Option<ThreadLocal>>;
        const INTERNAL_SPAN_FINISH: u32;
        const INTERNAL_ACQUIRED_LOCK: u32;
        const INTERNAL_RELEASED_LOCK: u32;
    }

    pub fn new_span_finisher<S: EventLogStatics>(evt_id: u64) -> SpanFinishNotifier<S> {
        SpanFinishNotifier {
            evt_id,
            phantom: PhantomData,
        }
    }

    pub fn new_event_logging_mutex_guard<S: EventLogStatics, T>(
        evt_id: u64,
        guard: MutexGuard<'_, T>,
    ) -> EventLoggingMutexGuard<'_, S, T> {
        EventLoggingMutexGuard {
            evt_id,
            guard,
            phantom: PhantomData,
        }
    }

    #[cold]
    pub fn open_event_log(
        dst: &Path,
        schema: &EventLogSchema,
        gs_handle: &'static GlobalStateHandle,
    ) -> eyre::Result<()> {
        let mut gs = gs_handle.write();
        if !matches!(&*gs, GlobalState::NotYetOpen) {
            panic!("event log has already been opened");
        }
        let mut dst = lz4::EncoderBuilder::new()
            .build(BufWriter::new(File::create(dst).wrap_err_with(|| {
                format!("Opening {:?} to create EventLog", dst)
            })?))
            .wrap_err("opening lz4")?;
        let mut metadata = Cursor::new(Vec::new());
        ciborium::ser::into_writer(schema, &mut metadata)
            .expect("serialization of event log description succeeds");
        let metadata = metadata.into_inner();
        dst.write_all(&(metadata.len() as u64).to_le_bytes())?;
        dst.write_all(&metadata)?;
        let system_start = Instant::now();
        dst.write_all(
            &(SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64)
                .to_le_bytes(),
        )?;
        dst.flush()?;
        let new_buffers = SegQueue::new();
        *gs = GlobalState::Open {
            system_start,
            new_buffers,
            writer: Mutex::new(EventLogWriter {
                dst,
                sources: Vec::new(),
                sources_second_buffer: Vec::new(),
            }),
        };
        std::thread::spawn(move || loop {
            let gs = gs_handle.read();
            if let GlobalState::Open {
                system_start: _,
                new_buffers,
                writer,
            } = &*gs
            {
                writer
                    .lock()
                    .flush(new_buffers)
                    .expect("Failed to flush event log");
            } else {
                break;
            }
            std::thread::sleep(EVENT_LOG_POLL_DURATION);
        });
        Ok(())
    }

    #[cold]
    pub fn close_event_log(gs: &GlobalStateHandle) -> eyre::Result<()> {
        let gs = std::mem::replace(gs.write().deref_mut(), GlobalState::Closed);
        match gs {
            GlobalState::NotYetOpen => panic!("event log has never been opened"),
            GlobalState::Open {
                system_start: _,
                new_buffers,
                writer,
            } => {
                let mut writer = writer.into_inner();
                writer
                    .flush(&new_buffers)
                    .context("Final flush for event log")?;
                writer.dst.finish().1.context("finalizing event log lz4")?;
            }
            GlobalState::Closed => panic!("event log has already been closed"),
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! define_events {
    (@eventdescrkind lock) => {$crate::EventKind::Lock};
    (@eventdescrkind span) => {$crate::EventKind::Span};
    (@eventdescrkind oneoff) => {$crate::EventKind::OneOff};
    (@makestruct $eventname:ident) => {#[must_use] pub struct $eventname;};
    (@makestruct $eventname:ident { $($argname:ident : $argty:ty),* }) => {
        #[must_use]
        pub struct $eventname {
            $(pub $argname : $argty),*
        }
    };
    (@buildbuf [$self:expr] $eventname:ident { $($argname:ident : $argty:ty),* }) => {{
        let mut out = [0; {
            1 $(+ <$argty as $crate::EventLoggable>::SIZE)*
        }];
        out[0] = $eventname;
        let buf = &mut out[1..];
        $(
            let (current, next) = buf.split_at_mut(<$argty as $crate::EventLoggable>::SIZE);
            <$argty as $crate::EventLoggable>::encode(&$self.$argname, current);
            let buf = next;
        )*
        let _ = buf;
        out
    }};
    (@impl lock $eventname:ident { $($argname:ident : $argty:ty),* }) => {
        impl $eventname {
            #[inline(always)]
            pub fn lock<'a, T>(&self, lock: &'a parking_lot::Mutex<T>) -> $crate::EventLoggingMutexGuard<'a, TheStatics, T> {
                let now = std::time::Instant::now();
                const EVT: u32 = InternalEventId::$eventname as u32;
                let buf = $crate::define_events!(@buildbuf [self] EVT {$($argname : $argty),*});
                THREAD_LOCAL.with(|tl| {
                    if let Some(tl) = tl {
                        let evt_id = tl.submit_raw(now, &buf);
                        let guard = lock.lock();
                        let now = std::time::Instant::now();
                        tl.submit_event_with_event_id(
                            now,
                            InternalEventId::EventLogInternalAcquiredLock as u32,
                            evt_id,
                        );
                        $crate::internal::new_event_logging_mutex_guard(evt_id, guard)
                    } else {
                        $crate::internal::new_event_logging_mutex_guard(0, lock.lock())
                    }
                })
            }
            // TODO: support r/w locks
        }
    };
    (@impl span $eventname:ident { $($argname:ident : $argty:ty),* }) => {
        impl $eventname {
            #[inline(always)]
            #[must_use]
            pub fn start(&self) -> $crate::SpanFinishNotifier<TheStatics> {
                let now = std::time::Instant::now();
                const EVT: u32 = InternalEventId::$eventname as u32;
                let buf = $crate::define_events!(@buildbuf [self] EVT {$($argname : $argty),*});
                let id = THREAD_LOCAL.with(move |tl| {
                    if let Some(tl) = tl {
                        tl.submit_raw(now, &buf)
                    } else {
                        0
                    }
                });
                $crate::internal::new_span_finisher(id)
            }
        }
    };
    (@impl oneoff $eventname:ident { $($argname:ident : $argty:ty),* }) => {
        impl $eventname {
            #[inline(always)]
            pub fn submit(&self) {
                let now = std::time::Instant::now();
                const EVT: u32 = InternalEventId::$eventname as u32;
                let buf = $crate::define_events!(@buildbuf [self] EVT {$($argname : $argty),*});
                THREAD_LOCAL.with(move |tl| {
                    if let Some(tl) = tl {
                        tl.submit_raw(now, &buf);
                    }
                });
            }
        }
    };
    ($vis:vis schema $modname:ident {
        $($eventkind:ident $eventname:ident $({
            $($argname:ident : $argty:ty),*
            $(,)?
        })?),*
        $(,)?
    }) => {
        $vis mod $modname {
            #[allow(unused_imports)]
            use super::*;

            static GLOBAL: $crate::internal::GlobalStateHandle =
                parking_lot::RwLock::const_new(
                    <parking_lot::RawRwLock as parking_lot::lock_api::RawRwLock>::INIT,
                    $crate::internal::GlobalState::NotYetOpen,
            );
            thread_local! {
                static THREAD_LOCAL: Option<$crate::internal::ThreadLocal> =
                    $crate::internal::ThreadLocal::new(&GLOBAL);
            }
            #[doc(hidden)]
            pub struct TheStatics;
            impl $crate::internal::EventLogStatics for TheStatics {
                const LOCAL_KEY:
                    &'static std::thread::LocalKey<Option<$crate::internal::ThreadLocal>> =
                    &THREAD_LOCAL;
                const INTERNAL_SPAN_FINISH: u32 =
                    InternalEventId::EventLogInternalSpanFinish as u32;
                const INTERNAL_ACQUIRED_LOCK: u32 =
                    InternalEventId::EventLogInternalAcquiredLock as u32;
                const INTERNAL_RELEASED_LOCK: u32 =
                    InternalEventId::EventLogInternalReleasedLock as u32;
            }

            #[allow(unused)]
            pub type MutexGuard<'a, T> = $crate::EventLoggingMutexGuard<'a, TheStatics, T>;

            #[repr(u32)]
            enum InternalEventId {
                $($eventname,)*
                EventLogInternalSpanFinish,
                EventLogInternalAcquiredLock,
                EventLogInternalReleasedLock,
            }

            $(
                $crate::define_events!(@makestruct $eventname $({ $($argname : $argty),* })?);
                $crate::define_events!(@impl $eventkind $eventname { $($($argname : $argty),*)? });
            )*

            #[cold]
            #[inline(never)]
            fn dump_schema() -> $crate::EventLogSchema {
                $crate::EventLogSchema {
                    events: vec![
                        // These events MUST be visited in the same order as the EventId span
                        // above.
                        $($crate::EventDescription{
                            name: stringify!($eventname).to_string(),
                            kind: $crate::define_events!(@eventdescrkind $eventkind),
                            args: vec![$($(
                                $crate::EventArgument {
                                    name: stringify!($argname).to_string(),
                                    ty_name: stringify!($argty).to_string(),
                                    ty: <$argty as $crate::EventLoggable>::TYPE,
                                },
                            )*)?],
                        },)*
                    ],
                }
            }
            #[cold]
            pub fn open_event_log(dst: impl std::convert::AsRef<std::path::Path>) -> ::eyre::Result<()> {
                $crate::internal::open_event_log(dst.as_ref(), &dump_schema(), &GLOBAL)
            }

            #[cold]
            pub fn close_event_log() -> ::eyre::Result<()> {
                $crate::internal::close_event_log(&GLOBAL)
            }
        }
    };
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum EventLogEntryBody {
    SpanFinished {
        event_id: u64,
    },
    LockAcquired {
        event_id: u64,
    },
    LockReleased {
        event_id: u64,
    },
    Event {
        event_kind: u32,
        args: SmallVec<[i128; 4]>,
    },
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EventLogEntry {
    pub timestamp: Duration,
    pub thread_id: u64,
    pub body: EventLogEntryBody,
}

pub struct EventLogReader {
    r: lz4::Decoder<BufReader<File>>,
    schema: EventLogSchema,
    ele: EventLogEntry,
    current_thread: u64,
    current_thread_buffer: Vec<u32>,
    current_thread_buffer_read_pos: usize,
    last_event_timestamp: Vec<Duration>,
}

impl EventLogReader {
    pub fn open(path: impl AsRef<Path>) -> eyre::Result<Self> {
        Self::open_inner(path.as_ref())
    }
    fn open_inner(path: &Path) -> eyre::Result<Self> {
        let mut reader = lz4::Decoder::new(BufReader::new(
            File::open(path).with_context(|| format!("Opening {path:?}"))?,
        ))
        .context("lz4 opening")?;
        let mut u64_buf = [0; 8];
        reader.read_exact(&mut u64_buf)?;
        let mut metadata_buf = vec![
            0;
            usize::try_from(u64::from_le_bytes(u64_buf))
                .context("metadata buffer too big for usize")?
        ];
        reader.read_exact(&mut metadata_buf)?;
        let schema = ciborium::de::from_reader(Cursor::new(metadata_buf))
            .context("unable to decode event buffer schema")?;
        reader.read_exact(&mut u64_buf)?;
        // This reads the unix timestamp in milliseconds when the event log was started. We're
        // ignoring this for now.
        Ok(EventLogReader {
            r: reader,
            schema,
            ele: EventLogEntry {
                timestamp: Default::default(),
                thread_id: 0,
                body: EventLogEntryBody::SpanFinished { event_id: 0 },
            },
            current_thread: 0,
            current_thread_buffer: Vec::new(),
            current_thread_buffer_read_pos: 0,
            last_event_timestamp: Vec::new(),
        })
    }
    pub fn schema(&self) -> &EventLogSchema {
        &self.schema
    }
    pub fn next_event(&mut self) -> eyre::Result<Option<&EventLogEntry>> {
        if self.current_thread_buffer_read_pos >= self.current_thread_buffer.len() {
            // Read the next chunk of data in.
            let thread_id = {
                let mut buf = [0; 8];
                // First do a single byte read, so that we can use read_exact most of the time.
                if self.r.read(&mut buf[0..1])? == 0 {
                    // We've hit EOF
                    return Ok(None);
                }
                self.r.read_exact(&mut buf[1..])?;
                u64::from_le_bytes(buf)
            };
            let num_words = {
                let mut buf = [0; 8];
                self.r.read_exact(&mut buf)?;
                usize::try_from(u64::from_le_bytes(buf))
                    .context("single thread chunk is too big for usize")?
            };
            self.current_thread_buffer.resize(num_words, 0);
            self.r
                .read_exact(bytemuck::cast_slice_mut(&mut self.current_thread_buffer))?;
            self.current_thread = thread_id;
            self.current_thread_buffer_read_pos = 0;
            if self.last_event_timestamp.len()
                <= usize::try_from(thread_id).context("too many threads")?
            {
                self.last_event_timestamp
                    .resize(thread_id as usize + 1, Duration::default());
            }
        }
        fn decode_u64(pair: &[u32]) -> u64 {
            u64::from(pair[0]) | (u64::from(pair[1]) << 32)
        }
        let timestamp = {
            let delta_ns = decode_u64(
                self.current_thread_buffer
                    .get(0..2)
                    .context("Unexpected EOF reading timestamp delta")?,
            );
            let dst = &mut self.last_event_timestamp[self.current_thread as usize];
            *dst += Duration::from_nanos(delta_ns);
            self.current_thread_buffer_read_pos += 2;
            *dst
        };
        let tag = *self
            .current_thread_buffer
            .get(self.current_thread_buffer_read_pos)
            .context("Unexpected EOF reading event tag")? as usize;
        self.current_thread_buffer_read_pos += 1;
        self.ele = EventLogEntry {
            timestamp,
            thread_id: self.current_thread,
            body: if let Some(evt) = self.schema.events.get(tag) {
                let mut args: SmallVec<[i128; 4]> = Default::default();
                for arg in evt.args.iter() {
                    use EventArgumentType::*;
                    match arg.ty {
                        Bool | U8 | U16 | U32 => {
                            let word = self
                                .current_thread_buffer
                                .get(self.current_thread_buffer_read_pos)
                                .context("Unexpected EOF trying to read word")?;
                            self.current_thread_buffer_read_pos += 1;
                            args.push(i128::from(*word));
                        }
                        I8 | I16 | I32 => {
                            let word = self
                                .current_thread_buffer
                                .get(self.current_thread_buffer_read_pos)
                                .context("Unexpected EOF trying to read word")?;
                            self.current_thread_buffer_read_pos += 1;
                            args.push(i128::from(*word as i32));
                        }
                        U64 => {
                            let word = decode_u64(
                                self.current_thread_buffer
                                    .get(
                                        self.current_thread_buffer_read_pos
                                            ..self.current_thread_buffer_read_pos + 2,
                                    )
                                    .context("Unexpected EOF trying to read words")?,
                            );
                            self.current_thread_buffer_read_pos += 2;
                            args.push(i128::from(word));
                        }
                        I64 => {
                            let word = decode_u64(
                                self.current_thread_buffer
                                    .get(
                                        self.current_thread_buffer_read_pos
                                            ..self.current_thread_buffer_read_pos + 2,
                                    )
                                    .context("Unexpected EOF trying to read words")?,
                            );
                            self.current_thread_buffer_read_pos += 2;
                            args.push(i128::from(word as i64));
                        }
                    }
                }
                EventLogEntryBody::Event {
                    event_kind: tag as u32,
                    args,
                }
            } else {
                let event_id = decode_u64(
                    self.current_thread_buffer
                        .get(
                            self.current_thread_buffer_read_pos
                                ..self.current_thread_buffer_read_pos + 2,
                        )
                        .context("Unexpected EOF trying to read event id")?,
                );
                self.current_thread_buffer_read_pos += 2;
                if tag == self.schema.events.len() {
                    // Finished span
                    EventLogEntryBody::SpanFinished { event_id }
                } else if tag == self.schema.events.len() + 1 {
                    // Acquired lock
                    EventLogEntryBody::LockAcquired { event_id }
                } else if tag == self.schema.events.len() + 2 {
                    // Released lock
                    EventLogEntryBody::LockReleased { event_id }
                } else {
                    eyre::bail!("Unexpected event log tag {tag}");
                }
            },
        };
        Ok(Some(&self.ele))
    }
}

#[cfg(test)]
mod tests;
