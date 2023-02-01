use crate::{
    EventArgument, EventArgumentType::*, EventDescription, EventKind::*, EventLogEntry,
    EventLogEntryBody::*, EventLogReader, EventLogSchema,
};
use parking_lot::Mutex;
use smallvec::smallvec;
use std::time::Duration;

super::define_events! {
    schema test_schema {
        oneoff Thing1 {
            a_min: i8,
            b_min: u8,
            c_min: bool,
            d_min: i16,
            e_min: u16,
            f_min: i32,
            g_min: u32,
            h_min: i64,
            i_min: u64,
            a_max: i8,
            b_max: u8,
            c_max: bool,
            d_max: i16,
            e_max: u16,
            f_max: i32,
            g_max: u32,
            h_max: i64,
            i_max: u64,
        },
        lock MyLock,
        span Blarg {
            x: i64,
            y: u64,
        },
    }
}

// Because event log uses global variables to log events, we can only have a single test for each
// schema we define.

#[test]
fn test_it() {
    let events_snapshot = vec![
        EventLogEntry {
            timestamp: Default::default(),
            thread_id: 0,
            body: Event {
                event_kind: 1,
                args: smallvec![],
            },
        },
        EventLogEntry {
            timestamp: Default::default(),
            thread_id: 0,
            body: LockAcquired { event_id: 0 },
        },
        EventLogEntry {
            timestamp: Default::default(),
            thread_id: 0,
            body: Event {
                event_kind: 2,
                args: smallvec![7458, 85,],
            },
        },
        EventLogEntry {
            timestamp: Default::default(),
            thread_id: 0,
            body: Event {
                event_kind: 0,
                args: smallvec![
                    -128,
                    0,
                    0,
                    -32768,
                    0,
                    -2147483648,
                    0,
                    -9223372036854775808,
                    0,
                    127,
                    255,
                    1,
                    32767,
                    65535,
                    2147483647,
                    4294967295,
                    9223372036854775807,
                    18446744073709551615,
                ],
            },
        },
        EventLogEntry {
            timestamp: Default::default(),
            thread_id: 0,
            body: SpanFinished { event_id: 2 },
        },
        EventLogEntry {
            timestamp: Default::default(),
            thread_id: 0,
            body: LockReleased { event_id: 0 },
        },
    ];
    let schema_snapshot = EventLogSchema {
        events: vec![
            EventDescription {
                name: "Thing1".to_string(),
                kind: OneOff,
                args: vec![
                    EventArgument {
                        name: "a_min".to_string(),
                        ty_name: "i8".to_string(),
                        ty: I8,
                    },
                    EventArgument {
                        name: "b_min".to_string(),
                        ty_name: "u8".to_string(),
                        ty: U8,
                    },
                    EventArgument {
                        name: "c_min".to_string(),
                        ty_name: "bool".to_string(),
                        ty: Bool,
                    },
                    EventArgument {
                        name: "d_min".to_string(),
                        ty_name: "i16".to_string(),
                        ty: I16,
                    },
                    EventArgument {
                        name: "e_min".to_string(),
                        ty_name: "u16".to_string(),
                        ty: U16,
                    },
                    EventArgument {
                        name: "f_min".to_string(),
                        ty_name: "i32".to_string(),
                        ty: I32,
                    },
                    EventArgument {
                        name: "g_min".to_string(),
                        ty_name: "u32".to_string(),
                        ty: U32,
                    },
                    EventArgument {
                        name: "h_min".to_string(),
                        ty_name: "i64".to_string(),
                        ty: I64,
                    },
                    EventArgument {
                        name: "i_min".to_string(),
                        ty_name: "u64".to_string(),
                        ty: U64,
                    },
                    EventArgument {
                        name: "a_max".to_string(),
                        ty_name: "i8".to_string(),
                        ty: I8,
                    },
                    EventArgument {
                        name: "b_max".to_string(),
                        ty_name: "u8".to_string(),
                        ty: U8,
                    },
                    EventArgument {
                        name: "c_max".to_string(),
                        ty_name: "bool".to_string(),
                        ty: Bool,
                    },
                    EventArgument {
                        name: "d_max".to_string(),
                        ty_name: "i16".to_string(),
                        ty: I16,
                    },
                    EventArgument {
                        name: "e_max".to_string(),
                        ty_name: "u16".to_string(),
                        ty: U16,
                    },
                    EventArgument {
                        name: "f_max".to_string(),
                        ty_name: "i32".to_string(),
                        ty: I32,
                    },
                    EventArgument {
                        name: "g_max".to_string(),
                        ty_name: "u32".to_string(),
                        ty: U32,
                    },
                    EventArgument {
                        name: "h_max".to_string(),
                        ty_name: "i64".to_string(),
                        ty: I64,
                    },
                    EventArgument {
                        name: "i_max".to_string(),
                        ty_name: "u64".to_string(),
                        ty: U64,
                    },
                ],
            },
            EventDescription {
                name: "MyLock".to_string(),
                kind: Lock,
                args: vec![],
            },
            EventDescription {
                name: "Blarg".to_string(),
                kind: Span,
                args: vec![
                    EventArgument {
                        name: "x".to_string(),
                        ty_name: "i64".to_string(),
                        ty: I64,
                    },
                    EventArgument {
                        name: "y".to_string(),
                        ty_name: "u64".to_string(),
                        ty: U64,
                    },
                ],
            },
        ],
    };
    let tmp = tempfile::NamedTempFile::new().unwrap();
    test_schema::open_event_log(tmp.path()).unwrap();
    let lock = Mutex::new(());
    let guard = test_schema::MyLock.lock(&lock);
    let span = test_schema::Blarg { x: 7458, y: 85 }.start();
    test_schema::Thing1 {
        a_min: i8::MIN,
        b_min: u8::MIN,
        c_min: false,
        d_min: i16::MIN,
        e_min: u16::MIN,
        f_min: i32::MIN,
        g_min: u32::MIN,
        h_min: i64::MIN,
        i_min: u64::MIN,
        a_max: i8::MAX,
        b_max: u8::MAX,
        c_max: true,
        d_max: i16::MAX,
        e_max: u16::MAX,
        f_max: i32::MAX,
        g_max: u32::MAX,
        h_max: i64::MAX,
        i_max: u64::MAX,
    }
    .submit();
    std::thread::sleep(Duration::from_millis(500));
    span.finish();
    std::mem::drop(guard);
    test_schema::close_event_log().unwrap();
    let mut r = EventLogReader::open(tmp.path()).unwrap();
    assert_eq!(r.schema(), &schema_snapshot);
    let mut evts = Vec::new();
    while let Some(evt) = r.next_event().unwrap() {
        evts.push(evt.clone());
    }
    assert_eq!(evts.len(), events_snapshot.len());
    for (evt, snap) in evts.iter().zip(events_snapshot.iter()) {
        assert_eq!(evt.body, snap.body);
        assert_eq!(evt.thread_id, snap.thread_id);
    }
}
