import dataclasses
import subprocess
from collections import defaultdict
from pathlib import Path

import cbor2
import plotly.express as px

ROOT = Path(__file__).resolve().parent.parent.parent


def _read_evt_log_raw(x: Path):
    # TODO: run in release mode?
    proc = subprocess.Popen(
        [
            "cargo",
            "run",
            "--bin",
            "mac-n-cheese-inspector",
            "--",
            "read-event-log",
            x.resolve(),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        cwd=ROOT,
    )
    try:
        return cbor2.load(proc.stdout)
    finally:
        proc.kill()
        proc.wait()


def _duration2ns(ts):
    return 1000000000 * ts["secs"] + ts["nanos"]


class EventBase:
    timestamp_ns: int


class OneOff(EventBase):
    pass


class Span(EventBase):
    duration_ns: int | None


class Lock(EventBase):
    acquire_duration_ns: int | None
    hold_duration_ns: int | None


@dataclasses.dataclass(frozen=True)
class SpanFinished(EventBase):
    timestamp_ns: int
    event_id: int


@dataclasses.dataclass(frozen=True)
class LockAcquired(EventBase):
    timestamp_ns: int
    event_id: int


@dataclasses.dataclass(frozen=True)
class LockReleased(EventBase):
    timestamp_ns: int
    event_id: int


def _parse_schema(schema):
    out = {}
    base_fields = [("timestamp_ns", int)]
    cls_info = {
        "Span": (
            Span,
            base_fields
            + [("duration_ns", int | None, dataclasses.field(default=None))],
        ),
        "OneOff": (OneOff, base_fields),
        "Lock": (
            Lock,
            base_fields
            + [
                ("acquire_duration_ns", int | None, dataclasses.field(default=None)),
                ("hold_duration_ns", int | None, dataclasses.field(default=None)),
            ],
        ),
    }
    by_number = []
    for evt in schema["events"]:
        base, fields = cls_info[evt["kind"]]
        cls = dataclasses.make_dataclass(
            evt["name"],
            [arg["name"] for arg in evt["args"]] + fields,
            bases=(base,),
            frozen=True,
        )
        setattr(cls, "METADATA", evt)
        by_number.append(cls)
        out[evt["name"]] = cls
    return out, by_number


class EventLog:
    def __init__(self, path: Path):
        raw = _read_evt_log_raw(path)
        self.schema, kinds_by_number = _parse_schema(raw["schema"])
        for k, v in self.schema.items():
            setattr(self, k, v)
        self.events_by_thread = dict()
        for evt in raw["events"]:
            if evt["thread_id"] not in self.events_by_thread:
                self.events_by_thread[evt["thread_id"]] = []
            body = evt["body"]
            thread_evts = self.events_by_thread[evt["thread_id"]]
            ts = _duration2ns(evt["timestamp"])
            match body["type"]:
                case "Event":
                    thread_evts.append(
                        kinds_by_number[body["event_kind"]](
                            *body["args"],
                            timestamp_ns=ts,
                        )
                    )
                case "SpanFinished":
                    existing = thread_evts[body["event_id"]]
                    assert existing.duration_ns is None
                    assert existing.timestamp_ns <= ts
                    thread_evts[body["event_id"]] = dataclasses.replace(
                        existing, duration_ns=ts - existing.timestamp_ns
                    )
                    thread_evts.append(SpanFinished(ts, body["event_id"]))
                case "LockAcquired":
                    existing = thread_evts[body["event_id"]]
                    assert existing.acquire_duration_ns is None
                    assert existing.timestamp_ns <= ts
                    thread_evts[body["event_id"]] = dataclasses.replace(
                        existing, acquire_duration_ns=ts - existing.timestamp_ns
                    )
                    thread_evts.append(LockAcquired(ts, body["event_id"]))
                case "LockReleased":
                    existing = thread_evts[body["event_id"]]
                    assert existing.hold_duration_ns is None
                    assert existing.timestamp_ns <= ts
                    thread_evts[body["event_id"]] = dataclasses.replace(
                        existing,
                        hold_duration_ns=ts
                        - existing.timestamp_ns
                        - existing.acquire_duration_ns,
                    )
                    thread_evts.append(LockReleased(ts, body["event_id"]))
                case ty:
                    raise Exception(f"Unknown event type {repr(ty)}")

    @property
    def span_kinds(self):
        return [x for x in self.schema.values() if issubclass(x, Span)]

    @property
    def oneoff_kinds(self):
        return [x for x in self.schema.values() if issubclass(x, OneOff)]

    @property
    def lock_kinds(self):
        return [x for x in self.schema.values() if issubclass(x, Lock)]

    @property
    def all_events(self):
        for events in self.events_by_thread.values():
            yield from events

    def kind(self, kind):
        return self.schema[kind] if isinstance(kind, str) else kind

    def all_events_of(self, *kinds):
        types = set(map(self.kind, kinds))
        for evt in self.all_events:
            if type(evt) in types:
                yield evt

    def has_events_of(self, *kinds):
        types = set(map(self.kind, kinds))
        for evt in self.all_events:
            if type(evt) in types:
                return True
        return False


def visualize_lock_evts(title, evts):
    data = defaultdict(lambda: [])
    for evt in evts:
        for field in ["acquire_duration_ns", "hold_duration_ns"]:
            data[field].append({"time": evt.timestamp_ns, field: getattr(evt, field)})
    for field in ["acquire_duration_ns", "hold_duration_ns"]:
        px.box(
            [x[field] for x in data[field]],
            title=f"{title} {field}",
        ).show()
        px.scatter(
            data[field],
            title=f"{title} {field}",
            x="time",
            y=field,
        ).show()
