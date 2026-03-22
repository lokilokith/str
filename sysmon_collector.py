"""
sysmon_collector.py — SentinelTrace Live Collector  (MySQL edition)
====================================================================
All DB interactions updated to use the MySQL-compatible db.py layer.

Changes vs the PostgreSQL version
-----------------------------------
* get_cursor() is now a context manager — all call sites updated to:
      with get_cursor(conn) as cur:
          cur.execute(...)
* checked_insert() signature updated: expect_duplicate kwarg supported.
* DB_STRICT imported from db (not re-declared here).
* ensure_events_table() uses context-manager get_cursor.
* consumer_thread heartbeat UPDATE uses context-manager get_cursor.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import queue
import random
import sys
import threading
import time
import xml.etree.ElementTree as ET
from enum import Enum
from itertools import count as _count_iter
from pathlib import Path
from typing import Any

log = logging.getLogger("sysmon_collector")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

# ---------------------------------------------------------------------------
# Platform guard
# ---------------------------------------------------------------------------
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import pywintypes          # noqa: F401
    import win32evtlog
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
else:
    win32evtlog = win32service = win32serviceutil = win32event = servicemanager = None
    log.warning(
        "sysmon_collector: Windows APIs unavailable (%s). "
        "Live collection disabled; upload-analysis path is unaffected.",
        platform.system(),
    )

from dashboard.db import (          # noqa: E402
    DB_STRICT,
    checked_insert,
    get_db_connection,
    get_cursor,
)
from dashboard.event_parser import parse_event                    # noqa: E402
from dashboard.analysis_engine import process_event               # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CHANNEL_NAME           = "Microsoft-Windows-Sysmon/Operational"
BATCH_SIZE             = 50
POLL_INTERVAL          = 1
BOOKMARK_EVERY         = 50
REPLAY_BATCH_SIZE      = 200
ANALYSIS_QUEUE_MAX     = 5_000
METRICS_INTERVAL_SECS  = 30

BACKPRESSURE_THRESHOLD = float(os.environ.get("BACKPRESSURE_THRESHOLD",    "0.70"))
BACKPRESSURE_MAX_SLEEP = float(os.environ.get("BACKPRESSURE_MAX_SLEEP_MS", "50")) / 1000

BASE_DIR          = Path(__file__).resolve().parent
DATA_DIR          = BASE_DIR / "data"
BOOKMARK_FILE     = DATA_DIR / "sysmon_bookmark.xml"

OVERFLOW_FILE     = DATA_DIR / "sysmon_overflow.jsonl"
OVERFLOW_CKPT     = DATA_DIR / "sysmon_overflow_checkpoint.txt"
OVERFLOW_MAX_MB   = int(os.environ.get("OVERFLOW_MAX_MB",          "256"))
OVERFLOW_WARN_PCT = int(os.environ.get("OVERFLOW_WARN_PCT",        "80"))
OVERFLOW_CRIT_PCT = int(os.environ.get("OVERFLOW_CRIT_PCT",        "95"))

ANALYSIS_OVF_FILE = DATA_DIR / "sysmon_analysis_overflow.jsonl"
ANALYSIS_OVF_CKPT = DATA_DIR / "sysmon_analysis_overflow_checkpoint.txt"
ANALYSIS_OVF_MB   = int(os.environ.get("ANALYSIS_OVERFLOW_MAX_MB", "64"))

CB_FAILURE_THRESHOLD = int(os.environ.get("CB_FAILURE_THRESHOLD",  "5"))
CB_COOLDOWN_SECONDS  = int(os.environ.get("CB_COOLDOWN_SECONDS",   "30"))

_INGEST_STRICT: bool = os.environ.get("INGEST_STRICT", "0") == "1"

shutdown_event = threading.Event()

# ---------------------------------------------------------------------------
# Priority queue
# ---------------------------------------------------------------------------
_CRITICAL_IDS = frozenset({1, 8, 9, 12, 13, 14, 19, 25})
_HIGH_IDS     = frozenset({3, 7, 10, 11, 22, 23})
_MEDIUM_IDS   = frozenset({17, 18, 26, 27})

PRIORITY_CRITICAL = 0
PRIORITY_HIGH     = 1
PRIORITY_MEDIUM   = 2
PRIORITY_LOW      = 3


def _event_priority(evt: dict) -> int:
    try:
        eid = int(evt.get("event_id") or 0)
    except (TypeError, ValueError):
        eid = 0
    if eid in _CRITICAL_IDS:
        return PRIORITY_CRITICAL
    if eid in _HIGH_IDS:
        return PRIORITY_HIGH
    if eid in _MEDIUM_IDS:
        return PRIORITY_MEDIUM
    return PRIORITY_LOW


_seq = _count_iter()


def _make_item(evt: dict) -> tuple[int, int, dict]:
    return (_event_priority(evt), next(_seq), evt)


def _unwrap(item: tuple[int, int, dict]) -> dict:
    return item[2]


event_queue:    queue.PriorityQueue = queue.PriorityQueue(maxsize=10_000)
analysis_queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=ANALYSIS_QUEUE_MAX)

# ---------------------------------------------------------------------------
# Overflow disk pressure helpers
# ---------------------------------------------------------------------------
def _overflow_fill_pct(overflow_file: Path, max_mb: int) -> float:
    if not overflow_file.exists():
        return 0.0
    return overflow_file.stat().st_size / (max_mb * 1024 * 1024) * 100.0


def _overflow_pressure_level(fill_pct: float) -> str:
    if fill_pct >= OVERFLOW_CRIT_PCT:
        return "crit"
    if fill_pct >= OVERFLOW_WARN_PCT:
        return "warn"
    return "ok"


# ---------------------------------------------------------------------------
# PipelineMetrics
# ---------------------------------------------------------------------------
class PipelineMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {
            "events_ingested":          0,
            "events_analysed":          0,
            "ingest_errors":            0,
            "analysis_errors":          0,
            "ingest_overflow_count":    0,
            "analysis_overflow_count":  0,
            "ingest_drops":             0,
            "analysis_drops":           0,
            "ingest_skips":             0,
            "replay_ingested":          0,
            "replay_analysed":          0,
            "priority_critical":        0,
            "priority_high":            0,
            "priority_medium":          0,
            "priority_low":             0,
        }
        self._start_time = time.monotonic()

    def inc(self, counter: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[counter] = self._counters.get(counter, 0) + amount

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            snap = dict(self._counters)

        elapsed = time.monotonic() - self._start_time
        snap["uptime_seconds"] = round(elapsed, 1)
        snap["eps_ingested"]   = round(snap["events_ingested"] / elapsed, 2) if elapsed > 0 else 0.0

        snap["event_queue_size"]    = event_queue.qsize()
        snap["event_queue_max"]     = event_queue.maxsize
        snap["event_queue_pct"]     = round(event_queue.qsize() / event_queue.maxsize * 100, 1)
        snap["analysis_queue_size"] = analysis_queue.qsize()
        snap["analysis_queue_max"]  = analysis_queue.maxsize
        snap["analysis_queue_pct"]  = round(analysis_queue.qsize() / analysis_queue.maxsize * 100, 1)

        snap["ingest_breaker_state"]   = _ingest_breaker.state.value
        snap["analysis_breaker_state"] = _analysis_breaker.state.value

        ingest_fill   = _overflow_fill_pct(OVERFLOW_FILE,     OVERFLOW_MAX_MB)
        analysis_fill = _overflow_fill_pct(ANALYSIS_OVF_FILE, ANALYSIS_OVF_MB)
        snap["ingest_overflow_fill_pct"]   = round(ingest_fill, 1)
        snap["analysis_overflow_fill_pct"] = round(analysis_fill, 1)
        snap["ingest_overflow_pressure"]   = _overflow_pressure_level(ingest_fill)
        snap["analysis_overflow_pressure"] = _overflow_pressure_level(analysis_fill)
        snap["ingest_overflow_exists"]     = OVERFLOW_FILE.exists()
        snap["analysis_overflow_exists"]   = ANALYSIS_OVF_FILE.exists()
        return snap

    def log_summary(self) -> None:
        s = self.snapshot()
        ing_pressure = s["ingest_overflow_pressure"]
        ana_pressure = s["analysis_overflow_pressure"]
        overflow_str = (
            f"ing={ing_pressure}({s['ingest_overflow_fill_pct']}%) "
            f"ana={ana_pressure}({s['analysis_overflow_fill_pct']}%)"
        )
        log.info(
            "[Metrics] uptime=%.0fs eps=%.1f "
            "ingested=%d analysed=%d "
            "ingest_q=%d(%.0f%%) analysis_q=%d(%.0f%%) "
            "err=ing:%d/ana:%d "
            "overflow=[%s] "
            "cb=ing:%s/ana:%s "
            "priority=C:%d H:%d M:%d L:%d",
            s["uptime_seconds"], s["eps_ingested"],
            s["events_ingested"], s["events_analysed"],
            s["event_queue_size"],    s["event_queue_pct"],
            s["analysis_queue_size"], s["analysis_queue_pct"],
            s["ingest_errors"], s["analysis_errors"],
            overflow_str,
            s["ingest_breaker_state"], s["analysis_breaker_state"],
            s["priority_critical"], s["priority_high"],
            s["priority_medium"],   s["priority_low"],
        )


_metrics = PipelineMetrics()


def get_pipeline_metrics() -> dict[str, Any]:
    return _metrics.snapshot()


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------
class _State(Enum):
    CLOSED    = "CLOSED"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int, cooldown: int) -> None:
        self.name               = name
        self._failure_threshold = failure_threshold
        self._cooldown          = cooldown
        self._state             = _State.CLOSED
        self._failure_count     = 0
        self._opened_at: float  = 0.0
        self._lock              = threading.Lock()

    @property
    def state(self) -> _State:
        with self._lock:
            return self._state

    @property
    def is_open(self) -> bool:
        return self.state == _State.OPEN

    def allow_attempt(self) -> bool:
        with self._lock:
            if self._state == _State.CLOSED:
                return True
            if self._state == _State.OPEN:
                if time.monotonic() - self._opened_at >= self._cooldown:
                    self._state = _State.HALF_OPEN
                    log.info("[CB:%s] Cooldown elapsed → HALF_OPEN", self.name)
                    return True
                return False
            return False

    def record_success(self) -> None:
        with self._lock:
            recovering = self._state in (_State.HALF_OPEN, _State.OPEN)
            self._state         = _State.CLOSED
            self._failure_count = 0
            if recovering:
                log.info("[CB:%s] Recovered → CLOSED", self.name)

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            if self._state == _State.CLOSED:
                if self._failure_count >= self._failure_threshold:
                    self._state     = _State.OPEN
                    self._opened_at = time.monotonic()
                    log.error(
                        "[CB:%s] %d failures → OPEN. Cooldown %ds.",
                        self.name, self._failure_count, self._cooldown,
                    )
            elif self._state == _State.HALF_OPEN:
                self._state     = _State.OPEN
                self._opened_at = time.monotonic()
                log.warning("[CB:%s] Probe failed → OPEN.", self.name)


_ingest_breaker   = CircuitBreaker("ingest",   CB_FAILURE_THRESHOLD, CB_COOLDOWN_SECONDS)
_analysis_breaker = CircuitBreaker("analysis", CB_FAILURE_THRESHOLD, CB_COOLDOWN_SECONDS)

# ---------------------------------------------------------------------------
# Adaptive backpressure
# ---------------------------------------------------------------------------
def _backpressure_sleep() -> None:
    fill = event_queue.qsize() / event_queue.maxsize
    if fill <= BACKPRESSURE_THRESHOLD:
        return
    scale   = (fill - BACKPRESSURE_THRESHOLD) / (1.0 - BACKPRESSURE_THRESHOLD)
    sleep_s = scale * BACKPRESSURE_MAX_SLEEP
    if sleep_s > 0:
        time.sleep(sleep_s)

# ---------------------------------------------------------------------------
# Disk overflow helpers
# ---------------------------------------------------------------------------
_overflow_last_warn: dict[str, int] = {"ingest": -1, "analysis": -1}
_overflow_warn_lock = threading.Lock()


def _maybe_warn_overflow(overflow_file: Path, max_mb: int, path_name: str) -> None:
    fill_pct = _overflow_fill_pct(overflow_file, max_mb)
    if fill_pct < OVERFLOW_WARN_PCT:
        return
    fill_bucket = int(fill_pct)
    with _overflow_warn_lock:
        if fill_bucket <= _overflow_last_warn.get(path_name, -1):
            return
        _overflow_last_warn[path_name] = fill_bucket
    level = _overflow_pressure_level(fill_pct)
    msg = (
        f"Overflow pressure [{path_name}] {fill_pct:.1f}% "
        f"({overflow_file.stat().st_size // 1024} KB / {max_mb * 1024} KB). "
        f"Restore DB connectivity to prevent data loss."
    )
    if level == "crit":
        log.error("[Overflow:%s] CRITICAL — %s", path_name, msg)
    else:
        log.warning("[Overflow:%s] %s", path_name, msg)


def _overflow_write(
    evt: dict,
    overflow_file: Path,
    overflow_ckpt: Path,
    max_mb: int,
    path_name: str,
) -> bool:
    try:
        if overflow_file.exists():
            size_mb = overflow_file.stat().st_size / (1024 * 1024)
            _maybe_warn_overflow(overflow_file, max_mb, path_name)
            if size_mb >= max_mb:
                _metrics.inc(f"{path_name}_drops")
                count = _metrics.snapshot()[f"{path_name}_drops"]
                if count % 500 == 1:
                    log.error(
                        "[Overflow:%s] Cap reached (%d MB). Dropping event #%d.",
                        path_name, max_mb, count,
                    )
                return False

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        safe = {k: (str(v) if v is not None else None) for k, v in evt.items()}
        with overflow_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(safe) + "\n")
        _metrics.inc(f"{path_name}_overflow_count")
        return True
    except Exception as exc:
        log.error("Overflow write failed (%s): %s", overflow_file.name, exc)
        return False


def _overflow_replay(
    overflow_file: Path,
    checkpoint_file: Path,
    write_fn,
    batch_size: int,
    path_name: str,
) -> tuple[int, int]:
    if not overflow_file.exists():
        return 0, 0

    start_offset = 0
    if checkpoint_file.exists():
        try:
            start_offset = int(checkpoint_file.read_text().strip())
        except ValueError:
            start_offset = 0

    file_size      = overflow_file.stat().st_size
    replayed       = 0
    failed         = 0
    current_offset = start_offset

    try:
        with overflow_file.open("r", encoding="utf-8") as fh:
            fh.seek(start_offset)
            batch: list[dict] = []
            while True:
                line = fh.readline()
                if not line:
                    if batch:
                        ok, err = _replay_batch(batch, write_fn)
                        replayed += ok
                        failed   += err
                        if err == 0:
                            current_offset = fh.tell()
                            _write_checkpoint(checkpoint_file, current_offset)
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    batch.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    log.warning("[Replay:%s] Malformed JSON: %s", path_name, exc)
                    failed += 1
                    continue
                if len(batch) >= batch_size:
                    ok, err = _replay_batch(batch, write_fn)
                    replayed += ok
                    failed   += err
                    if err == 0:
                        current_offset = fh.tell()
                        _write_checkpoint(checkpoint_file, current_offset)
                    batch = []
    except Exception as exc:
        log.error("[Replay:%s] Unexpected error: %s", path_name, exc)

    counter_key = f"replay_{path_name}d"
    _metrics.inc(counter_key, replayed)

    if failed == 0 and current_offset >= file_size:
        _delete_overflow(overflow_file, checkpoint_file)
        log.info("[Replay:%s] Complete — %d events.", path_name, replayed)
    else:
        log.warning(
            "[Replay:%s] Partial — %d ok, %d failed. Checkpoint at byte %d.",
            path_name, replayed, failed, current_offset,
        )
    return replayed, failed


def _replay_batch(batch: list[dict], write_fn) -> tuple[int, int]:
    ok = failed = 0
    for evt in batch:
        try:
            write_fn(evt)
            ok += 1
        except Exception as exc:
            log.warning("[Replay] Item failed: %s", exc)
            failed += 1
    return ok, failed


def _write_checkpoint(ckpt_file: Path, offset: int) -> None:
    try:
        tmp = ckpt_file.with_suffix(".tmp")
        tmp.write_text(str(offset))
        tmp.replace(ckpt_file)
    except Exception as exc:
        log.warning("[Replay] Checkpoint write failed: %s", exc)


def _delete_overflow(overflow_file: Path, checkpoint_file: Path) -> None:
    for f in (overflow_file, checkpoint_file):
        try:
            if f.exists():
                f.unlink()
        except Exception as exc:
            log.warning("Could not delete %s: %s", f.name, exc)

# ---------------------------------------------------------------------------
# DB write functions
# ---------------------------------------------------------------------------
_INSERT_COLUMNS = [
    "event_uid", "event_time", "event_id", "image", "parent_image",
    "command_line", "user", "pid", "ppid", "source_ip", "destination_ip",
    "destination_port", "severity", "computer", "target_filename", "run_id",
]


def _build_insert_values(evt: dict) -> tuple:
    return (
        evt.get("event_uid"),
        evt.get("utc_time") or evt.get("event_time"),
        int(evt.get("event_id") or 0),
        evt.get("image"),
        evt.get("parent_image"),
        evt.get("command_line"),
        evt.get("user"),
        evt.get("pid"),
        evt.get("ppid"),
        evt.get("src_ip"),
        evt.get("dst_ip"),
        evt.get("dst_port"),
        evt.get("severity"),
        evt.get("computer"),
        evt.get("target_filename") or evt.get("file_path"),
        evt.get("run_id", "live"),
    )


def _ingest_write(evt: dict, expect_dup: bool = False) -> None:
    """Write one event to live_events."""
    strict = DB_STRICT or (_INGEST_STRICT and not expect_dup)

    with get_db_connection("live") as conn:
        with get_cursor(conn) as cur:
            inserted = checked_insert(
                cur,
                "live_events",
                _INSERT_COLUMNS,
                _build_insert_values(evt),
                identity_hint=f"event_uid={evt.get('event_uid')}",
                expect_duplicate=expect_dup,
            )
            if not inserted:
                _metrics.inc("ingest_skips")
                if strict and not expect_dup:
                    raise RuntimeError(
                        f"INGEST_STRICT: unexpected INSERT skip for "
                        f"event_uid={evt.get('event_uid')}"
                    )
        conn.commit()


def _ingest_write_replay(evt: dict) -> None:
    _ingest_write(evt, expect_dup=True)


def _analysis_write(evt: dict) -> None:
    with get_db_connection("live") as conn:
        process_event(evt, conn=conn)
        conn.commit()

# ---------------------------------------------------------------------------
# DB schema check
# ---------------------------------------------------------------------------
def ensure_events_table() -> None:
    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute("SELECT 1 FROM live_events LIMIT 1")
    except Exception as exc:
        log.error("DB schema check failed. Run setup.sql first. Error: %s", exc)
        raise SystemExit("Database not ready.") from exc
    log.info("DB schema verified: live_events accessible.")

# ---------------------------------------------------------------------------
# Bookmark persistence
# ---------------------------------------------------------------------------
bookmark_handle = None


def load_bookmark() -> None:
    global bookmark_handle
    if not IS_WINDOWS:
        return
    if BOOKMARK_FILE.exists():
        try:
            xml_text = BOOKMARK_FILE.read_text(encoding="utf-8")
            bookmark_handle = win32evtlog.EvtCreateBookmark(xml_text)
            log.info("Bookmark loaded from %s", BOOKMARK_FILE)
            return
        except Exception as exc:
            log.warning("Failed to load bookmark (%s) — creating fresh.", exc)
    try:
        bookmark_handle = win32evtlog.EvtCreateBookmark(None)
        log.info("Fresh bookmark created.")
    except Exception as exc:
        log.warning("Failed to create bookmark: %s", exc)


def save_bookmark() -> None:
    global bookmark_handle
    if not IS_WINDOWS or bookmark_handle is None:
        return
    try:
        xml_text = win32evtlog.EvtRender(bookmark_handle, win32evtlog.EvtRenderBookmark)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        BOOKMARK_FILE.write_text(xml_text, encoding="utf-8")
    except Exception as exc:
        log.warning("Failed to persist bookmark: %s", exc)


def update_bookmark(event_handle: Any) -> None:
    global bookmark_handle
    if not IS_WINDOWS or bookmark_handle is None or event_handle is None:
        return
    try:
        win32evtlog.EvtUpdateBookmark(bookmark_handle, event_handle)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Thread 1 — Collector (producer)
# ---------------------------------------------------------------------------
_MAX_RETRIES = 3

_PRIORITY_COUNTER_MAP = {
    PRIORITY_CRITICAL: "priority_critical",
    PRIORITY_HIGH:     "priority_high",
    PRIORITY_MEDIUM:   "priority_medium",
    PRIORITY_LOW:      "priority_low",
}


def collector_thread() -> None:
    if not IS_WINDOWS:
        log.warning("collector_thread: Windows API unavailable — exiting.")
        return

    log.info("Starting Sysmon collector on channel: %s", CHANNEL_NAME)
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
    load_bookmark()

    query_handle     = None
    bookmark_counter = 0

    try:
        query_handle = win32evtlog.EvtQuery(CHANNEL_NAME, flags, "*")

        if bookmark_handle:
            try:
                win32evtlog.EvtSeek(
                    query_handle, 0,
                    Bookmark=bookmark_handle,
                    Flags=win32evtlog.EvtSeekRelativeToBookmark,
                )
            except Exception as exc:
                log.warning("EvtSeek failed (first run?): %s", exc)
        else:
            try:
                win32evtlog.EvtSeek(query_handle, 0, Flags=win32evtlog.EvtSeekRelativeToLast)
                evts = win32evtlog.EvtNext(query_handle, 1)
                if evts:
                    update_bookmark(evts[0])
                    if hasattr(evts[0], "Close"):
                        evts[0].Close()
            except Exception as exc:
                log.warning("End-of-log bookmark failed: %s", exc)

        while not shutdown_event.is_set():
            try:
                events = win32evtlog.EvtNext(query_handle, BATCH_SIZE, Timeout=1000)
                if not events:
                    shutdown_event.wait(POLL_INTERVAL)
                    continue

                for event in events:
                    try:
                        xml_str    = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                        xml_root   = ET.fromstring(xml_str)
                        event_dict = parse_event(xml_root)

                        if not event_dict or not event_dict.get("event_uid"):
                            continue
                        event_dict["run_id"] = "live"

                        prio = _event_priority(event_dict)
                        _metrics.inc(_PRIORITY_COUNTER_MAP[prio])
                        _backpressure_sleep()

                        item = _make_item(event_dict)
                        try:
                            event_queue.put_nowait(item)
                        except queue.Full:
                            _overflow_write(
                                event_dict,
                                OVERFLOW_FILE, OVERFLOW_CKPT,
                                OVERFLOW_MAX_MB, "ingest",
                            )

                        bookmark_counter += 1
                        if bookmark_counter >= BOOKMARK_EVERY:
                            update_bookmark(event)
                            bookmark_counter = 0

                    except Exception as exc:
                        log.error("Event render/parse error: %s", exc)
                    finally:
                        if hasattr(event, "Close"):
                            event.Close()

            except Exception as exc:
                log.error("EvtNext failure: %s", exc)
                shutdown_event.wait(POLL_INTERVAL)

    finally:
        if query_handle and hasattr(query_handle, "Close"):
            query_handle.Close()
        log.info("Collector thread exiting.")

# ---------------------------------------------------------------------------
# Thread 2 — Consumer
# ---------------------------------------------------------------------------
def consumer_thread() -> None:
    log.info("Consumer thread started.")
    last_heartbeat = time.time()

    while not shutdown_event.is_set() or not event_queue.empty():
        try:
            item = event_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        evt = _unwrap(item)

        if _ingest_breaker.is_open and not _ingest_breaker.allow_attempt():
            _overflow_write(evt, OVERFLOW_FILE, OVERFLOW_CKPT, OVERFLOW_MAX_MB, "ingest")
            event_queue.task_done()
            continue

        success  = False
        last_exc = None

        for attempt in range(_MAX_RETRIES):
            try:
                with get_db_connection("live") as conn:
                    with get_cursor(conn) as cur:
                        # Heartbeat
                        if time.time() - last_heartbeat > 5:
                            cur.execute(
                                "UPDATE collector_status SET last_seen = NOW() WHERE id = 1"
                            )
                            save_bookmark()
                            last_heartbeat = time.time()

                        inserted = checked_insert(
                            cur,
                            "live_events",
                            _INSERT_COLUMNS,
                            _build_insert_values(evt),
                            identity_hint=f"event_uid={evt.get('event_uid')}",
                            expect_duplicate=False,
                        )
                        if not inserted:
                            _metrics.inc("ingest_skips")
                            if _INGEST_STRICT:
                                raise RuntimeError(
                                    f"INGEST_STRICT: unexpected skip for "
                                    f"event_uid={evt.get('event_uid')}"
                                )

                    conn.commit()

                _metrics.inc("events_ingested")

                ana_item = _make_item(evt)
                try:
                    analysis_queue.put_nowait(ana_item)
                except queue.Full:
                    _overflow_write(
                        evt, ANALYSIS_OVF_FILE, ANALYSIS_OVF_CKPT,
                        ANALYSIS_OVF_MB, "analysis",
                    )

                success = True
                break

            except Exception as exc:
                last_exc = exc
                delay = (2 ** attempt) + random.uniform(0.0, 0.5)
                log.warning(
                    "[Ingest] Write failed (attempt %d/%d): %s — retrying in %.1fs",
                    attempt + 1, _MAX_RETRIES, exc, delay,
                )
                time.sleep(delay)

        if success:
            _ingest_breaker.record_success()
            if OVERFLOW_FILE.exists():
                replayed, _ = _overflow_replay(
                    OVERFLOW_FILE, OVERFLOW_CKPT,
                    _ingest_write_replay, REPLAY_BATCH_SIZE, "ingest",
                )
                if replayed:
                    log.info("[Ingest] Overflow replay: %d events restored.", replayed)
        else:
            _metrics.inc("ingest_errors")
            _ingest_breaker.record_failure()
            log.error(
                "[Ingest] All %d retries exhausted for event_uid=%s. Spooling.",
                _MAX_RETRIES, evt.get("event_uid"),
            )
            _overflow_write(evt, OVERFLOW_FILE, OVERFLOW_CKPT, OVERFLOW_MAX_MB, "ingest")

        event_queue.task_done()

    log.info("Consumer thread exiting.")

# ---------------------------------------------------------------------------
# Thread 3 — Analysis
# ---------------------------------------------------------------------------
def analysis_thread() -> None:
    log.info("Analysis thread started.")

    while not shutdown_event.is_set() or not analysis_queue.empty():
        try:
            item = analysis_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        evt = _unwrap(item)

        if _analysis_breaker.is_open and not _analysis_breaker.allow_attempt():
            _overflow_write(
                evt, ANALYSIS_OVF_FILE, ANALYSIS_OVF_CKPT, ANALYSIS_OVF_MB, "analysis"
            )
            analysis_queue.task_done()
            continue

        success  = False
        last_exc = None

        for attempt in range(_MAX_RETRIES):
            try:
                _analysis_write(evt)
                success = True
                break
            except Exception as exc:
                last_exc = exc
                delay = (2 ** attempt) + random.uniform(0.0, 0.5)
                log.warning(
                    "[Analysis] Write failed (attempt %d/%d): %s — retry in %.1fs",
                    attempt + 1, _MAX_RETRIES, exc, delay,
                )
                time.sleep(delay)

        if success:
            _metrics.inc("events_analysed")
            _analysis_breaker.record_success()
            if ANALYSIS_OVF_FILE.exists():
                replayed, _ = _overflow_replay(
                    ANALYSIS_OVF_FILE, ANALYSIS_OVF_CKPT,
                    _analysis_write, REPLAY_BATCH_SIZE, "analysis",
                )
                if replayed:
                    log.info("[Analysis] Overflow replay: %d events re-analysed.", replayed)
        else:
            _metrics.inc("analysis_errors")
            _analysis_breaker.record_failure()
            log.error(
                "[Analysis] All %d retries exhausted for event_uid=%s.",
                _MAX_RETRIES, evt.get("event_uid"),
            )
            _overflow_write(
                evt, ANALYSIS_OVF_FILE, ANALYSIS_OVF_CKPT, ANALYSIS_OVF_MB, "analysis"
            )

        analysis_queue.task_done()

    log.info("Analysis thread exiting.")

# ---------------------------------------------------------------------------
# Thread 4 — Metrics
# ---------------------------------------------------------------------------
def metrics_thread() -> None:
    log.info("Metrics thread started (interval=%ds).", METRICS_INTERVAL_SECS)
    while not shutdown_event.is_set():
        shutdown_event.wait(METRICS_INTERVAL_SECS)
        if not shutdown_event.is_set():
            _metrics.log_summary()
    log.info("Metrics thread exiting.")

# ---------------------------------------------------------------------------
# Windows Service wrapper
# ---------------------------------------------------------------------------
if IS_WINDOWS:
    class SentinelTraceService(win32serviceutil.ServiceFramework):
        _svc_name_         = "SentinelTraceCollector"
        _svc_display_name_ = "SentinelTrace Sysmon Collector"
        _svc_description_  = "Streams Sysmon telemetry into SentinelTrace SIEM"

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            servicemanager.LogInfoMsg("SentinelTraceCollector starting…")
            try:
                run_collector(self.stop_event)
            except Exception as exc:
                servicemanager.LogErrorMsg(str(exc))

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run_collector(svc_stop_event=None) -> None:
    ensure_events_table()

    if svc_stop_event and IS_WINDOWS:
        def _monitor():
            win32event.WaitForSingleObject(svc_stop_event, win32event.INFINITE)
            shutdown_event.set()
        threading.Thread(target=_monitor, daemon=True).start()

    threads = [
        threading.Thread(target=collector_thread, daemon=True, name="sysmon-collector"),
        threading.Thread(target=consumer_thread,  daemon=True, name="sysmon-consumer"),
        threading.Thread(target=analysis_thread,  daemon=True, name="sysmon-analysis"),
        threading.Thread(target=metrics_thread,   daemon=True, name="sysmon-metrics"),
    ]
    for t in threads:
        t.start()
    log.info("All threads started: %s", [t.name for t in threads])

    if svc_stop_event and IS_WINDOWS:
        while not shutdown_event.is_set():
            time.sleep(1)
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutdown requested.")
            shutdown_event.set()

    for t in threads:
        t.join(timeout=15)
    log.info("Sysmon collector stopped cleanly.")


if __name__ == "__main__":
    if not IS_WINDOWS:
        log.error("sysmon_collector must be run on Windows. Exiting.")
        sys.exit(1)
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SentinelTraceService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SentinelTraceService)
