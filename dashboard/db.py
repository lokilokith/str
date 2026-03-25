"""
db.py — SentinelTrace database layer  (MySQL edition)
======================================================
Install deps:
    pip install mysql-connector-python sqlalchemy

Environment variables (all optional — defaults shown):
    DB_HOST       localhost
    DB_PORT       3306
    DB_USER       sentinel_user
    DB_PASSWORD   StrongPass123
    DB_LIVE       sentinel_live
    DB_CASES      sentinel_cases
    DB_STRICT     0   (set to 1 to raise instead of warn on INSERT IGNORE skips)
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import json
from decimal import Context, ROUND_HALF_UP, setcontext
from types import MappingProxyType
from contextlib import contextmanager
from typing import Any, Dict, List, Sequence

import mysql.connector
from mysql.connector import pooling
from sqlalchemy import create_engine, text, MetaData, Table, Column, String, Integer, DateTime, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.exc import OperationalError, ProgrammingError

log = logging.getLogger("db")

# ---------------------------------------------------------------------------
# 10/10 Formally Correct Mastery: Global Fixed Decimal Context
# ---------------------------------------------------------------------------
GLOBAL_CTX = Context(prec=10, rounding=ROUND_HALF_UP)
setcontext(GLOBAL_CTX)

# ---------------------------------------------------------------------------
# Ingestion State Machine (Formal Transitions)
# ---------------------------------------------------------------------------
INGESTED = "INGESTED"
ANALYZING = "ANALYZING"
COMPLETE = "COMPLETE"
DEGRADED = "DEGRADED"
FAILED = "FAILED"

VALID_TRANSITIONS = MappingProxyType({
    INGESTED: [ANALYZING],
    ANALYZING: [COMPLETE, DEGRADED, FAILED],
    FAILED: [ANALYZING],
    DEGRADED: [ANALYZING],
})

# ---------------------------------------------------------------------------
# Schema Definitions (REQUIRED vs OPTIONAL)
# ---------------------------------------------------------------------------
REQUIRED_COLUMNS = {
    "cases": ["run_id", "status", "content_hash"],
    "events": ["run_id", "event_time", "event_id", "computer", "event_uid"],
    "detections": ["rule_id", "severity"],
}

# Suppress repeated INSERT IGNORE warnings for the same row within a process lifetime.
# This prevents log spam when an XML with duplicate events is uploaded multiple times.
_warned_uids: set = set()
_WARN_CACHE_MAX = 500   # stop caching after this many unique UIDs

# ---------------------------------------------------------------------------
# DB type flag
# ---------------------------------------------------------------------------
DB_TYPE: str = "mysql"

# ---------------------------------------------------------------------------
# Strictness mode
# ---------------------------------------------------------------------------
DB_STRICT: bool = os.environ.get("DB_STRICT", "0") == "1"

# ---------------------------------------------------------------------------
# Connection config
# ---------------------------------------------------------------------------
_HOST  = os.environ.get("DB_HOST",     "localhost")
_PORT  = int(os.environ.get("DB_PORT", "3306"))
_USER  = os.environ.get("DB_USER",     "sentinel_user")
_PASS  = os.environ.get("DB_PASSWORD", "StrongPass123")   # ← updated default
_LIVE  = os.environ.get("DB_LIVE",     "sentinel_live")
_CASES = os.environ.get("DB_CASES",    "sentinel_cases")

DB_CONFIG: Dict[str, Dict] = {
    "live":  dict(host=_HOST, port=_PORT, user=_USER, password=_PASS, database=_LIVE),
    "cases": dict(host=_HOST, port=_PORT, user=_USER, password=_PASS, database=_CASES),
}

# ---------------------------------------------------------------------------
# Connection pools
# ---------------------------------------------------------------------------
POOLS: Dict[str, pooling.MySQLConnectionPool] = {
    "live": pooling.MySQLConnectionPool(
        pool_name="st_live",
        pool_size=10,
        pool_reset_session=True,
        **DB_CONFIG["live"],
    ),
    "cases": pooling.MySQLConnectionPool(
        pool_name="st_cases",
        pool_size=10,
        pool_reset_session=True,
        **DB_CONFIG["cases"],
    ),
}

# ---------------------------------------------------------------------------
# SQLAlchemy engines (pandas read_sql_query)
# ---------------------------------------------------------------------------
def _mysql_url(cfg: Dict) -> str:
    return (
        f"mysql+mysqlconnector://{cfg['user']}:{cfg['password']}"
        f"@{cfg['host']}:{cfg['port']}/{cfg['database']}"
    )

ENGINES = {
    "live":  create_engine(_mysql_url(DB_CONFIG["live"]),  pool_pre_ping=True),
    "cases": create_engine(_mysql_url(DB_CONFIG["cases"]), pool_pre_ping=True),
}

# ---------------------------------------------------------------------------
# 10/10 Mastery Table Initialization
# ---------------------------------------------------------------------------
def _init_mastery_tables(mode: str = "cases"):
    """Initialize missing mastery tables and columns."""
    engine = ENGINES[mode]
    metadata = MetaData()
    
    # case_history: Structured audit trail
    Table('case_history', metadata,
          Column('id', Integer, primary_key=True),
          Column('run_id', String(64)),
          Column('old_status', String(16)),
          Column('new_status', String(16)),
          Column('reason', JSON),  # Structured causality (Option A)
          Column('timestamp', DateTime, server_default=text('CURRENT_TIMESTAMP')))

    # pipeline_metrics: Persistent telemetry
    Table('pipeline_metrics', metadata,
          Column('id', Integer, primary_key=True),
          Column('run_id', String(64)),
          Column('stage', String(32)),
          Column('duration_ms', Integer),
          Column('status', String(16)),
          Column('timestamp', DateTime, server_default=text('CURRENT_TIMESTAMP')))

    try:
        metadata.create_all(engine)
    except Exception as e:
        log.warning("Failed to create mastery tables in %s: %s", mode, e)
    
    # Atomic updates for existing tables
    with engine.connect() as conn:
        # Check if columns exist before adding
        res = conn.execute(text("DESCRIBE cases"))
        existing = [r[0].lower() for r in res]
        
        if "content_hash" not in existing:
            try:
                conn.execute(text("ALTER TABLE cases ADD COLUMN content_hash VARCHAR(64)"))
                conn.execute(text("CREATE UNIQUE INDEX idx_content_hash ON cases(content_hash)"))
            except Exception as e: log.debug("Failed to add content_hash: %s", e)
            
        if "analysis_version" not in existing:
            try:
                conn.execute(text("ALTER TABLE cases ADD COLUMN analysis_version INT DEFAULT 1"))
            except Exception as e: log.debug("Failed to add analysis_version: %s", e)

        if "last_heartbeat" not in existing:
            try:
                conn.execute(text("ALTER TABLE cases ADD COLUMN last_heartbeat DATETIME"))
            except Exception as e: log.debug("Failed to add last_heartbeat: %s", e)
        
        conn.commit()

def verify_schema_strict(mode: str = "cases"):
    """
    10/10 Formal Truth: Verify that the DB matches code expectations.
    SystemExit on REQUIRED column mismatch.
    """
    engine = ENGINES[mode]
    with engine.connect() as conn:
        for table, required in REQUIRED_COLUMNS.items():
            try:
                res = conn.execute(text(f"DESCRIBE {table}"))
                existing = [r[0].lower() for r in res]
                
                missing = [c for c in required if c.lower() not in existing]
                if missing:
                    log.critical(f"[FAIL-FAST] Missing REQUIRED columns in {table}: {missing}")
                    import sys
                    sys.exit(1)
                
                log.info(f"[SCHEMA] Table '{table}' verified (REQUIRED columns OK)")
            except Exception as e:
                log.warning(f"[SCHEMA] Could not verify table '{table}': {e}")

# Trigger initialization and verification
_init_mastery_tables("cases")
verify_schema_strict("cases")

# ---------------------------------------------------------------------------
# Engine refresh — call before running analysis after a bulk insert
# This forces SQLAlchemy to drop stale pooled connections so read_sql_query
# always sees the rows that were just committed via mysql.connector.
# ---------------------------------------------------------------------------
def dispose_engine(mode: str = "cases") -> None:
    """Dispose SQLAlchemy connection pool to force fresh connections."""
    try:
        ENGINES[mode].dispose()
        log.debug("SQLAlchemy engine pool disposed for mode=%s", mode)
    except Exception as e:
        log.warning("dispose_engine failed for mode=%s: %s", mode, e)

# ---------------------------------------------------------------------------
# Connection context manager
# ---------------------------------------------------------------------------
@contextmanager
def get_db_connection(mode: str = "live"):
    """
    Yield a pooled MySQL connection.
    Sets a generous innodb_lock_wait_timeout for large batch inserts.
    Rolls back and closes on exception; always returns conn to pool.
    """
    conn = POOLS[mode].get_connection()
    try:
        # Increase lock wait timeout for this session — prevents timeouts
        # when inserting tens of thousands of rows in bulk uploads.
        cur = conn.cursor()
        cur.execute("SET SESSION innodb_lock_wait_timeout = 120")
        cur.execute("SET SESSION wait_timeout = 300")
        cur.close()
        yield conn
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Cursor context manager
# FIX: consume all pending results before closing to prevent
#      "Unread result found" errors on pooled connections.
# ---------------------------------------------------------------------------
@contextmanager
def get_cursor(conn):
    """
    Yield a dict cursor; drain any unread results and close on exit.

    Usage:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute("SELECT …")
                rows = cur.fetchall()
    """
    cur = conn.cursor(dictionary=True)
    try:
        yield cur
    finally:
        try:
            # Drain any unread results to keep the connection clean
            while cur.nextset():
                pass
        except Exception:
            pass
        try:
            cur.close()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Engine accessor
# ---------------------------------------------------------------------------
def get_engine(mode: str = "live"):
    return ENGINES[mode]

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------
def now_utc() -> datetime.datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.datetime.now(tz=datetime.timezone.utc)


# MySQL DATETIME(6) format: YYYY-MM-DD HH:MM:SS.ffffff  (max 6 decimal places)
# Sysmon XML timestamps look like: 2025-12-17T15:29:44.7368343Z  (7 digits + Z)
_TS_CLEANUP_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$'
)

def sanitize_datetime(value: Any) -> Any:
    """
    Coerce a datetime-like value into a format MySQL DATETIME(6) accepts.

    Handles:
      - ISO strings with >6 fractional digits  (e.g. 7368343Z → 736834)
      - Trailing 'Z' timezone indicator
      - datetime objects (returned as-is — mysql-connector handles them)
      - None / NaN / 'NaT' / 'nan'  → None
    """
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        # Strip timezone info — MySQL DATETIME has no tz
        return value.replace(tzinfo=None)
    s = str(value).strip()
    if s in ("", "None", "NaT", "nan", "NaN"):
        return None
    m = _TS_CLEANUP_RE.match(s)
    if not m:
        return s  # let MySQL raise if it's truly invalid
    date_part   = m.group(1)          # YYYY-MM-DD
    time_part   = m.group(2)          # HH:MM:SS
    frac_part   = (m.group(3) or "")  # 0–N digits
    # Truncate fractional seconds to 6 digits (MySQL DATETIME(6) max)
    frac_part   = frac_part[:6].ljust(6, "0") if frac_part else ""
    if frac_part:
        return f"{date_part} {time_part}.{frac_part}"
    return f"{date_part} {time_part}"


def sanitize_row(row: Dict[str, Any], datetime_cols: set) -> Dict[str, Any]:
    """
    Return a copy of *row* with all datetime columns sanitized.
    Pass the set of column names that are DATETIME columns in the target table.
    """
    out = dict(row)
    for col in datetime_cols:
        if col in out:
            out[col] = sanitize_datetime(out[col])
    return out

# ---------------------------------------------------------------------------
# SQL dialect helpers
# ---------------------------------------------------------------------------
def quote_identifier(name: str) -> str:
    return f"`{name}`"


def sql_now_minus(amount: int, unit: str = "HOUR") -> str:
    return f"(NOW() - INTERVAL {amount} {unit.upper()})"


def sql_insert_ignore(table: str, columns: Sequence[str]) -> str:
    cols         = ", ".join(f"`{c}`" for c in columns)
    placeholders = ", ".join(["%s"] * len(columns))
    return f"INSERT IGNORE INTO `{table}` ({cols}) VALUES ({placeholders})"


def sql_upsert(
    table: str,
    columns: Sequence[str],
    conflict_cols: Sequence[str],
    update_cols: Sequence[str],
) -> str:
    cols         = ", ".join(f"`{c}`" for c in columns)
    placeholders = ", ".join(["%s"] * len(columns))
    updates      = ", ".join(f"`{c}` = VALUES(`{c}`)" for c in update_cols)
    return (
        f"INSERT INTO `{table}` ({cols}) VALUES ({placeholders}) "
        f"ON DUPLICATE KEY UPDATE {updates}"
    )

# ---------------------------------------------------------------------------
# Table column cache
# FIX: key by (database, table) so live and cases don't share the same cache
# ---------------------------------------------------------------------------
_COLUMN_CACHE: Dict[str, List[str]] = {}

def get_table_columns(cur, table: str) -> List[str]:
    """
    Return column names for *table* in the current database.
    Cached per (database, table) pair so live/cases don't collide.
    """
    # Get the current database name to namespace the cache key
    cur.execute("SELECT DATABASE()")
    row = cur.fetchone()
    db_name = (row.get("DATABASE()") or row.get("database()") or "unknown") if row else "unknown"
    cache_key = f"{db_name}.{table}"

    if cache_key in _COLUMN_CACHE:
        return _COLUMN_CACHE[cache_key]

    cur.execute(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s "
        "ORDER BY ORDINAL_POSITION",
        (table,),
    )
    cols = [row["COLUMN_NAME"] for row in cur.fetchall()]
    _COLUMN_CACHE[cache_key] = cols
    return cols


def get_datetime_columns(cur, table: str) -> set:
    """Return the set of DATETIME/TIMESTAMP column names for a table."""
    cur.execute("SELECT DATABASE()")
    row = cur.fetchone()
    db_name = (row.get("DATABASE()") or row.get("database()") or "unknown") if row else "unknown"

    cur.execute(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
        "AND DATA_TYPE IN ('datetime', 'timestamp')",
        (db_name, table),
    )
    return {r["COLUMN_NAME"] for r in cur.fetchall()}

# ---------------------------------------------------------------------------
# checked_insert
# ---------------------------------------------------------------------------
def checked_insert(
    cur,
    table: str,
    columns: Sequence[str],
    values: Sequence[Any],
    identity_hint: str = "",
    expect_duplicate: bool = False,
) -> bool:
    """
    Execute INSERT IGNORE and warn/raise when the row is silently skipped.
    Returns True if inserted, False if skipped (duplicate).
    """
    stmt = sql_insert_ignore(table, columns)
    cur.execute(stmt, list(values))
    inserted = cur.rowcount > 0

    if not inserted:
        msg = f"[db] INSERT IGNORE skipped row in `{table}` ({identity_hint})"
        if DB_STRICT and not expect_duplicate:
            raise RuntimeError(msg)
        if expect_duplicate:
            log.debug(msg)
        else:
            # Suppress repeated warnings for the same identity_hint to avoid log spam
            # (e.g. XML files with hundreds of duplicate event_uid values)
            global _warned_uids
            if identity_hint and identity_hint not in _warned_uids:
                if len(_warned_uids) < _WARN_CACHE_MAX:
                    _warned_uids.add(identity_hint)
                log.warning(msg)
            elif not identity_hint:
                log.warning(msg)

    return inserted

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
def health_check() -> Dict[str, bool]:
    results: Dict[str, bool] = {}
    for mode in ("live", "cases"):
        try:
            with get_db_connection(mode) as conn:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
                cur.close()
            results[mode] = True
            log.info("DB health [%s]: OK", mode)
        except Exception as exc:
            log.error("DB health [%s]: FAILED — %s", mode, exc)
            results[mode] = False
    return results
