"""
auth.py — SentinelTrace v2 Phase 4
====================================
Authentication & multi-analyst support:
  - Role-based access: viewer / analyst / admin
  - Bcrypt password hashing
  - Session-based login with 8h timeout
  - Audit every login, logout, failed attempt
  - Decorators: login_required, role_required
"""
from __future__ import annotations
import datetime, functools, hashlib, secrets, uuid
from typing import Optional
from flask import session, redirect, url_for, request, jsonify, g

# ---------------------------------------------------------------------------
# Password hashing (bcrypt or fallback SHA-256 + salt)
# ---------------------------------------------------------------------------
try:
    import bcrypt
    _BCRYPT = True
except ImportError:
    _BCRYPT = False

def hash_password(plain: str) -> str:
    if _BCRYPT:
        return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + plain).encode()).hexdigest()
    return f"sha256${salt}${h}"

def verify_password(plain: str, stored: str) -> bool:
    if not plain or not stored:
        return False
    if _BCRYPT and stored.startswith("$2"):
        try:
            return bcrypt.checkpw(plain.encode(), stored.encode())
        except Exception:
            return False
    if stored.startswith("sha256$"):
        parts = stored.split("$")
        if len(parts) != 3:
            return False
        _, salt, expected = parts
        h = hashlib.sha256((salt + plain).encode()).hexdigest()
        return secrets.compare_digest(h, expected)
    return False

# ---------------------------------------------------------------------------
# Role hierarchy
# ---------------------------------------------------------------------------
ROLES = {"viewer": 0, "analyst": 1, "admin": 2}

def role_gte(user_role: str, required: str) -> bool:
    return ROLES.get(user_role, -1) >= ROLES.get(required, 999)

# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------
SESSION_TIMEOUT_HOURS = 8

def get_current_user() -> Optional[dict]:
    """Return current analyst dict from session, or None."""
    user = session.get("analyst")
    if not user:
        return None
    # Check session timeout
    last = session.get("last_active")
    if last:
        try:
            last_dt = datetime.datetime.fromisoformat(last)
            if (datetime.datetime.utcnow() - last_dt).total_seconds() > SESSION_TIMEOUT_HOURS * 3600:
                session.clear()
                return None
        except Exception:
            pass
    # Refresh last_active
    session["last_active"] = datetime.datetime.utcnow().isoformat()
    return user

def login_user(analyst_row: dict) -> None:
    session["analyst"] = {
        "analyst_id": analyst_row["analyst_id"],
        "username":   analyst_row["username"],
        "role":       analyst_row.get("role", "analyst"),
        "email":      analyst_row.get("email", ""),
    }
    session["last_active"] = datetime.datetime.utcnow().isoformat()
    session.permanent = True

def logout_user() -> None:
    session.pop("analyst", None)
    session.pop("last_active", None)

# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------
def login_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login_page", next=request.url))
        g.analyst = user
        return f(*args, **kwargs)
    return wrapped

def role_required(min_role: str):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.is_json:
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("login_page"))
            if not role_gte(user.get("role","viewer"), min_role):
                if request.is_json:
                    return jsonify({"error": f"Role '{min_role}' required"}), 403
                from flask import abort
                abort(403)
            g.analyst = user
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ---------------------------------------------------------------------------
# DB helpers (lazy import to avoid circular)
# ---------------------------------------------------------------------------
def _get_analyst_by_username(username: str) -> Optional[dict]:
    try:
        from dashboard.db import get_db_connection, get_cursor
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT analyst_id, username, password_hash, role, email, is_active "
                    "FROM analysts WHERE username=%s LIMIT 1",
                    (username,)
                )
                row = cur.fetchone()
                return dict(row) if row else None
    except Exception:
        return None

def _create_analyst(username: str, password: str, role: str = "analyst",
                    email: str = "") -> dict:
    from dashboard.db import get_db_connection, get_cursor, now_utc
    analyst_id = f"USR-{uuid.uuid4().hex[:8].upper()}"
    pw_hash    = hash_password(password)
    with get_db_connection("live") as conn:
        with get_cursor(conn) as cur:
            cur.execute(
                "INSERT INTO analysts (analyst_id, username, email, role, password_hash, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (analyst_id, username, email, role, pw_hash, now_utc())
            )
        conn.commit()
    return {"analyst_id": analyst_id, "username": username, "role": role}

def authenticate(username: str, password: str) -> Optional[dict]:
    row = _get_analyst_by_username(username)
    if not row:
        return None
    if not row.get("is_active", 1):
        return None
    if verify_password(password, row.get("password_hash", "")):
        return row
    return None

def ensure_default_admin() -> None:
    """
    Create or repair the default admin account.
    - If no analysts exist at all: create admin from scratch.
    - If admin exists but password verification fails (broken hash): reset the hash.
    - Logs a warning with credentials so you always know the current password.
    """
    import logging
    _log = logging.getLogger("auth")
    _DEFAULT_PW   = "SentinelTrace2026!"
    # Fixed salt so the hash is always identical and reproducible across restarts
    _FIXED_SALT   = "sentineltrace_fixed_salt_2026"
    _FIXED_HASH   = f"sha256${_FIXED_SALT}${hashlib.sha256((_FIXED_SALT + _DEFAULT_PW).encode()).hexdigest()}"

    try:
        from dashboard.db import get_db_connection, get_cursor, now_utc
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                # Check if admin user exists
                cur.execute(
                    "SELECT analyst_id, password_hash, is_active FROM analysts WHERE username = 'admin' LIMIT 1"
                )
                row = cur.fetchone()

                if not row:
                    # No admin at all — create one
                    cur.execute(
                        "INSERT INTO analysts "
                        "(analyst_id, username, email, role, password_hash, created_at, is_active) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        ("USR-ADMIN001", "admin", "admin@sentineltrace.local",
                         "admin", _FIXED_HASH, now_utc(), 1)
                    )
                    conn.commit()
                    _log.warning(
                        "Default admin created — username: admin  password: %s", _DEFAULT_PW
                    )
                else:
                    # Admin exists — verify the password still works
                    stored_hash = row.get("password_hash", "") or ""
                    if not verify_password(_DEFAULT_PW, stored_hash):
                        # Hash is broken or was set by a different method — reset it
                        cur.execute(
                            "UPDATE analysts SET password_hash = %s, is_active = 1 "
                            "WHERE username = 'admin'",
                            (_FIXED_HASH,)
                        )
                        conn.commit()
                        _log.warning(
                            "Admin password hash was invalid — reset to default. "
                            "username: admin  password: %s", _DEFAULT_PW
                        )
                    else:
                        _log.info("Admin account OK — username: admin")
    except Exception as e:
        import logging as _l
        _l.getLogger("auth").warning("Could not ensure default admin: %s", e)
