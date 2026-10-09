"""
============================================================
  SHOP MANAGEMENT — FLASK WEB APP  (app.py)
  Includes Role-Based Dashboards (Admin & Staff) & Password Recovery
============================================================
  Run with:  python app.py
  Then open: http://127.0.0.1:5000
============================================================
"""

import json
import os
import uuid
import hashlib
import base64
import datetime
import re
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, jsonify, session
)

# ── App setup & Session Security ────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "shop-mgmt-secure-session-key-2026")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(hours=8)

# Enable ProxyFix for reverse proxy deployments (Render, Railway, Nginx, etc.)
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
except Exception:
    pass

# ── Data file paths & Security Constants ────────────────
BASE_DIR             = os.path.dirname(os.path.abspath(__file__))
INVENTORY_FILE       = os.path.join(BASE_DIR, "inventory.json")
BILLS_FOLDER         = os.path.join(BASE_DIR, "bills")
USERS_FILE           = os.path.join(BASE_DIR, "users.json")
SECURITY_CONFIG_FILE = os.path.join(BASE_DIR, "security_config.json")
SECURITY_AUDIT_FILE  = os.path.join(BASE_DIR, "security_audit.json")

# Master system key used for admin recovery of encrypted bills
MASTER_SYSTEM_KEY    = "AGY_SHOP_ADMIN_MASTER_RECOVERY_KEY_2026"
# Default Master Recovery PIN for Admin account password reset
DEFAULT_ADMIN_RECOVERY_PIN = "778899"
ADMIN_RECOVERY_PIN   = DEFAULT_ADMIN_RECOVERY_PIN

# ── In-Memory Rate Limiting & Account Lockout ────────────
FAILED_LOGIN_ATTEMPTS = {}  # identifier -> {"count": int, "locked_until": datetime}
FAILED_PIN_ATTEMPTS   = {}  # ip         -> {"count": int, "locked_until": datetime}
LOCKOUT_THRESHOLD     = 5   # 5 failed login attempts
LOCKOUT_DURATION_MIN  = 5   # 5 minutes
PIN_LOCKOUT_THRESHOLD = 3   # 3 failed PIN attempts
PIN_LOCKOUT_DURATION  = 10  # 10 minutes


# ══════════════════════════════════════════════════════════
#  SECURITY HELPERS (Audit Logging, Rate Limiting, Sanitization)
# ══════════════════════════════════════════════════════════

def load_security_config() -> dict:
    """Load security configuration from security_config.json."""
    defaults = {
        "admin_recovery_pin": DEFAULT_ADMIN_RECOVERY_PIN,
        "min_password_length": 6,
        "max_login_attempts": LOCKOUT_THRESHOLD,
        "lockout_minutes": LOCKOUT_DURATION_MIN,
        "pin_lockout_threshold": PIN_LOCKOUT_THRESHOLD,
        "pin_lockout_minutes": PIN_LOCKOUT_DURATION,
    }
    if os.path.exists(SECURITY_CONFIG_FILE):
        try:
            with open(SECURITY_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                defaults.update(data)
                return defaults
        except Exception:
            pass
    save_security_config(defaults)
    return defaults


def save_security_config(cfg: dict) -> None:
    """Save security configuration to security_config.json."""
    with open(SECURITY_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4)


def get_admin_recovery_pin() -> str:
    """Get active Master Recovery PIN."""
    return load_security_config().get("admin_recovery_pin", DEFAULT_ADMIN_RECOVERY_PIN)


def get_client_ip() -> str:
    """Extract client IP address safely, checking proxy headers."""
    try:
        if request.headers.get("X-Forwarded-For"):
            return request.headers.get("X-Forwarded-For").split(",")[0].strip()
        return request.remote_addr or "127.0.0.1"
    except Exception:
        return "127.0.0.1"


def is_locked_out(identifier: str, tracker: dict) -> tuple[bool, int]:
    """Check if identifier (user or IP) is locked out. Return (is_locked, remaining_seconds)."""
    if not identifier:
        return False, 0
    now = datetime.datetime.now()
    entry = tracker.get(identifier)
    if not entry:
        return False, 0
    locked_until = entry.get("locked_until")
    if locked_until and locked_until > now:
        remaining = int((locked_until - now).total_seconds())
        return True, remaining
    if locked_until and locked_until <= now:
        tracker.pop(identifier, None)
    return False, 0


def record_failed_attempt(identifier: str, tracker: dict, max_attempts: int, duration_min: int) -> tuple[int, bool]:
    """Increment failed attempts. If threshold reached, set lockout."""
    if not identifier:
        return 1, False
    now = datetime.datetime.now()
    if identifier not in tracker:
        tracker[identifier] = {"count": 1, "locked_until": None}
    else:
        tracker[identifier]["count"] += 1

    count = tracker[identifier]["count"]
    if count >= max_attempts:
        tracker[identifier]["locked_until"] = now + datetime.timedelta(minutes=duration_min)
        return count, True
    return count, False


def clear_failed_attempts(identifier: str, tracker: dict):
    """Clear failed attempt history upon successful authentication."""
    if identifier in tracker:
        tracker.pop(identifier, None)


def get_active_lockouts() -> list:
    """Return all currently active locked-out users and IPs."""
    now = datetime.datetime.now()
    active = []
    for k, v in list(FAILED_LOGIN_ATTEMPTS.items()):
        locked_until = v.get("locked_until")
        if locked_until and locked_until > now:
            rem = int((locked_until - now).total_seconds())
            active.append({
                "type": "Login Account/IP",
                "target": k,
                "remaining_seconds": rem,
                "remaining_minutes": max(1, (rem + 59) // 60),
                "count": v.get("count", 0),
            })
    for k, v in list(FAILED_PIN_ATTEMPTS.items()):
        locked_until = v.get("locked_until")
        if locked_until and locked_until > now:
            rem = int((locked_until - now).total_seconds())
            active.append({
                "type": "Recovery PIN (IP)",
                "target": k,
                "remaining_seconds": rem,
                "remaining_minutes": max(1, (rem + 59) // 60),
                "count": v.get("count", 0),
            })
    return active


def log_security_event(event_type: str, details: str, severity: str = "INFO", username: str = None) -> None:
    """Append a security event to the audit log."""
    try:
        ip = get_client_ip()
    except Exception:
        ip = "System"

    if username is None:
        try:
            username = session.get("user", {}).get("username", "Anonymous")
        except Exception:
            username = "System"

    event = {
        "id": str(uuid.uuid4()).upper()[:8],
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event_type,
        "username": username,
        "ip": ip,
        "details": details,
        "severity": severity,
    }

    events = []
    if os.path.exists(SECURITY_AUDIT_FILE):
        try:
            with open(SECURITY_AUDIT_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
        except Exception:
            events = []

    events.insert(0, event)
    events = events[:100]

    try:
        with open(SECURITY_AUDIT_FILE, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
    except Exception:
        pass


def get_recent_security_events(limit: int = 20) -> list:
    """Read recent security events for admin dashboard."""
    if os.path.exists(SECURITY_AUDIT_FILE):
        try:
            with open(SECURITY_AUDIT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)[:limit]
        except Exception:
            return []
    return []


def sanitize_bill_id(bill_id: str) -> str:
    """Sanitize bill ID to strictly uppercase alphanumeric characters (prevent path traversal)."""
    if not bill_id:
        return ""
    return re.sub(r"[^A-Za-z0-9]", "", str(bill_id)).upper()


def sanitize_username(username: str) -> str:
    """Sanitize username to lowercase alphanumeric, dot, underscore, dash."""
    if not username:
        return ""
    return re.sub(r"[^a-zA-Z0-9_.-]", "", str(username)).lower()


@app.after_request
def add_security_headers(response):
    """Inject robust security headers on every HTTP response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ══════════════════════════════════════════════════════════
#  USER AUTHENTICATION & ACCESS CONTROL HELPERS
# ══════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    """Return SHA-256 hex digest of a password string."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load_users() -> dict:
    """Load users database from users.json. Create defaults if missing."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # Default accounts
    default_users = {
        "admin": {
            "username": "admin",
            "name": "Store Administrator",
            "role": "admin",
            "password": "admin123",
            "password_hash": hash_password("admin123")
        },
        "staff": {
            "username": "staff",
            "name": "Front Desk Cashier",
            "role": "staff",
            "password": "staff123",
            "password_hash": hash_password("staff123")
        }
    }
    save_users(default_users)
    return default_users


def save_users(users: dict) -> None:
    """Save users dictionary to users.json."""
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)


def login_required(f):
    """Decorator to require user login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require Admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Please log in to access this page.", "info")
            return redirect(url_for("login", next=request.url))
        if session.get("user", {}).get("role") != "admin":
            flash("Access denied: Admin privileges required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_user_context():
    """Make user info, role, and security settings available to all templates."""
    user = session.get("user")
    sec_cfg = load_security_config()
    return {
        "current_user": user,
        "is_admin": bool(user and user.get("role") == "admin"),
        "is_staff": bool(user and user.get("role") == "staff"),
        "admin_recovery_pin": sec_cfg.get("admin_recovery_pin", DEFAULT_ADMIN_RECOVERY_PIN),
        "min_password_length": sec_cfg.get("min_password_length", 6),
    }


# ══════════════════════════════════════════════════════════
#  HELPERS – Inventory I/O
# ══════════════════════════════════════════════════════════

def load_inventory() -> dict:
    """Read inventory.json; return {} if it doesn't exist yet."""
    if os.path.exists(INVENTORY_FILE):
        try:
            with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_inventory(inventory: dict) -> None:
    """Write the inventory dict back to inventory.json."""
    with open(INVENTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=4)


# ══════════════════════════════════════════════════════════
#  HELPERS – Bill Security & Password Recovery
# ══════════════════════════════════════════════════════════

def xor_encrypt(text: str, key: str) -> bytes:
    """Repeating-XOR cipher — same function encrypts and decrypts."""
    key_bytes  = key.encode("utf-8")
    text_bytes = text.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes))


def recover_legacy_bill_text(raw_bytes: bytes) -> tuple[str, str]:
    """
    Recover the repeating XOR key by exploiting the known receipt header.
    Every bill receipt begins with 52 '=' characters.
    """
    stream = bytes([b ^ ord('=') for b in raw_bytes[:52]])
    for klen in range(1, 26):
        cand = stream[:klen]
        if stream[:50] == (cand * (50 // klen + 1))[:50]:
            try:
                k = cand.decode("utf-8")
                return xor_encrypt(raw_bytes.decode("latin-1"), k).decode("utf-8", errors="replace"), k
            except Exception:
                pass
    k = stream[:10].decode("latin-1")
    return xor_encrypt(raw_bytes.decode("latin-1"), k).decode("utf-8", errors="replace"), k


def save_bill_file(
    bill_id:          str,
    bill_text:        str,
    password:         str = "",
    customer_name:    str = "",
    customer_address: str = "",
    created_by:       str = "System",
    total_amount:     float = 0.0,
) -> str:
    """
    Persist a bill to disk.
    Always includes an ADMIN_RECOVERY_BODY encrypted with MASTER_SYSTEM_KEY
    so the Admin can always recover the bill if the user forgets the password!
    Sanitizes bill_id to prevent path traversal attacks.
    """
    bill_id = sanitize_bill_id(bill_id)
    if not bill_id:
        raise ValueError("Invalid bill_id")

    os.makedirs(BILLS_FOLDER, exist_ok=True)
    filepath = os.path.join(BILLS_FOLDER, f"bill_{bill_id}.txt")

    # Encrypt recovery copy with Master Key
    admin_encrypted = xor_encrypt(bill_text, MASTER_SYSTEM_KEY)
    admin_rec_b64   = base64.b64encode(admin_encrypted).decode("ascii")

    if password:
        encrypted = xor_encrypt(bill_text, password)
        body      = base64.b64encode(encrypted).decode("ascii")
        pwd_hash  = hash_password(password)
    else:
        body      = base64.b64encode(bill_text.encode("utf-8")).decode("ascii")
        pwd_hash  = "NONE"

    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"BILL_ID:{bill_id}\n")
        f.write(f"CUSTOMER_NAME:{customer_name}\n")
        f.write(f"CUSTOMER_ADDRESS:{customer_address}\n")
        f.write(f"TOTAL_AMOUNT:{total_amount:.2f}\n")
        f.write(f"CREATED_AT:{created_at}\n")
        f.write(f"CREATED_BY:{created_by}\n")
        f.write(f"PASSWORD_HASH:{pwd_hash}\n")
        if password:
            f.write(f"BILL_PASSWORD:{password}\n")
        f.write(f"ADMIN_RECOVERY_BODY:{admin_rec_b64}\n")
        f.write("---\n")
        f.write(body)

    return filepath


def read_bill_file(bill_id: str, password: str = "", is_admin: bool = False) -> tuple[str | None, str | None]:
    """
    Read and (if needed) decrypt a saved bill.
    If is_admin is True, bypasses password check using Admin Master Recovery!
    Sanitizes bill_id to prevent path traversal attacks.
    """
    bill_id = sanitize_bill_id(bill_id)
    if not bill_id:
        return None, "Invalid bill ID."

    filepath = os.path.join(BILLS_FOLDER, f"bill_{bill_id}.txt")
    if not os.path.exists(filepath):
        return None, f"Bill '{bill_id}' not found."

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    stored_hash    = None
    admin_rec_body = None
    body_start     = 0
    for idx, line in enumerate(lines):
        if line.startswith("PASSWORD_HASH:"):
            stored_hash = line.split(":", 1)[1].strip()
        elif line.startswith("ADMIN_RECOVERY_BODY:"):
            admin_rec_body = line.split(":", 1)[1].strip()
        elif line == "---":
            body_start = idx + 1
            break

    body_b64  = "\n".join(lines[body_start:])
    raw_bytes = base64.b64decode(body_b64)

    # 1. Unprotected bills
    if not stored_hash or stored_hash == "NONE":
        return raw_bytes.decode("utf-8", errors="replace"), None

    # 2. Admin Override / Master Unlock (Password Forgotten scenario)
    if is_admin:
        if admin_rec_body:
            rec_bytes = base64.b64decode(admin_rec_body)
            bill_text = xor_encrypt(rec_bytes.decode("latin-1"), MASTER_SYSTEM_KEY).decode("utf-8", errors="replace")
            return bill_text, None
        else:
            # Fallback for legacy files
            rec_text, _ = recover_legacy_bill_text(raw_bytes)
            return rec_text, None

    # 3. Normal Staff/User access
    if not password:
        return None, "PASSWORD_REQUIRED"
    if hash_password(password) != stored_hash:
        return None, "WRONG_PASSWORD"

    bill_text = xor_encrypt(raw_bytes.decode("latin-1"), password).decode("utf-8", errors="replace")
    return bill_text, None


def read_bill_metadata(bill_id: str) -> dict:
    """Read metadata header of a saved bill file (sanitized)."""
    bill_id = sanitize_bill_id(bill_id)
    meta = {
        "bill_id":          bill_id,
        "customer_name":    "",
        "customer_address": "",
        "total_amount":     0.0,
        "created_at":       "",
        "created_by":       "Cashier",
        "protected":        False,
        "bill_password":    "",
    }
    if not bill_id:
        return meta
    filepath = os.path.join(BILLS_FOLDER, f"bill_{bill_id}.txt")

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "---":
                break
            if line.startswith("CUSTOMER_NAME:"):
                meta["customer_name"] = line.split(":", 1)[1].strip()
            elif line.startswith("CUSTOMER_ADDRESS:"):
                meta["customer_address"] = line.split(":", 1)[1].strip()
            elif line.startswith("TOTAL_AMOUNT:"):
                try:
                    meta["total_amount"] = float(line.split(":", 1)[1].strip())
                except Exception:
                    meta["total_amount"] = 0.0
            elif line.startswith("CREATED_AT:"):
                meta["created_at"] = line.split(":", 1)[1].strip()
            elif line.startswith("CREATED_BY:"):
                meta["created_by"] = line.split(":", 1)[1].strip()
            elif line.startswith("PASSWORD_HASH:"):
                meta["protected"] = line.split(":", 1)[1].strip() != "NONE"
            elif line.startswith("BILL_PASSWORD:"):
                meta["bill_password"] = line.split(":", 1)[1].strip()

    # If protected and no stored plaintext password header, recover using known-plaintext header
    if meta["protected"] and not meta["bill_password"]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            parts = content.split("---", 1)
            if len(parts) > 1:
                body_b64 = parts[1].strip()
                raw_bytes = base64.b64decode(body_b64)
                _, rec_key = recover_legacy_bill_text(raw_bytes)
                if rec_key:
                    meta["bill_password"] = rec_key
        except Exception:
            pass

    # If created_at is empty (legacy bill), use file mtime
    if not meta["created_at"]:
        mtime = os.path.getmtime(filepath)
        meta["created_at"] = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")

    return meta


# ══════════════════════════════════════════════════════════
#  ROUTES – Authentication & Login
# ══════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page for Admin and Staff with brute-force lockout defense."""
    if "user" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        ip = get_client_ip()
        username = sanitize_username(request.form.get("username", "").strip())
        password = request.form.get("password", "").strip()

        # Check for active lockout
        locked_user, sec_user = is_locked_out(username, FAILED_LOGIN_ATTEMPTS)
        locked_ip, sec_ip     = is_locked_out(f"ip_{ip}", FAILED_LOGIN_ATTEMPTS)

        if locked_user:
            mins = max(1, (sec_user + 59) // 60)
            log_security_event("LOGIN_BLOCKED_LOCKOUT", f"Login attempt blocked due to active lockout for user '{username}'", "WARNING", username)
            flash(f"Account '{username}' is temporarily locked due to multiple failed attempts. Please wait {mins} minute(s) before trying again.", "danger")
            return render_template("login.html")

        if locked_ip:
            mins = max(1, (sec_ip + 59) // 60)
            log_security_event("LOGIN_BLOCKED_LOCKOUT", f"Network IP {ip} temporarily blocked due to excessive failures", "WARNING", username)
            flash(f"Access from this network/IP is temporarily locked due to excessive failed attempts. Please wait {mins} minute(s).", "danger")
            return render_template("login.html")

        users = load_users()
        user  = users.get(username)

        if user and user.get("password_hash") == hash_password(password):
            # Clear failed attempts on successful login
            clear_failed_attempts(username, FAILED_LOGIN_ATTEMPTS)
            clear_failed_attempts(f"ip_{ip}", FAILED_LOGIN_ATTEMPTS)

            # Prevent session fixation
            session.clear()
            session.permanent = True
            session["user"] = {
                "username": user["username"],
                "name":     user.get("name", user["username"]),
                "role":     user.get("role", "staff"),
            }

            log_security_event("LOGIN_SUCCESS", f"User '{user['name']}' logged in successfully as {user.get('role', 'staff').upper()}", "SUCCESS", username)
            flash(f"Welcome back, {session['user']['name']}! Logged in as {session['user']['role'].upper()}.", "success")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))
        else:
            c1, locked1 = record_failed_attempt(username, FAILED_LOGIN_ATTEMPTS, LOCKOUT_THRESHOLD, LOCKOUT_DURATION_MIN)
            c2, locked2 = record_failed_attempt(f"ip_{ip}", FAILED_LOGIN_ATTEMPTS, 25, 10)
            attempts = c1

            if locked1:
                log_security_event("ACCOUNT_LOCKED", f"Account '{username}' locked for {LOCKOUT_DURATION_MIN} minutes after {attempts} failed attempts", "DANGER", username)
                flash(f"Too many failed login attempts! Account '{username}' is locked for {LOCKOUT_DURATION_MIN} minutes for security.", "danger")
            elif locked2:
                log_security_event("IP_LOCKED", f"IP {ip} locked for 10 minutes after excessive failed attempts", "DANGER", username)
                flash("Too many failed attempts from this network! Access temporarily locked for 10 minutes.", "danger")
            else:
                remaining = LOCKOUT_THRESHOLD - attempts
                log_security_event("LOGIN_FAILED", f"Failed login attempt ({attempts}/{LOCKOUT_THRESHOLD})", "WARNING", username)
                flash(f"Invalid username or password. ({remaining} attempt(s) remaining before security lockout)", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log out current user and clear session."""
    name = session.get("user", {}).get("name", "User")
    username = session.get("user", {}).get("username", "Unknown")
    log_security_event("LOGOUT", f"User '{name}' logged out", "INFO", username)
    session.clear()
    flash(f"Goodbye {name}! You have been logged out securely.", "info")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """
    Password Recovery Endpoint:
    - Master PIN Brute-Force Lockout Defense (3 attempts -> 10 min lockout).
    - Minimum password length policy enforcement.
    """
    if request.method == "POST":
        ip           = get_client_ip()
        username     = sanitize_username(request.form.get("username", "").strip())
        recovery_pin = request.form.get("recovery_pin", "").strip()
        new_password = request.form.get("new_password", "").strip()

        # Check PIN lockout
        locked_pin, sec_pin = is_locked_out(ip, FAILED_PIN_ATTEMPTS)
        if locked_pin:
            mins = max(1, (sec_pin + 59) // 60)
            log_security_event("PIN_RECOVERY_BLOCKED", "PIN recovery blocked due to active lockout", "WARNING")
            flash(f"Master Recovery is temporarily locked due to multiple incorrect PIN attempts. Try again in {mins} minute(s).", "danger")
            return render_template("forgot_password.html", prefill_user=username)

        if username != "admin":
            flash("Staff passwords must be reset by the Admin inside the Admin Dashboard.", "warning")
            return redirect(url_for("forgot_password"))

        active_pin = get_admin_recovery_pin()
        if recovery_pin != active_pin:
            count, locked = record_failed_attempt(ip, FAILED_PIN_ATTEMPTS, PIN_LOCKOUT_THRESHOLD, PIN_LOCKOUT_DURATION)
            if locked:
                log_security_event("PIN_RECOVERY_LOCKED", f"Master PIN recovery locked for {PIN_LOCKOUT_DURATION} minutes after {count} failed attempts", "DANGER")
                flash(f"Incorrect Master Recovery PIN! Too many attempts. PIN recovery locked for {PIN_LOCKOUT_DURATION} minutes.", "danger")
            else:
                rem = PIN_LOCKOUT_THRESHOLD - count
                log_security_event("PIN_RECOVERY_FAILED", f"Incorrect Master PIN entered ({count}/{PIN_LOCKOUT_THRESHOLD})", "WARNING")
                flash(f"Incorrect Master Recovery PIN! ({rem} attempt(s) remaining before lockout)", "danger")
            return render_template("forgot_password.html", prefill_user=username)

        # Clear PIN attempts on valid PIN
        clear_failed_attempts(ip, FAILED_PIN_ATTEMPTS)

        sec_cfg = load_security_config()
        min_len = sec_cfg.get("min_password_length", 6)
        if not new_password or len(new_password) < min_len:
            flash(f"New password must be at least {min_len} characters long for security.", "danger")
            return render_template("forgot_password.html", prefill_user=username)

        users = load_users()
        users["admin"]["password"]      = new_password
        users["admin"]["password_hash"] = hash_password(new_password)
        save_users(users)

        log_security_event("ADMIN_PASSWORD_RESET_PIN", "Admin password successfully reset via Master Security PIN", "SUCCESS", "admin")
        flash("Admin password has been reset successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


# ══════════════════════════════════════════════════════════
#  ROUTES – Dashboards (Role-Based Router)
# ══════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Root route — redirects to dashboard or login."""
    if "user" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    """Directs user to their role-specific dashboard."""
    role = session.get("user", {}).get("role", "staff")
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("staff_dashboard"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    """
    ADMIN DASHBOARD:
    - Executive business statistics (Revenue, Total Orders, Stock units)
    - Password Recovery Center for protected bills
    - Staff account management (add staff, reset passwords)
    - Inventory controls and recent bills
    """
    inventory = load_inventory()
    total_items    = len(inventory)
    total_units    = sum(d.get("quantity", 0) for d in inventory.values())
    low_stock      = [name for name, d in inventory.items() if 0 < d["quantity"] <= 5]
    out_of_stock   = [name for name, d in inventory.items() if d["quantity"] == 0]

    # Load all bills
    os.makedirs(BILLS_FOLDER, exist_ok=True)
    all_bill_files = sorted(
        [f.replace("bill_", "").replace(".txt", "") for f in os.listdir(BILLS_FOLDER) if f.endswith(".txt")],
        reverse=True,
    )
    all_bills = [read_bill_metadata(bid) for bid in all_bill_files]

    total_revenue   = sum(b.get("total_amount", 0.0) for b in all_bills)
    protected_bills = [b for b in all_bills if b.get("protected")]
    all_users = list(load_users().values())
    staff_users = [u for u in all_users if u.get("role") == "staff"]
    recent_security_events = get_recent_security_events(15)
    active_lockouts = get_active_lockouts()
    security_config = load_security_config()

    return render_template(
        "admin_dashboard.html",
        total_items=total_items,
        total_units=total_units,
        low_stock=low_stock,
        out_of_stock=out_of_stock,
        total_bills=len(all_bills),
        total_revenue=total_revenue,
        protected_bills=protected_bills,
        staff_users=staff_users,
        all_users=all_users,
        recent_bills=all_bills[:6],
        recent_security_events=recent_security_events,
        active_lockouts=active_lockouts,
        security_config=security_config,
    )


@app.route("/staff")
@login_required
def staff_dashboard():
    """
    STAFF DASHBOARD:
    - Quick POS / Cashier actions (New Bill front-and-center)
    - Quick product price & stock checker
    - Today's bills generated
    - Saved bills list
    """
    inventory = load_inventory()
    total_items  = len(inventory)
    out_of_stock = [name for name, d in inventory.items() if d["quantity"] == 0]
    low_stock    = [name for name, d in inventory.items() if 0 < d["quantity"] <= 5]

    os.makedirs(BILLS_FOLDER, exist_ok=True)
    all_bill_files = sorted(
        [f.replace("bill_", "").replace(".txt", "") for f in os.listdir(BILLS_FOLDER) if f.endswith(".txt")],
        reverse=True,
    )
    all_bills = [read_bill_metadata(bid) for bid in all_bill_files]

    today_str   = datetime.datetime.now().strftime("%Y-%m-%d")
    today_bills = [b for b in all_bills if str(b.get("created_at", "")).startswith(today_str)]

    return render_template(
        "staff_dashboard.html",
        inventory=inventory,
        total_items=total_items,
        out_of_stock=out_of_stock,
        low_stock=low_stock,
        today_bills_count=len(today_bills),
        recent_bills=all_bills[:8],
    )


# ══════════════════════════════════════════════════════════
#  ROUTES – User & Role Management (Admin Only)
# ══════════════════════════════════════════════════════════

@app.route("/admin/staff/add", methods=["POST"])
@app.route("/admin/users/add", methods=["POST"])
@admin_required
def add_staff():
    """Add a new staff or admin user account (Admin Only) with security policies."""
    username = sanitize_username(request.form.get("username", ""))
    name     = request.form.get("name", "").strip()
    password = request.form.get("password", "").strip()
    role     = request.form.get("role", "staff").strip().lower()
    if role not in ("admin", "staff"):
        role = "staff"

    if not username or not name or not password:
        flash("All fields (Name, Username, Role, Password) are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    if len(username) < 3:
        flash("Username must be at least 3 characters long.", "danger")
        return redirect(url_for("admin_dashboard"))

    sec_cfg = load_security_config()
    min_len = sec_cfg.get("min_password_length", 6)
    if len(password) < min_len:
        flash(f"Password must be at least {min_len} characters long for security.", "danger")
        return redirect(url_for("admin_dashboard"))

    users = load_users()
    if username in users:
        flash(f"User account '{username}' already exists.", "warning")
        return redirect(url_for("admin_dashboard"))

    users[username] = {
        "username":      username,
        "name":          name,
        "role":          role,
        "password":      password,
        "password_hash": hash_password(password),
    }
    save_users(users)
    log_security_event("USER_CREATED", f"Admin created new {role.upper()} account '{name}' (@{username})", "SUCCESS")
    flash(f"New {role.upper()} user '{name}' (@{username}) created successfully!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/update-role", methods=["POST"])
@admin_required
def update_user_role():
    """Admin assigns or changes role for an existing user (Admin Only)."""
    username = sanitize_username(request.form.get("username", ""))
    new_role = request.form.get("role", "").strip().lower()

    if not username or new_role not in ("admin", "staff"):
        flash("Invalid user or role selection.", "danger")
        return redirect(url_for("admin_dashboard"))

    users = load_users()
    if username not in users:
        flash(f"User '{username}' not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if username == "admin" and new_role != "admin":
        flash("Cannot change the role of the primary 'admin' account.", "danger")
        return redirect(url_for("admin_dashboard"))

    old_role = users[username].get("role", "staff")
    users[username]["role"] = new_role
    save_users(users)

    # If current user updated their own role
    if session.get("user", {}).get("username") == username:
        session["user"]["role"] = new_role

    log_security_event("ROLE_CHANGED", f"Role for user '@{username}' changed from {old_role.upper()} to {new_role.upper()}", "WARNING")
    flash(f"Role for '{users[username].get('name', username)}' (@{username}) updated from {old_role.upper()} to {new_role.upper()}!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/staff/reset-password", methods=["POST"])
@app.route("/admin/users/reset-password", methods=["POST"])
@admin_required
def reset_staff_password():
    """Admin resets any user account password (Admin Only) with security check."""
    username     = sanitize_username(request.form.get("username", ""))
    new_password = request.form.get("new_password", "").strip()

    if not username or not new_password:
        flash("Username and new password are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    sec_cfg = load_security_config()
    min_len = sec_cfg.get("min_password_length", 6)
    if len(new_password) < min_len:
        flash(f"Password must be at least {min_len} characters long for security.", "danger")
        return redirect(url_for("admin_dashboard"))

    users = load_users()
    if username not in users:
        flash(f"User '{username}' not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    users[username]["password"]      = new_password
    users[username]["password_hash"] = hash_password(new_password)
    save_users(users)
    log_security_event("PASSWORD_RESET", f"Password updated for user '{users[username].get('name', username)}' (@{username})", "SUCCESS")
    flash(f"Password for '{users[username].get('name', username)}' (@{username}) has been updated successfully!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/staff/delete/<username>", methods=["POST"])
@app.route("/admin/users/delete/<username>", methods=["POST"])
@admin_required
def delete_staff(username):
    """Delete a user account (Admin Only)."""
    username = sanitize_username(username)
    if username == "admin":
        flash("Cannot delete primary admin account.", "danger")
        return redirect(url_for("admin_dashboard"))

    if session.get("user", {}).get("username") == username:
        flash("You cannot delete your own currently active account.", "warning")
        return redirect(url_for("admin_dashboard"))

    users = load_users()
    if username in users:
        name = users[username].get("name", username)
        del users[username]
        save_users(users)
        log_security_event("USER_DELETED", f"User account '{name}' (@{username}) deleted", "DANGER")
        flash(f"User account '{name}' (@{username}) deleted successfully.", "success")
    else:
        flash("Account not found.", "danger")
    return redirect(url_for("admin_dashboard"))


# ══════════════════════════════════════════════════════════
#  ROUTES – Security Controls & Lockout Management (Admin Only)
# ══════════════════════════════════════════════════════════

@app.route("/admin/security/update-pin", methods=["POST"])
@admin_required
def update_recovery_pin():
    """Admin updates the Master Security Recovery PIN."""
    new_pin = request.form.get("new_pin", "").strip()
    if not re.match(r"^\d{6}$", new_pin):
        flash("Master Recovery PIN must be exactly 6 numeric digits.", "danger")
        return redirect(url_for("admin_dashboard"))

    cfg = load_security_config()
    cfg["admin_recovery_pin"] = new_pin
    save_security_config(cfg)

    log_security_event("PIN_UPDATED", "Master Security Recovery PIN updated by Admin", "WARNING")
    flash("Master Recovery PIN successfully updated!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/security/unlock-account", methods=["POST"])
@admin_required
def unlock_account():
    """Admin manually clears lockout for an account or IP."""
    target = request.form.get("target", "").strip()
    if not target:
        flash("Target identifier required.", "danger")
        return redirect(url_for("admin_dashboard"))

    clear_failed_attempts(target, FAILED_LOGIN_ATTEMPTS)
    clear_failed_attempts(target, FAILED_PIN_ATTEMPTS)

    log_security_event("ACCOUNT_UNLOCKED_BY_ADMIN", f"Admin lifted security lockout for '{target}'", "SUCCESS")
    flash(f"Security lockout for '{target}' has been cleared successfully!", "success")
    return redirect(url_for("admin_dashboard"))


# ══════════════════════════════════════════════════════════
#  ROUTES – Inventory
# ══════════════════════════════════════════════════════════

@app.route("/inventory")
@login_required
def inventory_page():
    """Display the inventory table."""
    inventory = load_inventory()
    return render_template("inventory.html", inventory=inventory)


@app.route("/inventory/add", methods=["GET", "POST"])
@login_required
def add_item():
    """GET: show add-item form. POST: save the new item."""
    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        price    = request.form.get("price", "")
        quantity = request.form.get("quantity", "")

        if not name:
            flash("Item name cannot be empty.", "danger")
            return redirect(url_for("add_item"))

        inventory = load_inventory()
        if name in inventory:
            flash(f"'{name}' already exists. Use Update to change it.", "warning")
            return redirect(url_for("add_item"))

        try:
            price    = float(price)
            quantity = int(quantity)
        except ValueError:
            flash("Price must be a number and quantity must be a whole number.", "danger")
            return redirect(url_for("add_item"))

        if price < 0 or quantity < 0:
            flash("Price and quantity must be non-negative.", "danger")
            return redirect(url_for("add_item"))

        inventory[name] = {"price": price, "quantity": quantity}
        save_inventory(inventory)
        flash(f"'{name}' added successfully!", "success")
        return redirect(url_for("inventory_page"))

    return render_template("add_item.html")


@app.route("/inventory/update/<name>", methods=["GET", "POST"])
@login_required
def update_item(name):
    """GET: show update form. POST: save quantity and/or price changes."""
    inventory = load_inventory()

    if name not in inventory:
        flash(f"Item '{name}' not found.", "danger")
        return redirect(url_for("inventory_page"))

    if request.method == "POST":
        new_price_str = request.form.get("price", "").strip()
        new_qty_str   = request.form.get("quantity", "").strip()

        updated = False

        if new_price_str:
            try:
                new_price = float(new_price_str)
                if new_price < 0:
                    flash("Price cannot be negative.", "danger")
                    return redirect(url_for("update_item", name=name))
                inventory[name]["price"] = new_price
                updated = True
            except ValueError:
                flash("Price must be a valid number.", "danger")
                return redirect(url_for("update_item", name=name))

        if new_qty_str:
            current = inventory[name]["quantity"]
            try:
                if new_qty_str.startswith("+"):
                    new_qty = current + int(new_qty_str[1:])
                elif new_qty_str.startswith("-"):
                    new_qty = current - int(new_qty_str[1:])
                else:
                    new_qty = int(new_qty_str)
            except ValueError:
                flash("Quantity must be a whole number (or use +N / -N).", "danger")
                return redirect(url_for("update_item", name=name))

            if new_qty < 0:
                flash("Quantity cannot be negative.", "danger")
                return redirect(url_for("update_item", name=name))
            inventory[name]["quantity"] = new_qty
            updated = True

        if updated:
            save_inventory(inventory)
            flash(f"'{name}' updated successfully!", "success")
        else:
            flash("No changes made (both fields were empty).", "info")

        return redirect(url_for("inventory_page"))

    return render_template("update_item.html", name=name, item=inventory[name])


@app.route("/inventory/delete/<name>", methods=["POST"])
@admin_required
def delete_item(name):
    """Admin-only: Remove an item from inventory."""
    inventory = load_inventory()
    if name in inventory:
        del inventory[name]
        save_inventory(inventory)
        flash(f"'{name}' deleted from inventory.", "success")
    else:
        flash(f"'{name}' not found.", "danger")
    return redirect(url_for("inventory_page"))


# ══════════════════════════════════════════════════════════
#  ROUTES – Billing
# ══════════════════════════════════════════════════════════

@app.route("/billing")
@login_required
def billing_page():
    """Show the billing page with in-stock items."""
    inventory = load_inventory()
    in_stock = {k: v for k, v in inventory.items() if v["quantity"] > 0}
    return render_template("billing.html", inventory=in_stock)


@app.route("/billing/generate", methods=["POST"])
@login_required
def generate_bill():
    """
    POST endpoint that receives a JSON cart, computes the bill,
    always saves it, and returns the receipt as JSON.
    """
    data             = request.get_json()
    cart             = data.get("cart", {})
    password         = data.get("password", "")
    save_it          = data.get("save", True)
    customer_name    = data.get("customer_name", "").strip()
    customer_address = data.get("customer_address", "").strip()

    if not cart:
        return jsonify({"error": "Cart is empty."}), 400

    inventory = load_inventory()

    bill_items = []
    subtotal   = 0.0
    errors     = []

    for item_name, qty in cart.items():
        if item_name not in inventory:
            errors.append(f"'{item_name}' not found in inventory.")
            continue
        available = inventory[item_name]["quantity"]
        if qty > available:
            errors.append(f"Only {available} unit(s) of '{item_name}' available.")
            continue
        unit_price = inventory[item_name]["price"]
        line_total = unit_price * qty
        subtotal  += line_total
        bill_items.append({
            "name":       item_name,
            "qty":        qty,
            "unit_price": unit_price,
            "line_total": line_total,
        })

    if errors:
        return jsonify({"error": "\n".join(errors)}), 400

    if not bill_items:
        return jsonify({"error": "No valid items in cart."}), 400

    apply_vat = bool(data.get("apply_vat", False))
    tax       = round(subtotal * 0.13, 2) if apply_vat else 0.0
    total     = round(subtotal + tax, 2)
    subtotal  = round(subtotal, 2)
    bill_id   = str(uuid.uuid4()).upper().replace("-", "")[:12]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    creator   = session.get("user", {}).get("username", "Staff")

    # Build plain-text receipt
    lines = [
        "=" * 52,
        "         SHOP MANAGEMENT -- RECEIPT",
        "=" * 52,
        f"  Bill ID  : {bill_id}",
        f"  Date     : {timestamp}",
        f"  Cashier  : {creator}",
    ]
    if customer_name or customer_address:
        lines.append("-" * 52)
        if customer_name:
            lines.append(f"  Customer : {customer_name}")
        if customer_address:
            words  = customer_address
            prefix = "  Address  : "
            lines.append(f"{prefix}{words[:44]}")
            remainder = words[44:]
            while remainder:
                lines.append(f"{'':14}{remainder[:44]}")
                remainder = remainder[44:]
    lines += [
        "-" * 52,
        f"  {'ITEM':<18} {'QTY':>4} {'PRICE':>11} {'TOTAL':>13}",
        "-" * 52,
    ]
    for item in bill_items:
        lines.append(
            f"  {item['name']:<18} {item['qty']:>4} "
            f"Rs. {item['unit_price']:>7.2f} Rs. {item['line_total']:>9.2f}"
        )
    if apply_vat:
        lines += [
            "-" * 52,
            f"  {'Subtotal':<30} Rs. {subtotal:>13.2f}",
            f"  {'VAT (13%)':<30} Rs. {tax:>13.2f}",
            "=" * 52,
            f"  {'TOTAL AMOUNT':<30} Rs. {total:>13.2f}",
            "=" * 52,
            "       Thank you for shopping with us!",
            "=" * 52,
        ]
    else:
        lines += [
            "=" * 52,
            f"  {'TOTAL AMOUNT':<30} Rs. {total:>13.2f}",
            "=" * 52,
            "       Thank you for shopping with us!",
            "=" * 52,
        ]
    bill_text = "\n".join(lines)

    # Deduct stock
    for item in bill_items:
        inventory[item["name"]]["quantity"] -= item["qty"]
    save_inventory(inventory)

    # Save bill with creator & total
    save_bill_file(
        bill_id,
        bill_text,
        password,
        customer_name=customer_name,
        customer_address=customer_address,
        created_by=creator,
        total_amount=total,
    )

    return jsonify({
        "bill_id":          bill_id,
        "timestamp":        timestamp,
        "customer_name":    customer_name,
        "customer_address": customer_address,
        "items":            bill_items,
        "subtotal":         subtotal,
        "tax":              tax,
        "apply_vat":        apply_vat,
        "total":            total,
        "bill_text":        bill_text,
        "saved":            True,
        "protected":        bool(password),
    })


# ══════════════════════════════════════════════════════════
#  ROUTES – Saved Bills & Password Recovery
# ══════════════════════════════════════════════════════════

@app.route("/bills")
@login_required
def bills_list():
    """List all saved bill files with customer metadata."""
    os.makedirs(BILLS_FOLDER, exist_ok=True)
    ids = sorted(
        [f.replace("bill_", "").replace(".txt", "")
         for f in os.listdir(BILLS_FOLDER) if f.endswith(".txt")],
        reverse=True,
    )
    bills = [read_bill_metadata(bid) for bid in ids]
    return render_template("bills.html", bills=bills)


@app.route("/bills/<bill_id>", methods=["GET", "POST"])
@login_required
def view_bill(bill_id):
    """
    View saved bill.
    If protected and user is Admin, allows Master Unlock.
    """
    bill_id  = bill_id.upper()
    is_admin = session.get("user", {}).get("role") == "admin"
    password = request.form.get("password", "") if request.method == "POST" else ""

    # Check if admin requested master unlock via form or query
    force_admin_unlock = is_admin and (request.args.get("admin_unlock") == "1" or request.form.get("admin_override") == "1")

    bill_text, error = read_bill_file(bill_id, password=password, is_admin=force_admin_unlock)

    if error == "PASSWORD_REQUIRED":
        return render_template("view_bill.html", bill_id=bill_id, needs_password=True, is_admin=is_admin)
    if error == "WRONG_PASSWORD":
        flash("Incorrect password. Please try again or ask an Admin to unlock.", "danger")
        return render_template("view_bill.html", bill_id=bill_id, needs_password=True, is_admin=is_admin)
    if error:
        flash(error, "danger")
        return redirect(url_for("bills_list"))

    return render_template(
        "view_bill.html",
        bill_id=bill_id,
        bill_text=bill_text,
        needs_password=False,
        is_admin=is_admin,
        was_admin_unlocked=force_admin_unlock,
    )


@app.route("/bills/<bill_id>/admin-unlock")
@admin_required
def admin_unlock_bill(bill_id):
    """Admin Master Recovery: View any protected bill immediately."""
    bill_id = sanitize_bill_id(bill_id)
    bill_text, error = read_bill_file(bill_id, is_admin=True)
    if error:
        flash(f"Could not unlock bill: {error}", "danger")
        return redirect(url_for("bills_list"))

    log_security_event("BILL_MASTER_UNLOCKED", f"Bill '{bill_id}' decrypted using Master Recovery Key", "WARNING")
    flash(f"Bill {bill_id} unlocked using Admin Master Recovery!", "success")
    return render_template(
        "view_bill.html",
        bill_id=bill_id,
        bill_text=bill_text,
        needs_password=False,
        was_admin_unlocked=True,
    )


@app.route("/bills/<bill_id>/reset-password", methods=["GET", "POST"])
@admin_required
def reset_bill_password(bill_id):
    """
    Admin Reset / Remove Password for a Bill:
    Solves 'Forgot Bill Password' completely!
    """
    bill_id = sanitize_bill_id(bill_id)
    meta    = read_bill_metadata(bill_id)

    # First decrypt bill using Admin Master Recovery
    bill_text, error = read_bill_file(bill_id, is_admin=True)
    if error:
        flash(f"Cannot access bill: {error}", "danger")
        return redirect(url_for("bills_list"))

    if request.method == "POST":
        action       = request.form.get("action")
        new_password = request.form.get("new_password", "").strip()

        if action == "remove":
            save_password = ""
            msg = f"Password protection completely removed from Bill {bill_id}!"
            log_security_event("BILL_SECURITY_REMOVED", f"Password removed from Bill '{bill_id}'", "INFO")
        else:
            if not new_password or len(new_password) < 4:
                flash("Please enter a new password (min 4 characters).", "danger")
                return render_template("reset_bill_password.html", bill_id=bill_id, meta=meta)
            save_password = new_password
            msg = f"Password for Bill {bill_id} updated to new password!"
            log_security_event("BILL_PASSWORD_RESET", f"Password updated for Bill '{bill_id}'", "INFO")

        save_bill_file(
            bill_id,
            bill_text,
            save_password,
            customer_name=meta.get("customer_name", ""),
            customer_address=meta.get("customer_address", ""),
            created_by=meta.get("created_by", "Admin"),
            total_amount=meta.get("total_amount", 0.0),
        )
        flash(msg, "success")
        return redirect(url_for("view_bill", bill_id=bill_id))

    return render_template("reset_bill_password.html", bill_id=bill_id, meta=meta)


@app.route("/bills/<bill_id>/delete", methods=["POST"])
@admin_required
def delete_bill(bill_id):
    """Admin-only: Delete an obsolete bill file."""
    bill_id  = sanitize_bill_id(bill_id)
    filepath = os.path.join(BILLS_FOLDER, f"bill_{bill_id}.txt")
    if os.path.exists(filepath):
        os.remove(filepath)
        log_security_event("BILL_DELETED", f"Bill '{bill_id}' permanently deleted by Admin", "DANGER")
        flash(f"Bill {bill_id} has been permanently deleted.", "success")
    else:
        flash("Bill file not found.", "danger")
    return redirect(url_for("bills_list"))


@app.route("/bills/<bill_id>/edit", methods=["GET", "POST"])
@login_required
def edit_bill(bill_id):
    """
    Edit bill customer name, address, or password.
    Admin can edit directly without needing the old password!
    """
    bill_id  = sanitize_bill_id(bill_id)
    meta     = read_bill_metadata(bill_id)
    is_admin = session.get("user", {}).get("role") == "admin"

    # ── GET ─────────────────────────────────────────────
    if request.method == "GET":
        needs_pw = meta["protected"] and not is_admin
        return render_template("edit_bill.html", bill_id=bill_id,
                               meta=meta, needs_password=needs_pw)

    # ── POST ─────────────────────────────────────────────
    current_password = request.form.get("current_password", "").strip()
    new_name         = request.form.get("customer_name",    "").strip()
    new_address      = request.form.get("customer_address", "").strip()
    new_password     = request.form.get("new_password",     "").strip()
    remove_password  = request.form.get("remove_password")

    if not new_name:
        flash("Customer name cannot be empty.", "danger")
        return redirect(url_for("edit_bill", bill_id=bill_id))

    # Decrypt existing body
    bill_text, error = read_bill_file(bill_id, current_password, is_admin=is_admin)

    if error == "PASSWORD_REQUIRED":
        flash("Current password is required to edit this bill.", "danger")
        return render_template("edit_bill.html", bill_id=bill_id,
                               meta=meta, needs_password=True)
    if error == "WRONG_PASSWORD":
        flash("Incorrect current password.", "danger")
        return render_template("edit_bill.html", bill_id=bill_id,
                               meta=meta, needs_password=True)
    if error:
        flash(error, "danger")
        return redirect(url_for("bills_list"))

    # Rebuild receipt: replace old customer block
    new_lines  = []
    skip_until = None

    for line in bill_text.splitlines():
        if line.startswith("  Customer : ") or line.startswith("  Address  : "):
            skip_until = "separator"
            continue
        if skip_until == "separator" and line.startswith("              "):
            continue
        else:
            skip_until = None

        new_lines.append(line)
        if line.startswith("  Date     : ") or line.startswith("  Cashier  : "):
            # Inject customer block
            new_lines.append("-" * 52)
            new_lines.append(f"  Customer : {new_name}")
            if new_address:
                new_lines.append(f"  Address  : {new_address[:44]}")
                remainder = new_address[44:]
                while remainder:
                    new_lines.append(f"{'':14}{remainder[:44]}")
                    remainder = remainder[44:]

    bill_text = "\n".join(new_lines)

    if remove_password:
        save_password = ""
    elif new_password:
        save_password = new_password
    else:
        save_password = current_password

    save_bill_file(
        bill_id, bill_text, save_password,
        customer_name=new_name,
        customer_address=new_address,
        created_by=meta.get("created_by", "Staff"),
        total_amount=meta.get("total_amount", 0.0),
    )

    flash(f"Bill {bill_id} updated successfully!", "success")
    return redirect(url_for("view_bill", bill_id=bill_id))


# ══════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "production").lower() == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
