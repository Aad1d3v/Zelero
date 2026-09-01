from flask import Flask, request, jsonify, session, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
import json as _json
import os
import re
import secrets
import sqlite3
import threading
import time as _time_mod
import urllib.request
from collections import deque
from datetime import timedelta

# SECURITY: no static_folder. The previous setup (static_folder='.') served EVERY
# file in this directory over HTTP, including codehelper.db (all users' password
# hashes) and .secret_key (the session-signing key — leaking it lets anyone forge
# a login cookie for any account). Static files are now served from an explicit
# whitelist below; everything else 404s.
BASE_DIR = os.path.dirname(__file__)
app = Flask(__name__)

# Hosted deploys (Render, Railway, Fly…) put the app behind a reverse proxy, so
# request.remote_addr is the proxy's internal IP for EVERY user. That breaks
# per-IP protections (brute-force limiter) and logs the wrong IP. Trust the
# proxy's X-Forwarded-For / X-Forwarded-Proto headers ONLY when TRUST_PROXY=1
# is explicitly set (Render overwrites these at the edge, so they are safe to
# trust there). Locally the flag stays off, so spoofed headers are ignored.
if os.environ.get('TRUST_PROXY') == '1':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Persistent secret key: SECRET_KEY env var wins (recommended in hosted deploys,
# where an ephemeral disk would regenerate the file and invalidate all sessions
# on every restart); otherwise a .secret_key file on disk so local sessions
# survive server restarts. Kept outside the served-file whitelist and outside
# version control.
SECRET_FILE = os.path.join(BASE_DIR, '.secret_key')
app.secret_key = os.environ.get('SECRET_KEY') or ''
if not app.secret_key and os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, 'r') as f:
        app.secret_key = f.read().strip()
if not app.secret_key:
    # Fresh key. On hosts with an EPHEMERAL disk (Render free tier, containers
    # without a volume) this regenerates on every restart, silently logging
    # every user out. Warn loudly so this is caught at deploy time.
    app.secret_key = secrets.token_hex(32)
    try:
        with open(SECRET_FILE, 'w') as f:
            f.write(app.secret_key)
    except OSError:
        pass  # read-only filesystem: key lives in memory for this process only
    import sys as _sys
    _sys.stderr.write('WARNING: SECRET_KEY is not set. Generated a temporary session key — '
                      'users will be logged out on the next restart. Set SECRET_KEY in the '
                      'deploy environment (e.g. Render) for persistent sessions.\n')
    _sys.stderr.flush()

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Secure cookies (HTTPS-only) for hosted deploys: set SESSION_COOKIE_SECURE=1 in
# the deploy environment. Left off by default so local http://127.0.0.1 keeps working.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE') == '1'
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Keep users signed in for 30 days across browser restarts.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
# Reject oversized request bodies early so huge JSON payloads can't choke the server.
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# DB location can be overridden (e.g. a mounted persistent disk in a hosted
# deploy); defaults to codehelper.db next to app.py. ZELERO_DB_PATH is the
# current name; DEVLY_DB_PATH is accepted for backwards compatibility.
DB_PATH = (os.environ.get('ZELERO_DB_PATH') or os.environ.get('DEVLY_DB_PATH')
           or os.path.join(BASE_DIR, 'codehelper.db'))

# Real email domains that should be accepted
VALID_EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.ca', 'yahoo.com.au',
    'hotmail.com', 'hotmail.co.uk', 'outlook.com', 'outlook.co.uk',
    'live.com', 'live.co.uk', 'msn.com',
    'icloud.com', 'me.com', 'mac.com',
    'aol.com', 'aim.com',
    'protonmail.com', 'proton.me',
    'zoho.com', 'yandex.com',
    'mail.com', 'email.com',
    'fastmail.com',
    'gmx.com', 'gmx.net',
    'tutanota.com', 'tutamail.com',
    'hey.com',
    'pm.me',
    'college.harvard.edu', 'stanford.edu', 'mit.edu',
    'code.org', 'github.com',
}

def is_valid_email(email):
    """Validate email format and domain"""
    if not email or '@' not in email:
        return False, 'Please enter a valid email address'

    # Basic format check
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, 'Please enter a valid email address'

    # Check domain
    domain = email.split('@')[1].lower()
    if domain not in VALID_EMAIL_DOMAINS:
        return False, f'Please use a real email provider (Gmail, Yahoo, Outlook, etc.)'

    return True, ''

def get_db():
    # timeout=30: waitress serves requests on multiple threads, and SQLite's
    # default 5s lock timeout can throw 'database is locked' under concurrent
    # writes. WAL mode lets readers proceed during writes.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA journal_mode=WAL')
    except sqlite3.Error:
        pass
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT DEFAULT '',
            intro_seen INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Migration for databases created before the intro_seen column existed.
    cols = {r[1] for r in conn.execute('PRAGMA table_info(users)').fetchall()}
    if 'intro_seen' not in cols:
        conn.execute('ALTER TABLE users ADD COLUMN intro_seen INTEGER DEFAULT 0')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tool TEXT NOT NULL,
            input_text TEXT,
            output_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# Create tables at import time too, so the app also works under a real WSGI
# server (gunicorn/waitress), not just `python app.py`. CREATE IF NOT EXISTS is
# idempotent, so this is safe to run on every start.
init_db()

def record_login(user_id, event):
    """Log a sign-in / sign-up event for the user."""
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO login_logs (user_id, event, ip) VALUES (?, ?, ?)',
            (user_id, event, request.remote_addr)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

@app.after_request
def add_security_headers(resp):
    # Basic hardening for every response (also covers API JSON + error pages).
    # X-Frame-Options: DENY blocks clickjacking; nosniff forces the declared
    # content type; CSP default-src 'self' stops third-party script injection
    # (external fonts loaded via <link> are fine because self-based pages still
    # fetch them, but see the explicit style-src/font-src for Google Fonts).
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return resp

@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/style.css')
def style_css():
    # Only explicitly whitelisted files are ever served; anything else 404s.
    return send_from_directory(BASE_DIR, 'style.css')

@app.route('/api/health')
def health():
    # Readiness probe for Render / uptime monitors. Returns 503 when the DB is
    # unreachable so the platform restarts the instance instead of routing
    # traffic to one that is broken (Render cancels deploys on non-2xx).
    try:
        conn = get_db()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False
    payload = {
        'ok': db_ok,
        'service': 'Zelero',
        'db': 'ok' if db_ok else 'unreachable',
        'ai': 'configured' if GROQ_API_KEY else 'not configured',
    }
    return jsonify(payload), (200 if db_ok else 503)

# ---- Simple in-memory brute-force protection for /api/auth/login ----
_MAX_FAILED_LOGINS = 8
_LOGIN_WINDOW_SECONDS = 900  # 15 minutes
_login_failures = {}
_login_lock = threading.Lock()
# A hash of a throwaway password: burned when an email is unknown so the
# response time doesn't reveal whether an email is registered (user enumeration).
_DUMMY_PASSWORD_HASH = generate_password_hash('invalid-password-timing-pad')

def _failed_count(key, now):
    dq = _login_failures.get(key)
    if not dq:
        return 0
    while dq and now - dq[0] > _LOGIN_WINDOW_SECONDS:
        dq.popleft()
    return len(dq)

def _too_many_failed_logins(keys):
    now = _time_mod.time()
    with _login_lock:
        return any(_failed_count(k, now) >= _MAX_FAILED_LOGINS for k in keys)

def _record_failed_login(key):
    with _login_lock:
        dq = _login_failures.setdefault(key, deque())
        dq.append(_time_mod.time())
        # Periodically purge stale entries so the dict can't grow without bound.
        if len(_login_failures) > 5000:
            now = _time_mod.time()
            stale = [k for k, v in _login_failures.items() if not v or now - v[-1] > _LOGIN_WINDOW_SECONDS]
            for k in stale:
                _login_failures.pop(k, None)

def _clear_failed_logins(keys):
    with _login_lock:
        for k in keys:
            _login_failures.pop(k, None)

@app.errorhandler(Exception)
def handle_unexpected(e):
    """Return a clean JSON error for any unexpected exception so the API stays
    predictable even when fed malformed input, and never leaks an HTML traceback."""
    # Let normal HTTP errors (404, 400, 401, ...) keep their correct status codes.
    if isinstance(e, HTTPException) and e.code != 500:
        return jsonify({'error': e.name or 'Error'}), e.code
    app.logger.error('Unexpected error: %s', e)
    return jsonify({'error': 'Something went wrong on our end. Please try again.'}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '') or '').strip().lower()
    password = str(data.get('password', '') or '')
    name = str(data.get('name', '') or '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Validate email
    valid, msg = is_valid_email(email)
    if not valid:
        return jsonify({'error': msg}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    if len(password) > 128:
        return jsonify({'error': 'Password is too long'}), 400

    if len(email) > 254:
        return jsonify({'error': 'Email is too long'}), 400
    if len(name) > 80:
        name = name[:80]

    conn = get_db()
    try:
        existing = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing:
            return jsonify({'error': 'An account with this email already exists'}), 409

        password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        display_name = name if name else email.split('@')[0].replace('.', ' ').replace('_', ' ').title()

        conn.execute(
            'INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)',
            (email, password_hash, display_name)
        )
        conn.commit()

        user = conn.execute('SELECT id, email, name, intro_seen FROM users WHERE email = ?', (email,)).fetchone()
        session.permanent = True
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user['name']
        record_login(user['id'], 'register')

        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'introSeen': bool(user['intro_seen'])
            }
        })
    except sqlite3.IntegrityError:
        # Two concurrent registrations for the same email can race past the
        # SELECT check above; the UNIQUE constraint is the real authority.
        return jsonify({'error': 'An account with this email already exists'}), 409
    except Exception:
        app.logger.exception('Registration failed')
        return jsonify({'error': 'Registration failed. Please try again.'}), 500
    finally:
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '') or '').strip().lower()
    password = str(data.get('password', '') or '')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Cap the password length before hashing it: pbkdf2 on megabyte-sized input
    # would burn CPU and make login trivially slow (DoS vector).
    if len(password) > 128:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Brute-force protection: too many recent failures for this IP or this
    # email account locks sign-in attempts for the window.
    ip = request.remote_addr or 'unknown'
    keys = ('ip:' + ip, 'email:' + email)
    if _too_many_failed_logins(keys):
        return jsonify({'error': 'Too many failed sign-in attempts. Please wait a few minutes and try again.'}), 429

    conn = get_db()
    try:
        user = conn.execute(
            'SELECT id, email, name, password_hash, intro_seen FROM users WHERE email = ?',
            (email,)
        ).fetchone()

        if not user:
            # Burn the same hashing time as a real password check so attackers
            # can't infer which emails are registered from response timing.
            check_password_hash(_DUMMY_PASSWORD_HASH, password)
            for k in keys:
                _record_failed_login(k)
            return jsonify({'error': 'Invalid email or password'}), 401

        if not check_password_hash(user['password_hash'], password):
            for k in keys:
                _record_failed_login(k)
            return jsonify({'error': 'Invalid email or password'}), 401

        # Successful sign-in resets the failure counters.
        _clear_failed_logins(keys)

        session.permanent = True
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user['name']
        record_login(user['id'], 'login')

        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'introSeen': bool(user['intro_seen'])
            }
        })
    finally:
        conn.close()

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/intro-seen', methods=['POST'])
def intro_seen():
    """Mark the welcome/onboarding tour as seen so it only shows on first sign-in."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    conn = get_db()
    try:
        conn.execute('UPDATE users SET intro_seen = 1 WHERE id = ?', (session['user_id'],))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'success': True})

@app.route('/api/auth/me')
def me():
    if 'user_id' in session:
        # .get() guards against a partial/corrupted session cookie (e.g. one
        # written by an older version) raising KeyError -> 500.
        # The name is read live from the DB so profile renames show up
        # without re-login (session cookie caches the old name).
        name = ''
        intro_seen = 0
        conn = get_db()
        try:
            row = conn.execute('SELECT name, intro_seen FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        finally:
            conn.close()
        if row is not None:
            name = row['name'] or session.get('user_name') or ''
            intro_seen = row['intro_seen'] or 0
        return jsonify({
            'loggedIn': True,
            'user': {
                'id': session['user_id'],
                'email': session.get('user_email') or '',
                'name': name,
                'introSeen': bool(intro_seen)
            }
        })
    return jsonify({'loggedIn': False})

@app.route('/api/conversations', methods=['GET'])
def get_conversations():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db()
    try:
        convos = conn.execute(
            'SELECT id, tool, input_text, output_text, created_at FROM conversations WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
            (session['user_id'],)
        ).fetchall()
        return jsonify({
            'conversations': [dict(c) for c in convos]
        })
    finally:
        conn.close()

@app.route('/api/conversations', methods=['POST'])
def save_conversation():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json(silent=True) or {}
    # Coerce to str and cap length: a JSON number/None/dict for these fields
    # would crash sqlite's parameter binding with a 500, and unbounded strings
    # would let one request stuff the database.
    tool = str(data.get('tool', '') or '')[:60]
    input_text = str(data.get('input', '') or '')[:100000]
    output_text = str(data.get('output', '') or '')[:200000]

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO conversations (user_id, tool, input_text, output_text) VALUES (?, ?, ?, ?)',
            (session['user_id'], tool, input_text, output_text)
        )
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# ---- AI (Groq) ----

def _load_groq_key():
    """The API key must never live in source code — the previous hardcoded key
    was leaked with the repo. It is read from the GROQ_API_KEY environment
    variable first, then from the local, untracked .groq_key file next to
    app.py. NOTE: the old key was exposed in source; rotate it in the Groq
    dashboard and put the new one in .groq_key (or the env var)."""
    key = os.environ.get('GROQ_API_KEY', '').strip()
    if key:
        return key
    key_file = os.path.join(BASE_DIR, '.groq_key')
    if os.path.exists(key_file):
        try:
            with open(key_file, 'r') as f:
                k = f.read().strip()
                if k:
                    return k
        except OSError:
            pass
    return ''

GROQ_API_KEY = _load_groq_key()
# Primary model: a reasoning model great for deep analysis, but it's heavy on the
# free tier (fast rate limits + spends tokens "thinking"). GROQ_MODEL_FAST is a
# cheap, fast, dependable model used as a fallback on rate limits / empty replies
# so the app stays usable under load instead of erroring out.
GROQ_MODEL = os.environ.get('GROQ_MODEL', 'openai/gpt-oss-20b')
GROQ_MODEL_FAST = os.environ.get('GROQ_MODEL_FAST', 'groq/compound-mini')
GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions'

# Serialize AI calls and throttle them to respect the free-tier rate limit.
_ai_lock = threading.Lock()
_ai_last_call = 0.0

FORMAT_RULES = (
    "CRITICAL FORMATTING RULES: "
    "1. Every piece of code you show must be wrapped in markdown code fences with the language name (e.g. ```python). "
    "2. Preserve the user's original code formatting exactly inside fences — keep all indentation, line breaks, and whitespace as the user wrote it. "
    "3. Never inline code as a single paragraph or one long line — always use proper multi-line code blocks. "
    "4. NEVER use markdown tables (no | or --- separators) and NEVER use horizontal rules (---). "
    "5. Instead structure answers with clear ## headings, short readable paragraphs, - bullet lists, and numbered steps. "
    "6. For each issue, write one short paragraph that says what is wrong, why it matters, and how to fix it — keep it easy to read. "
    "7. MISTAKE LEVEL: If the code or error has issues, end your response with a '## Mistake Level' section — follow the exact format in the user's instructions."
)

MISTAKE_REQ = (
    "\n\nMANDATORY FINAL SECTION — '## Mistake Level': if the code or error above has any issues, "
    "end your response with a heading '## Mistake Level' and one bullet per issue in exactly this format: "
    "'- **<Level>** — <short description>', where <Level> is one of exactly: Rookie, Beginner, Intermediate, Advanced, or 'Even pros make this'. "
    "Never use severity words like Critical or Minor there. If there are no issues, omit the section."
)

CHAT_SYSTEM = (
    "You are Aadi-04, an expert coding assistant built into Zelero, modeled after Claude. "
    "You specialize in analyzing code: explaining what it does, finding bugs, "
    "suggesting improvements, fixing errors, converting between languages, and teaching concepts. "
    "When the user provides code, analyze it in detail and point out issues, edge cases, "
    "and improvements with line references. Never claim code is correct without checking it line by line. "
    "If they ask a question, answer it precisely and clearly. Keep responses practical and well-structured."
    + FORMAT_RULES
)

ANALYZE_SYSTEM = (
    "You are Aadi-04, a rigorous code reviewer. Your job is to find EVERY problem in the code the user provides. "
    "Do NOT say code is correct unless you are certain. Scrutinize line by line for: "
    "- Syntax errors, missing colons, wrong indentation, unbalanced brackets/parens/quotes "
    "- Logic bugs, off-by-one errors, wrong operators, infinite loops "
    "- Runtime errors: undefined variables, wrong types, division by zero, None usage "
    "- Bad practices, unused imports/variables, security issues, performance problems "
    "For each issue, give the severity (Critical / Warning / Minor / Suggestion), the line number, and a clear fix. "
    "If the code genuinely has no errors, say so plainly and then suggest improvements anyway. "
    "If a syntax check was provided and reported an error, that is authoritative: use it and explain it."
    + FORMAT_RULES
)

ERROR_SYSTEM = (
    "You are Aadi-04, an expert at decoding error messages. The user pasted an error or traceback. "
    "Explain precisely: 1) What the error means in plain words, 2) The exact root cause with the line number from the traceback, "
    "3) How to fix it with corrected code in a code fence. "
    "If the error is ambiguous, say so and list the likely causes. Never invent details not in the traceback."
    + FORMAT_RULES
)

DEBUG_SYSTEM = (
    "You are Aadi-04, an expert debugger. The user pasted source code and an error output. "
    "Find the exact bug that causes the error. Report: 1) The bug location (function and line), "
    "2) Why it happens (explain the failing logic), 3) The fix as corrected code in a code fence, "
    "4) Any related bugs you notice. Be specific and reference actual lines from their code."
    + FORMAT_RULES
)

CONVERT_SYSTEM = (
    "You are Aadi-04, an expert at converting code between programming languages. "
    "The user provided code in one language and wants it converted to another. "
    "Produce a faithful, idiomatic translation that preserves the original logic exactly. "
    "Wrap the converted code in a code fence with the target language name. "
    "If the conversion is not straightforward, briefly note what changed and why."
    + FORMAT_RULES
)

SYSTEMS = {
    'chat': CHAT_SYSTEM,
    'analyze': ANALYZE_SYSTEM,
    'errors': ERROR_SYSTEM,
    'debug': DEBUG_SYSTEM,
    'convert': CONVERT_SYSTEM,
}

def check_python_syntax(code):
    """Return a real syntax error report for Python code, or None if valid."""
    try:
        compile(code, '<user_code>', 'exec')
        return None
    except SyntaxError as e:
        return {
            'line': e.lineno,
            'offset': e.offset,
            'msg': e.msg,
            'text': (e.text or '').strip(),
        }
    except ValueError:
        return {'msg': 'Code contains a null byte or invalid character.'}
    except Exception as e:
        return {'msg': str(e)}

def _ai_mistake_level_section(prev_reply):
    """One short follow-up call: write only the missing '## Mistake Level' section."""
    follow_payload = {
        'model': GROQ_MODEL,
        'messages': [
            {'role': 'system', 'content': (
                'You are Aadi-04. You just wrote an analysis of someone\'s code but forgot the mandatory final section. '
                'Output ONLY that missing section now, nothing else.'
            )},
            {'role': 'user', 'content': (
                'Below is the analysis you just wrote. Add the mandatory final "## Mistake Level" section listing EVERY issue '
                'found in it, one bullet per issue, in exactly this format: "- **<Level>** — <short description of the issue>". '
                '<Level> must be exactly one of: Rookie, Beginner, Intermediate, Advanced, or "Even pros make this" '
                '(never severity words like Critical or Minor). Output ONLY the section — the heading "## Mistake Level" and the bullets. '
                'If no issues were found, output only: No issues found.\n\n---\n' + prev_reply[:3000]
            )},
        ],
        'temperature': 0.2,
        'max_tokens': 800,
    }
    try:
        req = urllib.request.Request(
            GROQ_URL,
            data=_json.dumps(follow_payload).encode('utf-8'),
            headers={
                'Authorization': 'Bearer ' + GROQ_API_KEY,
                'Content-Type': 'application/json',
                'User-Agent': 'Zelero/1.0 (Aadi-04)',
                'Accept': 'application/json',
            },
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = _json.loads(resp.read().decode('utf-8'))
            extra = (result['choices'][0]['message'].get('content') or '').strip()
        if extra and 'no issues found' not in extra.lower():
            return extra
    except Exception:
        pass
    return ''

@app.route('/api/ai/chat', methods=['POST'])
def ai_chat():
    data = request.get_json(silent=True) or {}
    try:
        prompt = str(data.get('prompt') or '').strip()
        code = str(data.get('code') or '').strip()
        lang = str(data.get('lang') or 'python').strip().lower()
        mode = str(data.get('mode') or 'chat').strip().lower()
        to_lang = str(data.get('toLang') or '').strip()
    except Exception:
        prompt = code = ''
        lang = 'python'
        mode = 'chat'
        to_lang = ''

    if mode not in SYSTEMS:
        mode = 'chat'

    if not prompt and not code:
        return jsonify({'error': 'Nothing to ask'}), 400

    if not GROQ_API_KEY:
        return jsonify({'error': 'AI is not configured. Set the GROQ_API_KEY environment variable or put the key in the .groq_key file next to app.py.'}), 503

    # Cap oversized AI payloads up front: a ~900KB prompt survives the 2MB body
    # cap but Groq rejects it as "reduce the length of the messages" — an opaque
    # 502 for the user. 200k chars (~50k tokens) is comfortably above any
    # sensible paste and far below the model's context limit.
    MAX_AI_CHARS = 200000
    if len(prompt) > MAX_AI_CHARS:
        return jsonify({'error': 'Your message is too long — please trim it and try again.'}), 413
    if len(code) > MAX_AI_CHARS:
        return jsonify({'error': 'Your code is too long — please trim it and try again.'}), 413

    # Real Python syntax verification (authoritative for analyze/debug/chat on python code)
    syntax_note = ''
    if code and lang == 'python' and mode in ('analyze', 'debug', 'chat'):
        err = check_python_syntax(code)
        if err:
            syntax_note = (
                f"\n\n[AUTHORITATIVE SYNTAX CHECK RESULT]: "
                f"Python failed to compile this code. SyntaxError on line {err.get('line')}: "
                f"{err.get('msg')}. Line content: {err.get('text', '')}. "
                f"This error is real and verified by the Python interpreter — you must report and explain it."
            )
        else:
            syntax_note = (
                "\n\n[AUTHORITATIVE SYNTAX CHECK RESULT]: "
                "Python compiled this code successfully with no syntax errors. "
                "Note: this only proves syntax is valid — runtime and logic errors are still possible and you must check for them."
            )

    if mode == 'analyze':
        user_content = f"Analyze this {lang} code thoroughly and report every problem:\n```{lang}\n{code}\n```{syntax_note}" + MISTAKE_REQ
    elif mode == 'errors':
        user_content = f"Decode this error message and explain how to fix it:\n```text\n{prompt or code}\n```" + MISTAKE_REQ
    elif mode == 'debug':
        user_content = (
            f"Debug this code with the error output below. Find the exact bug and fix it.\n"
            f"Source code ({lang}):\n```{lang}\n{code}\n```\n"
            f"Error output:\n```text\n{prompt or '(no error output provided — analyze the code for likely runtime errors)'}\n```{syntax_note}" + MISTAKE_REQ
        )
    elif mode == 'convert':
        user_content = (
            f"Convert this {lang} code to {to_lang or 'JavaScript'}:\n```{lang}\n{code}\n```"
        )
    else:
        user_content = prompt
        if code:
            user_content = (user_content + '\n\n' if user_content else '') + (
                f"Here is my code (language: {lang}):\n```{lang}\n{code}\n```\n\n"
                f"Please analyze this code and answer my question about it." + syntax_note + MISTAKE_REQ
            )

    # gpt-oss is a reasoning model: it spends tokens "thinking" before answering,
    # so give it enough headroom for reasoning + the final answer.
    payload = {
        'model': GROQ_MODEL,
        'messages': [
            {'role': 'system', 'content': SYSTEMS[mode]},
            {'role': 'user', 'content': user_content}
        ],
        'temperature': 0.3,
        # gpt-oss spends a large chunk on reasoning, so give it enough room
        # for reasoning + the full detailed analysis + the Mistake Level section.
        'max_tokens': 4096,
    }

    # Space requests out so the free-tier token budget (8k/min) is not exhausted.
    global _ai_last_call
    _ai_lock.acquire()
    try:
        wait = _ai_last_call + 1.2 - _time_mod.time()
        if wait > 0:
            _time_mod.sleep(wait)

        attempts = 0
        last_err = None
        while attempts < 5:
            attempts += 1
            # Fall back to the cheap, fast model when the reasoning model
            # rate-limits or keeps returning empty content, so the app stays
            # usable under heavy load instead of erroring out.
            if last_err and last_err[0] in ('rate', 'empty'):
                payload['model'] = GROQ_MODEL_FAST
                # Fast model isn't a reasoning model — it doesn't need the huge
                # headroom, and a smaller cap keeps it cheap and quick.
                payload['max_tokens'] = 2048
            req = urllib.request.Request(
                GROQ_URL,
                data=_json.dumps(payload).encode('utf-8'),
                headers={
                    'Authorization': 'Bearer ' + GROQ_API_KEY,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Zelero/1.0 (Aadi-04)',
                    'Accept': 'application/json',
                },
                method='POST'
            )
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    result = _json.loads(resp.read().decode('utf-8'))
                msg = result['choices'][0]['message']
                reply = (msg.get('content') or '').strip()
                # Reasoning models occasionally spend the whole budget "thinking"
                # and return empty content — treat that as retryable.
                if not reply:
                    if attempts >= 3:
                        reasoning = msg.get('reasoning') or ''
                        # Must be a real error status — returning 200 with an
                        # error body made every client treat it as success-ish.
                        return jsonify({'error': 'Aadi-04 thought about it but produced no answer. Please try again.', 'detail': str(reasoning)[:200]}), 502
                    last_err = ('empty', attempts)
                    _time_mod.sleep(2)
                    continue
                _ai_last_call = _time_mod.time()
                # Guarantee the Mistake Level section: if the model forgot it,
                # make one cheap follow-up call that writes only that section.
                if mode in ('analyze', 'errors', 'debug') or (mode == 'chat' and code):
                    if '## mistake level' not in reply.lower():
                        extra = _ai_mistake_level_section(reply)
                        if extra:
                            reply = reply.rstrip() + '\n\n' + extra
                return jsonify({'reply': reply})
            except urllib.error.HTTPError as e:
                detail = e.read().decode('utf-8', errors='replace')[:300]
                if e.code == 429:
                    # Rate limited — wait longer each attempt (5s, 10s, 20s)
                    last_err = ('rate', 5 * attempts)
                    _time_mod.sleep(5 * attempts)
                elif e.code >= 500:
                    last_err = ('http', e.code)
                    _time_mod.sleep(2)
                else:
                    return jsonify({'error': f'AI request failed ({e.code})', 'detail': detail}), 502
            except Exception as e:
                last_err = ('exc', str(e)[:200])
                _time_mod.sleep(2)
        _ai_last_call = _time_mod.time()
        if last_err and last_err[0] == 'rate':
            return jsonify({'error': 'Aadi-04 is busy — rate limit reached. Please wait a moment and try again.'}), 429
        return jsonify({'error': 'AI request failed after retries', 'detail': str(last_err)}), 502
    finally:
        _ai_lock.release()

if __name__ == '__main__':
    init_db()
    # Deployment-friendly: PaaS platforms (Render, Railway, Fly…) set PORT and
    # expect the app to bind 0.0.0.0. Render's port scanner probes the public
    # interface — binding 127.0.0.1 (the old default) caused "No open ports
    # detected" + "Port scan timeout" even though the server was running.
    # Default is now 0.0.0.0 in ALL environments; set HOST to override.
    port = int(os.environ.get('PORT') or 5000)
    host = os.environ.get('HOST') or '0.0.0.0'
    print("\n" + "="*50)
    print("  Zelero Server")
    print("  http://%s:%s" % (host if host != '0.0.0.0' else '127.0.0.1', port))
    print("="*50 + "\n")
    # debug mode only when explicitly requested (FLASK_DEBUG=1) — safe for production.
    # Note: for real deployments prefer the WSGI entry point instead, e.g.
    #   waitress-serve --host=0.0.0.0 --port=$PORT app:app   (see requirements.txt / render.yaml)
    app.run(host=host, port=port, debug=os.environ.get('FLASK_DEBUG') == '1')
