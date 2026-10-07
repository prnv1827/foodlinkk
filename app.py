"""FoodLink - surplus food donation platform (Flask + SQLite, no extra libraries)."""
import hashlib
import hmac
import math
import os
import re
import secrets
import smtplib
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for, send_from_directory)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__, template_folder='.')

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
DEV_MODE = __name__ == '__main__' or os.environ.get('FLASK_DEBUG') == '1'
os.makedirs(app.instance_path, exist_ok=True)
UPLOAD_DIR = os.path.join(app.static_folder, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
# Sensitive NGO verification documents are kept outside /static so they are not public.
PRIVATE_UPLOAD_DIR = os.path.join(app.instance_path, 'verification_uploads')
os.makedirs(PRIVATE_UPLOAD_DIR, exist_ok=True)


def _secret_key():
    """SECRET_KEY env var, else a random key persisted in instance/secret_key."""
    key = os.environ.get('SECRET_KEY')
    if key:
        return key
    path = os.path.join(app.instance_path, 'secret_key')
    try:
        with open(path, 'x') as f:
            f.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    with open(path) as f:
        return f.read().strip()


app.config.update(
    SECRET_KEY=_secret_key(),
    DATABASE=os.environ.get('DATABASE_PATH', os.path.join(app.instance_path, 'foodlink.db')),
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE') == '1',
    REQUIRE_EMAIL_VERIFICATION=os.environ.get('REQUIRE_EMAIL_VERIFICATION') == '1',
)

CATEGORIES = ['Cooked meal', 'Bakery & bread', 'Fruits & vegetables', 'Packaged food',
              'Dairy', 'Beverages', 'Sweets & desserts', 'Grains & groceries', 'Other']
UNITS = ['kg', 'plates', 'packets', 'litres', 'pieces']
REPORT_TYPES = {
    'fake_donation': 'Fake donation',
    'unsafe_food': 'Spoiled / unsafe food',
    'fake_ngo': 'Fake NGO',
    'no_show': 'No-show',
    'incorrect_info': 'Incorrect information',
}
ACTIVE_STATUSES = ('AVAILABLE', 'REQUESTED', 'ACCEPTED', 'PICKED_UP')
OPEN_STATUSES = ('AVAILABLE', 'REQUESTED', 'ACCEPTED')      # before pickup
MAX_PICKUP_WINDOW_HOURS = 72
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_OTP_ATTEMPTS = 5
NEARBY_KM = 10
EXPIRING_SOON_MIN = 60
MAX_LOGIN_FAILS, LOCKOUT_SECONDS = 5, 300
DEFAULT_TZ_OFFSET = int(os.environ.get('DEFAULT_TZ_OFFSET', '-330'))  # JS style (UTC - local); IST

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
PHONE_RE = re.compile(r'^\+?[0-9][0-9\s\-]{8,14}$')

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL CHECK (role IN ('donor','ngo','admin')),
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    phone TEXT, address TEXT, lat REAL, lng REAL,
    reg_number TEXT,
    ngo_darpan_id TEXT,
    verification_doc TEXT,
    verification_doc_name TEXT,
    ngo_status TEXT CHECK (ngo_status IN ('PENDING','APPROVED','REJECTED')),
    is_verified INTEGER NOT NULL DEFAULT 0,
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','suspended','removed')),
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS donations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    donor_id INTEGER NOT NULL REFERENCES users(id),
    food_name TEXT NOT NULL,
    category TEXT NOT NULL,
    food_type TEXT NOT NULL CHECK (food_type IN ('veg','non-veg')),
    quantity REAL NOT NULL,
    unit TEXT NOT NULL,
    servings INTEGER NOT NULL,
    image_path TEXT,
    prepared_at TEXT NOT NULL,
    expiry_time TEXT NOT NULL,
    address TEXT NOT NULL,
    lat REAL, lng REAL,
    contact_name TEXT,
    contact_phone TEXT NOT NULL,
    instructions TEXT,
    status TEXT NOT NULL DEFAULT 'AVAILABLE' CHECK (status IN
        ('AVAILABLE','REQUESTED','ACCEPTED','PICKED_UP','COMPLETED','EXPIRED','CANCELLED')),
    expiry_notified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    picked_up_at TEXT, completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_donations_status_expiry ON donations(status, expiry_time);
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    donation_id INTEGER NOT NULL REFERENCES donations(id) ON DELETE CASCADE,
    ngo_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','ACCEPTED','REJECTED','CANCELLED')),
    pickup_otp TEXT,
    otp_attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    responded_at TEXT,
    UNIQUE (donation_id, ngo_id)
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL REFERENCES users(id),
    report_type TEXT NOT NULL,
    donation_id INTEGER REFERENCES donations(id),
    reported_user_id INTEGER REFERENCES users(id),
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','RESOLVED')),
    resolution_note TEXT,
    resolved_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    link TEXT,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
"""


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    # Backward-compatible migration for databases created by older FoodLink builds.
    cols = {r['name'] for r in db.execute('PRAGMA table_info(users)').fetchall()}
    for col, ddl in (
        ('ngo_darpan_id', 'ALTER TABLE users ADD COLUMN ngo_darpan_id TEXT'),
        ('verification_doc', 'ALTER TABLE users ADD COLUMN verification_doc TEXT'),
        ('verification_doc_name', 'ALTER TABLE users ADD COLUMN verification_doc_name TEXT'),
    ):
        if col not in cols:
            db.execute(ddl)
    db.commit()


def ensure_admin():
    """Create the first admin from ADMIN_EMAIL / ADMIN_PASSWORD (dev default only in dev mode)."""
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone():
        return
    email, pw = os.environ.get('ADMIN_EMAIL'), os.environ.get('ADMIN_PASSWORD')
    if not (email and pw):
        if not DEV_MODE:
            app.logger.warning('No admin account exists. Set ADMIN_EMAIL and ADMIN_PASSWORD and restart.')
            return
        email, pw = 'admin@foodlink.local', 'Admin@12345'
        app.logger.warning('DEV admin created: %s / %s  (set ADMIN_EMAIL/ADMIN_PASSWORD for real use)', email, pw)
    db.execute("INSERT INTO users (role, name, email, password_hash, ngo_status, email_verified, created_at) "
               "VALUES ('admin', 'Administrator', ?, ?, NULL, 1, ?)",
               (email.strip().lower(), generate_password_hash(pw), utcnow_str()))
    db.commit()


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def fmt(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def utcnow_str():
    return fmt(now_utc())


@app.template_filter('iso')
def iso_filter(ts):
    """'2026-10-07 12:00:00' (UTC) -> '2026-10-07T12:00:00Z' for JS."""
    return ts.replace(' ', 'T') + 'Z' if ts else ''


def to_float(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def to_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_coords(lat_s, lng_s):
    """-> (lat, lng, error). Both blank is fine (no location)."""
    if not (lat_s or '').strip() and not (lng_s or '').strip():
        return None, None, None
    lat, lng = to_float(lat_s), to_float(lng_s)
    if lat is None or lng is None or not (-90 <= lat <= 90 and -180 <= lng <= 180):
        return None, None, 'Location is invalid. Use the "Use my location" button or leave it blank.'
    return lat, lng, None


def haversine(lat1, lng1, lat2, lng2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def parse_local_dt(value, tz_offset):
    """datetime-local string + browser offset (minutes, UTC - local) -> naive UTC datetime."""
    for f in ('%Y-%m-%dT%H:%M', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime((value or '').strip(), f) + timedelta(minutes=tz_offset)
        except ValueError:
            continue
    return None


def safe_next(target):
    if target and target.startswith('/') and not target.startswith('//') and '\\' not in target:
        return target
    return None


def back(default_endpoint, **kw):
    """Redirect to the page the user came from (same host only)."""
    ref = request.referrer
    if ref:
        p = urlparse(ref)
        target = safe_next(p.path + ('?' + p.query if p.query else ''))
        if p.netloc == request.host and target:
            return redirect(target)
    return redirect(url_for(default_endpoint, **kw))


def valid_password(p):
    return len(p) >= 8 and re.search('[A-Za-z]', p) and re.search('[0-9]', p)


VERIFICATION_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png', '.webp'}
MAX_VERIFICATION_BYTES = 5 * 1024 * 1024


def save_verification_document(file_storage, user_id):
    """Save NGO evidence privately; return (stored_name, original_name, error)."""
    if not file_storage or not file_storage.filename:
        return None, None, 'Upload the NGO registration certificate.'
    original = os.path.basename(file_storage.filename).strip()
    ext = os.path.splitext(original)[1].lower()
    if ext not in VERIFICATION_EXTENSIONS:
        return None, None, 'Certificate must be PDF, JPG, JPEG, PNG or WebP.'
    data = file_storage.read(MAX_VERIFICATION_BYTES + 1)
    if len(data) > MAX_VERIFICATION_BYTES:
        return None, None, 'Verification document must be 5 MB or smaller.'
    if not data:
        return None, None, 'The uploaded verification document is empty.'
    stored = f'ngo_{user_id}_{secrets.token_hex(12)}{ext}'
    with open(os.path.join(PRIVATE_UPLOAD_DIR, stored), 'wb') as fh:
        fh.write(data)
    return stored, original, None


def sha(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def display_status(req_status, donation_status):
    """Status an NGO sees for one of its requests."""
    if req_status == 'REJECTED':
        return 'REJECTED'
    if donation_status in ('EXPIRED', 'CANCELLED'):
        return donation_status
    if req_status == 'ACCEPTED':
        return donation_status
    return req_status


def ngo_can_request(u):
    return bool(u and u['role'] == 'ngo' and u['ngo_status'] == 'APPROVED'
                and u['is_verified'] == 1 and u['account_status'] == 'active')


def ngo_block_reason(u):
    if u['ngo_status'] == 'PENDING':
        return 'Your NGO registration is still waiting for admin approval.'
    if u['ngo_status'] == 'REJECTED':
        return 'Your NGO registration was rejected. Contact the FoodLink admin.'
    if not u['is_verified']:
        return 'Your NGO is approved but not verified yet. Only verified NGOs can request food.'
    return 'Your NGO account cannot request food right now.'


def notify(user_id, message, link=None):
    get_db().execute('INSERT INTO notifications (user_id, message, link, created_at) VALUES (?,?,?,?)',
                     (user_id, message, link, utcnow_str()))


def email_verification_blocked():
    u = g.user
    if app.config['REQUIRE_EMAIL_VERIFICATION'] and not u['email_verified']:
        flash('Please verify your email address first. Use "Resend verification email" below the menu.', 'error')
        return True
    return False


def send_mail(to, subject, body):
    """Send via SMTP if MAIL_SERVER is configured; otherwise log to the console. -> bool sent"""
    host = os.environ.get('MAIL_SERVER')
    if not host:
        app.logger.warning('[EMAIL not configured] To: %s | Subject: %s\n%s', to, subject, body)
        return False
    try:
        msg = EmailMessage()
        msg['From'] = os.environ.get('MAIL_FROM', os.environ.get('MAIL_USERNAME', 'no-reply@foodlink.local'))
        msg['To'], msg['Subject'] = to, subject
        msg.set_content(body)
        with smtplib.SMTP(host, int(os.environ.get('MAIL_PORT', '587')), timeout=15) as s:
            s.starttls()
            if os.environ.get('MAIL_USERNAME'):
                s.login(os.environ['MAIL_USERNAME'], os.environ.get('MAIL_PASSWORD', ''))
            s.send_message(msg)
        return True
    except Exception:  # noqa: BLE001 - never crash a request because mail failed
        app.logger.exception('Could not send email to %s', to)
        return False


def send_link_mail(user, kind, subject, intro, hours):
    token = make_token(user['id'], kind, hours)
    link = url_for('reset_password' if kind == 'reset' else 'verify_email', token=token, _external=True)
    sent = send_mail(user['email'], subject, f'{intro}\n\n{link}\n\nThis link is valid for {hours} hour(s).')
    if not sent and (DEV_MODE or os.environ.get('SHOW_EMAIL_LINKS') == '1'):
        flash(Markup('Email is not configured (dev mode). <a class="underline font-semibold" href="{}">Open the link</a>').format(link), 'info')
    return sent


def make_token(user_id, kind, hours):
    raw = secrets.token_urlsafe(32)
    get_db().execute('INSERT INTO auth_tokens (user_id, kind, token_hash, expires_at) VALUES (?,?,?,?)',
                     (user_id, kind, sha(raw), fmt(now_utc() + timedelta(hours=hours))))
    get_db().commit()
    return raw


def find_token(raw, kind):
    return get_db().execute(
        'SELECT * FROM auth_tokens WHERE token_hash = ? AND kind = ? AND used = 0 AND expires_at > ?',
        (sha(raw), kind, utcnow_str())).fetchone()


# --------------------------------------------------------------------------
# Request lifecycle: current user, CSRF, automatic expiry
# --------------------------------------------------------------------------
def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(24)
    return session['csrf_token']


app.jinja_env.globals.update(csrf_token=csrf_token, ngo_can_request=ngo_can_request,
                             CATEGORIES=CATEGORIES, UNITS=UNITS, REPORT_TYPES=REPORT_TYPES,
                             MAX_OTP_ATTEMPTS=MAX_OTP_ATTEMPTS)


def run_maintenance():
    """Lazy expiry: mark overdue donations EXPIRED and raise 'expiring soon' notifications.
    Runs on every request; does nothing (and takes no write lock) when there is nothing to do."""
    db, now = get_db(), utcnow_str()
    link = '/my/donations'
    changed = False
    for d in db.execute("SELECT id, donor_id, food_name FROM donations WHERE status IN "
                        "('AVAILABLE','REQUESTED','ACCEPTED') AND expiry_time <= ?", (now,)).fetchall():
        ngos = db.execute("SELECT ngo_id FROM requests WHERE donation_id = ? AND status IN ('PENDING','ACCEPTED')",
                          (d['id'],)).fetchall()
        db.execute("UPDATE donations SET status = 'EXPIRED' WHERE id = ?", (d['id'],))
        db.execute("UPDATE requests SET status = 'CANCELLED', pickup_otp = NULL WHERE donation_id = ? AND status = 'PENDING'", (d['id'],))
        db.execute("UPDATE requests SET pickup_otp = NULL WHERE donation_id = ? AND status = 'ACCEPTED'", (d['id'],))
        notify(d['donor_id'], f'Your donation "{d["food_name"]}" has expired and is no longer listed.', link)
        for n in ngos:
            notify(n['ngo_id'], f'The donation "{d["food_name"]}" you requested has expired.', '/my/requests')
        changed = True
    soon_cutoff = fmt(now_utc() + timedelta(minutes=EXPIRING_SOON_MIN))
    created_before = fmt(now_utc() - timedelta(minutes=5))
    for d in db.execute("SELECT id, donor_id, food_name, expiry_time FROM donations WHERE status IN "
                        "('AVAILABLE','REQUESTED','ACCEPTED') AND expiry_notified = 0 AND expiry_time > ? "
                        "AND expiry_time <= ? AND created_at <= ?", (now, soon_cutoff, created_before)).fetchall():
        left = max(1, int((datetime.strptime(d['expiry_time'], '%Y-%m-%d %H:%M:%S') - now_utc()).total_seconds() // 60))
        db.execute('UPDATE donations SET expiry_notified = 1 WHERE id = ?', (d['id'],))
        notify(d['donor_id'], f'"{d["food_name"]}" expires in about {left} min.', link)
        acc = db.execute("SELECT ngo_id FROM requests WHERE donation_id = ? AND status = 'ACCEPTED'", (d['id'],)).fetchone()
        if acc:
            notify(acc['ngo_id'], f'Pickup deadline for "{d["food_name"]}" is in about {left} min.', '/my/requests')
        changed = True
    if changed:
        db.commit()


@app.before_request
def before():
    if request.endpoint == 'static':
        return
    g.user = None
    uid = session.get('uid')
    if uid:
        u = get_db().execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
        if u and u['account_status'] == 'active':
            g.user = u
        else:
            session.clear()
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        sent, expected = request.form.get('csrf_token', ''), session.get('csrf_token', '')
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, 'Your session expired or the form was invalid. Go back, refresh the page and try again.')
    run_maintenance()


@app.after_request
def security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    return resp


@app.context_processor
def inject_user_context():
    unread = 0
    if g.get('user'):
        unread = get_db().execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0',
                                  (g.user['id'],)).fetchone()[0]
    return {'unread_count': unread}


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not g.user:
                flash('Please log in to continue.', 'error')
                nxt = request.full_path.rstrip('?') if request.method == 'GET' else None
                return redirect(url_for('login', next=nxt) if nxt else url_for('login'))
            if g.user['role'] not in roles:
                abort(403)
            return f(*a, **kw)
        return wrapper
    return deco


def login_required(f):
    return role_required('donor', 'ngo', 'admin')(f)


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def http_error(e):
    msgs = {403: "You don't have permission to open this page.", 404: "We couldn't find that page.",
            413: 'That upload is too large. Images must be 5 MB or smaller.'}
    code = e.code or 400
    text = msgs.get(code) or getattr(e, 'description', 'Bad request.')
    return render_template('templates/error.html', code=code, message=text), code


# --------------------------------------------------------------------------
# Public pages
# --------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for({'donor': 'my_donations', 'ngo': 'my_requests', 'admin': 'admin_dashboard'}[g.user['role']]))


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------
def validate_profile(form, role):
    """Shared by signup and profile. -> (data, errors)"""
    e, d = {}, {}
    d['name'] = form.get('name', '').strip()
    if not 2 <= len(d['name']) <= 100:
        e['name'] = 'Enter a name (2-100 characters).' if role == 'donor' else 'Enter the organisation name (2-100 characters).'
    d['phone'] = form.get('phone', '').strip()
    if not PHONE_RE.match(d['phone']):
        e['phone'] = 'Enter a valid phone number (9-15 digits).'
    d['address'] = form.get('address', '').strip()
    if (role == 'ngo' or d['address']) and not 5 <= len(d['address']) <= 250:
        e['address'] = 'Enter an address (5-250 characters).'
    d['lat'], d['lng'], err = parse_coords(form.get('lat'), form.get('lng'))
    if err:
        e['location'] = err
    return d, e


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if g.user:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        f = request.form
        role = f.get('role', '')
        d, e = validate_profile(f, role if role in ('donor', 'ngo') else 'donor')
        if role not in ('donor', 'ngo'):
            e['role'] = 'Choose whether you are a donor or an NGO.'
        d['email'] = f.get('email', '').strip().lower()
        if not EMAIL_RE.match(d['email']) or len(d['email']) > 150:
            e['email'] = 'Enter a valid email address.'
        d['reg_number'] = f.get('reg_number', '').strip()
        d['ngo_darpan_id'] = f.get('ngo_darpan_id', '').strip()
        if role == 'ngo' and not 3 <= len(d['reg_number']) <= 60:
            e['reg_number'] = 'Enter your NGO registration number.'
        if role == 'ngo' and not 3 <= len(d['ngo_darpan_id']) <= 60:
            e['ngo_darpan_id'] = 'Enter the NGO Darpan / government registration ID.'
        verification_file = request.files.get('verification_doc')
        if role == 'ngo' and (not verification_file or not verification_file.filename):
            e['verification_doc'] = 'Upload the NGO registration certificate.'
        elif role == 'ngo' and verification_file and verification_file.filename:
            ext = os.path.splitext(os.path.basename(verification_file.filename))[1].lower()
            if ext not in VERIFICATION_EXTENSIONS:
                e['verification_doc'] = 'Certificate must be PDF, JPG, JPEG, PNG or WebP.'
            else:
                verification_file.stream.seek(0, os.SEEK_END)
                if verification_file.stream.tell() > MAX_VERIFICATION_BYTES:
                    e['verification_doc'] = 'Verification document must be 5 MB or smaller.'
                verification_file.stream.seek(0)
        pw = f.get('password', '')
        if not valid_password(pw):
            e['password'] = 'Password needs at least 8 characters with a letter and a number.'
        elif pw != f.get('confirm', ''):
            e['confirm'] = 'Passwords do not match.'
        db = get_db()
        if 'email' not in e and db.execute('SELECT 1 FROM users WHERE email = ?', (d['email'],)).fetchone():
            e['email'] = 'An account with this email already exists. Try logging in.'
        if e:
            return render_template('templates/signup.html', form=f, errors=e), 400
        cur = db.execute(
            'INSERT INTO users (role, name, email, password_hash, phone, address, lat, lng, reg_number, ngo_darpan_id, ngo_status, created_at) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
            (role, d['name'], d['email'], generate_password_hash(pw), d['phone'], d['address'] or None,
             d['lat'], d['lng'], d['reg_number'] if role == 'ngo' else None,
             d['ngo_darpan_id'] if role == 'ngo' else None,
             'PENDING' if role == 'ngo' else None, utcnow_str()))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE id = ?', (cur.lastrowid,)).fetchone()
        if role == 'ngo':
            stored, original, save_error = save_verification_document(request.files.get('verification_doc'), user['id'])
            if save_error:
                db.execute('DELETE FROM users WHERE id = ?', (user['id'],))
                db.commit()
                return render_template('templates/signup.html', form=f, errors={'verification_doc': save_error}), 400
            db.execute('UPDATE users SET verification_doc = ?, verification_doc_name = ? WHERE id = ?',
                       (stored, original, user['id']))
            db.commit()
            user = db.execute('SELECT * FROM users WHERE id = ?', (cur.lastrowid,)).fetchone()
            for a in db.execute("SELECT id FROM users WHERE role = 'admin' AND account_status = 'active'").fetchall():
                notify(a['id'], f'New NGO registration: {d["name"]}', '/admin/ngos')
            db.commit()
        session.clear()
        session['uid'] = user['id']
        flash('Welcome to FoodLink! Your account has been created.', 'success')
        if role == 'ngo':
            flash('Your NGO registration was submitted. Admin review requires your registration ID and uploaded registration proof.', 'info')
        send_link_mail(user, 'verify', 'Verify your FoodLink email', 'Welcome to FoodLink! Confirm your email address:', 48)
        return redirect(url_for('dashboard'))
    return render_template('templates/signup.html', form={'role': request.args.get('role', 'donor')}, errors={})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        key = (email, request.remote_addr)
        if login_locked(key):
            flash('Too many failed attempts. Please wait a few minutes and try again.', 'error')
            return render_template('templates/login.html', email=email), 429
        u = get_db().execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if not u or not check_password_hash(u['password_hash'], request.form.get('password', '')):
            login_failed(key)
            flash('Incorrect email or password.', 'error')
            return render_template('templates/login.html', email=email), 401
        if u['account_status'] != 'active':
            flash('This account has been %s. Contact the FoodLink admin.' % u['account_status'], 'error')
            return render_template('templates/login.html', email=email), 403
        LOGIN_FAILS.pop(key, None)
        session.clear()
        session['uid'] = u['id']
        flash('You are logged in.', 'success')
        return redirect(safe_next(request.args.get('next')) or url_for('dashboard'))
    return render_template('templates/login.html', email='')


LOGIN_FAILS = {}


def login_locked(key):
    c = LOGIN_FAILS.get(key)
    return bool(c and c[0] >= MAX_LOGIN_FAILS and c[1] > time.time())


def login_failed(key):
    c = LOGIN_FAILS.get(key)
    if not c or c[1] <= time.time():
        c = [0, 0]
    c[0] += 1
    c[1] = time.time() + LOCKOUT_SECONDS
    LOGIN_FAILS[key] = c


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        u = get_db().execute("SELECT * FROM users WHERE email = ? AND account_status = 'active'", (email,)).fetchone()
        if u:
            send_link_mail(u, 'reset', 'Reset your FoodLink password', 'Use this link to choose a new password:', 1)
        flash('If an account exists for that email, a reset link has been sent.', 'success')
        return redirect(url_for('forgot_password'))
    return render_template('templates/forgot.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    row = find_token(token, 'reset')
    if not row:
        flash('This reset link is invalid or has expired. Request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        pw = request.form.get('password', '')
        if not valid_password(pw):
            return render_template('templates/reset.html', error='Password needs at least 8 characters with a letter and a number.'), 400
        if pw != request.form.get('confirm', ''):
            return render_template('templates/reset.html', error='Passwords do not match.'), 400
        db = get_db()
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (generate_password_hash(pw), row['user_id']))
        db.execute("UPDATE auth_tokens SET used = 1 WHERE user_id = ? AND kind = 'reset'", (row['user_id'],))
        db.commit()
        flash('Password updated. You can log in now.', 'success')
        return redirect(url_for('login'))
    return render_template('templates/reset.html', error=None)


@app.route('/verify/<token>')
def verify_email(token):
    row = find_token(token, 'verify')
    if not row:
        flash('This verification link is invalid or has expired.', 'error')
        return redirect(url_for('dashboard') if g.user else url_for('login'))
    db = get_db()
    db.execute('UPDATE users SET email_verified = 1 WHERE id = ?', (row['user_id'],))
    db.execute("UPDATE auth_tokens SET used = 1 WHERE user_id = ? AND kind = 'verify'", (row['user_id'],))
    db.commit()
    flash('Email verified. Thank you!', 'success')
    return redirect(url_for('dashboard') if g.user else url_for('login'))


@app.route('/resend-verification', methods=['POST'])
@login_required
def resend_verification():
    if g.user['email_verified']:
        flash('Your email is already verified.', 'info')
    else:
        send_link_mail(g.user, 'verify', 'Verify your FoodLink email', 'Confirm your email address:', 48)
        flash('Verification email sent.', 'success')
    return back('dashboard')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        d, e = validate_profile(request.form, g.user['role'])
        if e:
            return render_template('templates/profile.html', form=request.form, errors=e), 400
        db = get_db()
        db.execute('UPDATE users SET name=?, phone=?, address=?, lat=?, lng=? WHERE id=?',
                   (d['name'], d['phone'], d['address'] or None, d['lat'], d['lng'], g.user['id']))
        db.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('profile'))
    return render_template('templates/profile.html', form=g.user, errors={})


# --------------------------------------------------------------------------
# Donations (donor)
# --------------------------------------------------------------------------
def read_image(file):
    """-> (bytes, ext, error). No file chosen is fine."""
    if not file or not file.filename:
        return None, None, None
    data = file.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        return None, None, 'Image must be 5 MB or smaller.'
    if data.startswith(b'\xff\xd8\xff'):
        return data, 'jpg', None
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return data, 'png', None
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return data, 'webp', None
    return None, None, 'Image must be a JPG, PNG or WebP photo.'


def validate_donation(form, files):
    e, d = {}, {}
    d['food_name'] = form.get('food_name', '').strip()
    if not 2 <= len(d['food_name']) <= 100:
        e['food_name'] = 'Enter the food name (2-100 characters).'
    d['category'] = form.get('category', '')
    if d['category'] not in CATEGORIES:
        e['category'] = 'Choose a category.'
    d['food_type'] = form.get('food_type', '')
    if d['food_type'] not in ('veg', 'non-veg'):
        e['food_type'] = 'Choose veg or non-veg.'
    d['quantity'] = to_float(form.get('quantity'))
    if d['quantity'] is None or not 0 < d['quantity'] <= 100000:
        e['quantity'] = 'Enter a quantity greater than 0.'
    d['unit'] = form.get('unit', '')
    if d['unit'] not in UNITS:
        e['unit'] = 'Choose a unit.'
    d['servings'] = to_int(form.get('servings'))
    if d['servings'] is None or not 1 <= d['servings'] <= 100000:
        e['servings'] = 'Enter the number of servings (at least 1).'
    tz = to_int(form.get('tz_offset'))
    tz = tz if tz is not None and -840 <= tz <= 840 else DEFAULT_TZ_OFFSET
    now = now_utc()
    prepared = parse_local_dt(form.get('prepared_at'), tz)
    expiry = parse_local_dt(form.get('expiry_time'), tz)
    if prepared is None:
        e['prepared_at'] = 'Enter when the food was prepared.'
    elif prepared > now + timedelta(minutes=5):
        e['prepared_at'] = 'Preparation time cannot be in the future.'
    if expiry is None:
        e['expiry_time'] = 'Enter the pickup deadline.'
    elif expiry <= now:
        e['expiry_time'] = 'The pickup deadline must be in the future.'
    elif prepared is not None and expiry <= prepared:
        e['expiry_time'] = 'The pickup deadline must be after the preparation time.'
    elif expiry > now + timedelta(hours=MAX_PICKUP_WINDOW_HOURS):
        e['expiry_time'] = f'The pickup deadline can be at most {MAX_PICKUP_WINDOW_HOURS} hours from now.'
    d['prepared_at'] = fmt(prepared) if prepared else None
    d['expiry_time'] = fmt(expiry) if expiry else None
    d['address'] = form.get('address', '').strip()
    if not 5 <= len(d['address']) <= 250:
        e['address'] = 'Enter the pickup address (5-250 characters).'
    d['contact_name'] = form.get('contact_name', '').strip()
    if len(d['contact_name']) > 100:
        e['contact_name'] = 'Contact name is too long.'
    d['contact_phone'] = form.get('contact_phone', '').strip()
    if not PHONE_RE.match(d['contact_phone']):
        e['contact_phone'] = 'Enter a valid contact phone number.'
    d['instructions'] = form.get('instructions', '').strip()
    if len(d['instructions']) > 500:
        e['instructions'] = 'Keep instructions under 500 characters.'
    d['lat'], d['lng'], err = parse_coords(form.get('lat'), form.get('lng'))
    if err:
        e['location'] = err
    img, ext, err = read_image(files.get('image'))
    if err:
        e['image'] = err
    return d, e, img, ext


@app.route('/post', methods=['GET', 'POST'])
@role_required('donor')
def post_food():
    if request.method == 'POST':
        if email_verification_blocked():
            return render_template('post.html', form=request.form, errors={}), 403
        d, e, img, ext = validate_donation(request.form, request.files)
        if e:
            return render_template('post.html', form=request.form, errors=e), 400
        path = None
        if img:
            name = f'{secrets.token_hex(16)}.{ext}'
            with open(os.path.join(UPLOAD_DIR, name), 'wb') as fh:
                fh.write(img)
            path = 'uploads/' + name
        db = get_db()
        cur = db.execute(
            'INSERT INTO donations (donor_id, food_name, category, food_type, quantity, unit, servings, image_path, '
            'prepared_at, expiry_time, address, lat, lng, contact_name, contact_phone, instructions, created_at) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (g.user['id'], d['food_name'], d['category'], d['food_type'], d['quantity'], d['unit'], d['servings'], path,
             d['prepared_at'], d['expiry_time'], d['address'], d['lat'], d['lng'], d['contact_name'] or g.user['name'],
             d['contact_phone'], d['instructions'] or None, utcnow_str()))
        notify_nearby_ngos(d['food_name'], d['lat'], d['lng'])
        db.commit()
        flash('Your donation is live. NGOs can now request it.', 'success')
        return redirect(url_for('my_donations'))
    form = {'contact_phone': g.user['phone'] or '', 'contact_name': g.user['name'],
            'address': g.user['address'] or '', 'lat': g.user['lat'] or '', 'lng': g.user['lng'] or ''}
    return render_template('post.html', form=form, errors={})


def notify_nearby_ngos(food_name, lat, lng):
    if lat is None:
        return
    for n in get_db().execute("SELECT id, lat, lng FROM users WHERE role = 'ngo' AND ngo_status = 'APPROVED' AND "
                              "is_verified = 1 AND account_status = 'active' AND lat IS NOT NULL").fetchall():
        km = haversine(lat, lng, n['lat'], n['lng'])
        if km <= NEARBY_KM:
            notify(n['id'], f'New donation nearby: {food_name} ({km:.1f} km away).', '/find')


def cancel_donation(did, reason):
    """Cancel an unpicked donation and tell the NGOs involved. -> bool"""
    db = get_db()
    d = db.execute('SELECT * FROM donations WHERE id = ?', (did,)).fetchone()
    cur = db.execute("UPDATE donations SET status = 'CANCELLED' WHERE id = ? AND status IN ('AVAILABLE','REQUESTED','ACCEPTED')", (did,))
    if not cur.rowcount:
        return False
    ngos = db.execute("SELECT ngo_id FROM requests WHERE donation_id = ? AND status IN ('PENDING','ACCEPTED')", (did,)).fetchall()
    db.execute("UPDATE requests SET status = 'CANCELLED', pickup_otp = NULL WHERE donation_id = ? AND status IN ('PENDING','ACCEPTED')", (did,))
    for n in ngos:
        notify(n['ngo_id'], f'The donation "{d["food_name"]}" was cancelled ({reason}).', '/my/requests')
    return True


def release_ngo_requests(ngo_id):
    """An NGO lost its verified status / was suspended: free up what it was holding."""
    db = get_db()
    rows = db.execute(
        "SELECT r.id, r.status, r.donation_id, d.donor_id, d.food_name, d.status AS dstatus FROM requests r "
        "JOIN donations d ON d.id = r.donation_id WHERE r.ngo_id = ? AND "
        "((r.status = 'PENDING' AND d.status = 'REQUESTED') OR (r.status = 'ACCEPTED' AND d.status = 'ACCEPTED'))",
        (ngo_id,)).fetchall()
    for r in rows:
        db.execute("UPDATE requests SET status = 'CANCELLED', pickup_otp = NULL WHERE id = ?", (r['id'],))
        if r['status'] == 'ACCEPTED':
            db.execute("UPDATE donations SET status = 'AVAILABLE' WHERE id = ? AND status = 'ACCEPTED'", (r['donation_id'],))
            notify(r['donor_id'], f'The NGO for "{r["food_name"]}" is no longer verified. The donation is available again.', '/my/donations')
        else:
            reopen_if_no_pending(r['donation_id'])


def reopen_if_no_pending(did):
    db = get_db()
    if not db.execute("SELECT 1 FROM requests WHERE donation_id = ? AND status = 'PENDING'", (did,)).fetchone():
        db.execute("UPDATE donations SET status = 'AVAILABLE' WHERE id = ? AND status = 'REQUESTED'", (did,))


@app.route('/my/donations')
@role_required('donor')
def my_donations():
    db = get_db()
    rows = [dict(r) for r in db.execute('SELECT * FROM donations WHERE donor_id = ? ORDER BY created_at DESC, id DESC', (g.user['id'],))]
    reqs = {}
    for r in db.execute('SELECT r.*, u.name AS ngo_name, u.phone AS ngo_phone, u.is_verified AS ngo_verified FROM requests r '
                        'JOIN users u ON u.id = r.ngo_id WHERE r.donation_id IN (SELECT id FROM donations WHERE donor_id = ?) '
                        'ORDER BY r.created_at', (g.user['id'],)):
        reqs.setdefault(r['donation_id'], []).append(r)
    return render_template('templates/my_donations.html',
                           active=[d for d in rows if d['status'] in ACTIVE_STATUSES],
                           history=[d for d in rows if d['status'] not in ACTIVE_STATUSES], reqs=reqs)


@app.route('/donations/<int:did>/cancel', methods=['POST'])
@role_required('donor')
def cancel_my_donation(did):
    d = get_db().execute('SELECT * FROM donations WHERE id = ? AND donor_id = ?', (did, g.user['id'])).fetchone()
    if not d:
        abort(404)
    if cancel_donation(did, 'cancelled by the donor'):
        get_db().commit()
        flash('Donation cancelled.', 'success')
    else:
        flash('This donation can no longer be cancelled.', 'error')
    return back('my_donations')


# --------------------------------------------------------------------------
# Find food
# --------------------------------------------------------------------------
@app.route('/find')
def find_food():
    db = get_db()
    q = request.args.get('q', '').strip()[:100]
    category = request.args.get('category', '')
    ftype = request.args.get('type', '')
    sort = request.args.get('sort', 'expiring')
    radius = to_float(request.args.get('radius'))
    lat, lng, _ = parse_coords(request.args.get('lat'), request.args.get('lng'))
    where = ["d.status IN ('AVAILABLE','REQUESTED')", 'd.expiry_time > ?', "u.account_status = 'active'"]
    params = [utcnow_str()]
    if q:
        like = '%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        where.append("(d.food_name LIKE ? ESCAPE '\\' OR d.address LIKE ? ESCAPE '\\' OR d.category LIKE ? ESCAPE '\\')")
        params += [like] * 3
    if category in CATEGORIES:
        where.append('d.category = ?')
        params.append(category)
    if ftype in ('veg', 'non-veg'):
        where.append('d.food_type = ?')
        params.append(ftype)
    rows = [dict(r) for r in db.execute(
        'SELECT d.*, u.name AS donor_name FROM donations d JOIN users u ON u.id = d.donor_id WHERE '
        + ' AND '.join(where) + ' LIMIT 500', params)]
    for r in rows:
        r['distance'] = haversine(lat, lng, r['lat'], r['lng']) if lat is not None and r['lat'] is not None else None
    hidden_no_location = 0
    if lat is not None and radius:
        kept = [r for r in rows if r['distance'] is not None and r['distance'] <= radius]
        hidden_no_location = sum(1 for r in rows if r['distance'] is None)
        rows = kept
    rows.sort(key=lambda r: r['expiry_time'])
    if sort == 'nearest' and lat is not None:
        rows.sort(key=lambda r: (r['distance'] is None, r['distance'] or 0))
    elif sort == 'newest':
        rows.sort(key=lambda r: (r['created_at'], r['id']), reverse=True)
    mine = {}
    if g.user and g.user['role'] == 'ngo':
        mine = {r['donation_id']: r['status'] for r in
                db.execute('SELECT donation_id, status FROM requests WHERE ngo_id = ?', (g.user['id'],))}
    return render_template('find.html', posts=rows, mine=mine, q=q, category=category, ftype=ftype,
                           sort=sort, radius=request.args.get('radius', ''), lat=lat, lng=lng,
                           hidden_no_location=hidden_no_location,
                           sort_needs_location=(sort == 'nearest' and lat is None),
                           filtered=bool(q or category or ftype or radius))


# --------------------------------------------------------------------------
# Request workflow: AVAILABLE -> REQUESTED -> ACCEPTED -> PICKED_UP -> COMPLETED
# --------------------------------------------------------------------------
def new_otp():
    db = get_db()
    for _ in range(20):
        otp = f'{secrets.randbelow(1000000):06d}'
        if not db.execute("SELECT 1 FROM requests WHERE pickup_otp = ? AND status = 'ACCEPTED'", (otp,)).fetchone():
            return otp
    raise RuntimeError('Could not generate a unique OTP')


@app.route('/donations/<int:did>/request', methods=['POST'])
@role_required('ngo')
def request_food(did):
    if not ngo_can_request(g.user):
        flash(ngo_block_reason(g.user), 'error')
        return back('find_food')
    if email_verification_blocked():
        return back('find_food')
    db = get_db()
    d = db.execute('SELECT * FROM donations WHERE id = ?', (did,)).fetchone()
    if not d or d['status'] not in ('AVAILABLE', 'REQUESTED') or d['expiry_time'] <= utcnow_str():
        flash('Sorry, this donation is no longer available.', 'error')
        return back('find_food')
    ex = db.execute('SELECT * FROM requests WHERE donation_id = ? AND ngo_id = ?', (did, g.user['id'])).fetchone()
    if ex and ex['status'] in ('PENDING', 'ACCEPTED'):
        flash('You have already requested this donation.', 'info')
        return back('find_food')
    if ex and ex['status'] == 'REJECTED':
        flash('The donor declined your earlier request for this donation.', 'error')
        return back('find_food')
    if ex:
        db.execute("UPDATE requests SET status = 'PENDING', created_at = ?, responded_at = NULL WHERE id = ?", (utcnow_str(), ex['id']))
    else:
        db.execute('INSERT INTO requests (donation_id, ngo_id, created_at) VALUES (?,?,?)', (did, g.user['id'], utcnow_str()))
    db.execute("UPDATE donations SET status = 'REQUESTED' WHERE id = ? AND status IN ('AVAILABLE','REQUESTED')", (did,))
    notify(d['donor_id'], f'New food request from {g.user["name"]} for "{d["food_name"]}".', '/my/donations')
    db.commit()
    flash('Request sent. You will be notified when the donor responds.', 'success')
    return back('find_food')


def load_request(rid):
    return get_db().execute(
        'SELECT r.*, d.donor_id, d.food_name, d.status AS dstatus, d.expiry_time FROM requests r '
        'JOIN donations d ON d.id = r.donation_id WHERE r.id = ?', (rid,)).fetchone()


@app.route('/requests/<int:rid>/accept', methods=['POST'])
@role_required('donor')
def accept_request(rid):
    db = get_db()
    r = load_request(rid)
    if not r or r['donor_id'] != g.user['id']:
        abort(404)
    if r['status'] != 'PENDING' or r['dstatus'] != 'REQUESTED' or r['expiry_time'] <= utcnow_str():
        flash('This request can no longer be accepted.', 'error')
        return back('my_donations')
    cur = db.execute("UPDATE donations SET status = 'ACCEPTED' WHERE id = ? AND status = 'REQUESTED'", (r['donation_id'],))
    if not cur.rowcount:
        flash('This request can no longer be accepted.', 'error')
        return back('my_donations')
    db.execute("UPDATE requests SET status = 'ACCEPTED', pickup_otp = ?, otp_attempts = 0, responded_at = ? WHERE id = ?",
               (new_otp(), utcnow_str(), rid))
    for o in db.execute("SELECT id, ngo_id FROM requests WHERE donation_id = ? AND status = 'PENDING' AND id != ?", (r['donation_id'], rid)).fetchall():
        db.execute("UPDATE requests SET status = 'CANCELLED', responded_at = ? WHERE id = ?", (utcnow_str(), o['id']))
        notify(o['ngo_id'], f'"{r["food_name"]}" was given to another NGO.', '/my/requests')
    notify(r['ngo_id'], f'Your request for "{r["food_name"]}" was accepted. Ask the donor for the pickup OTP when you collect it.', '/my/requests')
    db.commit()
    flash('Request accepted. Share the pickup OTP with the NGO only when they arrive.', 'success')
    return back('my_donations')


@app.route('/requests/<int:rid>/reject', methods=['POST'])
@role_required('donor')
def reject_request(rid):
    db = get_db()
    r = load_request(rid)
    if not r or r['donor_id'] != g.user['id']:
        abort(404)
    if r['status'] != 'PENDING':
        flash('This request has already been handled.', 'error')
        return back('my_donations')
    db.execute("UPDATE requests SET status = 'REJECTED', responded_at = ? WHERE id = ?", (utcnow_str(), rid))
    reopen_if_no_pending(r['donation_id'])
    notify(r['ngo_id'], f'Your request for "{r["food_name"]}" was declined.', '/my/requests')
    db.commit()
    flash('Request rejected.', 'success')
    return back('my_donations')


@app.route('/requests/<int:rid>/new-otp', methods=['POST'])
@role_required('donor')
def regenerate_otp(rid):
    r = load_request(rid)
    if not r or r['donor_id'] != g.user['id']:
        abort(404)
    if r['status'] != 'ACCEPTED' or r['dstatus'] != 'ACCEPTED':
        flash('A new OTP can only be created while pickup is pending.', 'error')
    else:
        get_db().execute('UPDATE requests SET pickup_otp = ?, otp_attempts = 0 WHERE id = ?', (new_otp(), rid))
        get_db().commit()
        flash('New pickup OTP generated.', 'success')
    return back('my_donations')


@app.route('/requests/<int:rid>/pickup', methods=['POST'])
@role_required('ngo')
def verify_pickup(rid):
    db = get_db()
    r = load_request(rid)
    if not r or r['ngo_id'] != g.user['id']:
        abort(404)
    if r['status'] != 'ACCEPTED' or r['dstatus'] != 'ACCEPTED':
        flash('This donation is not waiting for pickup.', 'error')
        return back('my_requests')
    if r['otp_attempts'] >= MAX_OTP_ATTEMPTS:
        flash('Too many wrong OTP attempts. Ask the donor to generate a new OTP.', 'error')
        return back('my_requests')
    otp = request.form.get('otp', '').strip()
    if not re.fullmatch(r'\d{6}', otp):
        flash('Enter the 6-digit OTP.', 'error')
        return back('my_requests')
    if r['pickup_otp'] and hmac.compare_digest(otp, r['pickup_otp']):
        cur = db.execute("UPDATE donations SET status = 'PICKED_UP', picked_up_at = ? WHERE id = ? AND status = 'ACCEPTED'",
                         (utcnow_str(), r['donation_id']))
        if cur.rowcount:
            db.execute('UPDATE requests SET pickup_otp = NULL WHERE id = ?', (rid,))
            notify(r['donor_id'], f'Pickup completed: {g.user["name"]} collected "{r["food_name"]}".', '/my/donations')
            db.commit()
            flash('OTP verified. The food is marked as picked up.', 'success')
        return back('my_requests')
    db.execute('UPDATE requests SET otp_attempts = otp_attempts + 1 WHERE id = ?', (rid,))
    db.commit()
    left = MAX_OTP_ATTEMPTS - r['otp_attempts'] - 1
    flash(f'Wrong OTP. {left} attempt(s) left.' if left else 'Wrong OTP. No attempts left - ask the donor for a new OTP.', 'error')
    return back('my_requests')


@app.route('/requests/<int:rid>/complete', methods=['POST'])
@role_required('donor', 'ngo')
def complete_request(rid):
    db = get_db()
    r = load_request(rid)
    if not r or g.user['id'] not in (r['donor_id'], r['ngo_id']):
        abort(404)
    cur = db.execute("UPDATE donations SET status = 'COMPLETED', completed_at = ? WHERE id = ? AND status = 'PICKED_UP' "
                     "AND ? = 'ACCEPTED'", (utcnow_str(), r['donation_id'], r['status']))
    if not cur.rowcount:
        flash('Only picked-up donations can be marked completed.', 'error')
        return back('dashboard')
    other = r['ngo_id'] if g.user['id'] == r['donor_id'] else r['donor_id']
    notify(other, f'"{r["food_name"]}" was marked completed. Thank you for fighting food waste!',
           '/my/requests' if other == r['ngo_id'] else '/my/donations')
    db.commit()
    flash('Marked as completed.', 'success')
    return back('dashboard')


@app.route('/my/requests')
@role_required('ngo')
def my_requests():
    rows = []
    for r in get_db().execute(
            'SELECT r.*, d.food_name, d.category, d.food_type, d.quantity, d.unit, d.servings, d.address, d.image_path, '
            'd.expiry_time, d.contact_name, d.contact_phone, d.instructions, d.status AS dstatus, d.donor_id, '
            'u.name AS donor_name FROM requests r JOIN donations d ON d.id = r.donation_id '
            'JOIN users u ON u.id = d.donor_id WHERE r.ngo_id = ? ORDER BY r.created_at DESC, r.id DESC', (g.user['id'],)):
        r = dict(r)
        r['shown'] = display_status(r['status'], r['dstatus'])
        r['pickup_otp'] = None            # NGOs never see the OTP; the donor reads it out at handover
        rows.append(r)
    live = ('PENDING', 'ACCEPTED', 'PICKED_UP')
    return render_template('templates/my_requests.html', active=[r for r in rows if r['shown'] in live],
                           history=[r for r in rows if r['shown'] not in live], can_request=ngo_can_request(g.user))


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------
@app.route('/notifications')
@login_required
def notifications():
    db = get_db()
    rows = db.execute('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100', (g.user['id'],)).fetchall()
    resp = render_template('templates/notifications.html', items=rows)
    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0', (g.user['id'],))
    db.commit()
    return resp


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    db = get_db()
    src = request.form if request.method == 'POST' else request.args
    did, uid = to_int(src.get('donation_id')), to_int(src.get('user_id'))
    donation = db.execute('SELECT id, food_name, donor_id FROM donations WHERE id = ?', (did,)).fetchone() if did else None
    target = db.execute('SELECT id, name, role FROM users WHERE id = ? AND role != ?', (uid, 'admin')).fetchone() if uid else None
    if target and target['id'] == g.user['id']:
        target = None
    if request.method == 'POST':
        rtype, desc = request.form.get('report_type', ''), request.form.get('description', '').strip()
        reported = target['id'] if target else (donation['donor_id'] if donation and donation['donor_id'] != g.user['id'] else None)
        err = None
        if rtype not in REPORT_TYPES:
            err = 'Choose what you are reporting.'
        elif not 10 <= len(desc) <= 1000:
            err = 'Describe the problem in 10-1000 characters.'
        elif db.execute("SELECT 1 FROM reports WHERE reporter_id = ? AND report_type = ? AND status = 'OPEN' AND "
                        "COALESCE(donation_id, 0) = ? AND COALESCE(reported_user_id, 0) = ?",
                        (g.user['id'], rtype, donation['id'] if donation else 0, reported or 0)).fetchone():
            err = 'You already have an open report about this. Our team will review it.'
        if err:
            flash(err, 'error')
            return render_template('templates/report_form.html', donation=donation, target=target,
                                   form=request.form), 400
        db.execute('INSERT INTO reports (reporter_id, report_type, donation_id, reported_user_id, description, created_at) '
                   'VALUES (?,?,?,?,?,?)', (g.user['id'], rtype, donation['id'] if donation else None, reported, desc, utcnow_str()))
        for a in db.execute("SELECT id FROM users WHERE role = 'admin' AND account_status = 'active'").fetchall():
            notify(a['id'], f'New report: {REPORT_TYPES[rtype]}', '/admin/reports')
        db.commit()
        flash('Report submitted. Thank you - an admin will review it.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('templates/report_form.html', donation=donation, target=target,
                           form={'report_type': request.args.get('type', '')})


# --------------------------------------------------------------------------
# Impact
# --------------------------------------------------------------------------
def impact_stats(donor_id=None, ngo_id=None):
    db = get_db()
    join, where, p = '', "d.status != 'CANCELLED'", []
    if donor_id:
        where += ' AND d.donor_id = ?'
        p.append(donor_id)
    if ngo_id:
        join = "JOIN requests r ON r.donation_id = d.id AND r.status = 'ACCEPTED'"
        where += ' AND r.ngo_id = ?'
        p.append(ngo_id)
    row = db.execute(
        f"SELECT COUNT(*) AS total, COALESCE(SUM(d.status = 'COMPLETED'), 0) AS completed, "
        f"COALESCE(SUM(d.status = 'EXPIRED'), 0) AS expired, "
        f"COALESCE(SUM(CASE WHEN d.status = 'COMPLETED' THEN d.servings END), 0) AS meals "
        f"FROM donations d {join} WHERE {where}", p).fetchone()
    qty = db.execute(f"SELECT d.unit, SUM(d.quantity) AS q FROM donations d {join} WHERE {where} AND d.status = 'COMPLETED' "
                     f"GROUP BY d.unit ORDER BY q DESC", p).fetchall()
    return {'total': row['total'], 'completed': row['completed'], 'expired': row['expired'], 'meals': row['meals'],
            'quantity': ' + '.join(f'{r["q"]:g} {r["unit"]}' for r in qty) or '0'}


@app.route('/impact')
def impact():
    db = get_db()
    mine = None
    if g.user and g.user['role'] == 'donor':
        mine = impact_stats(donor_id=g.user['id'])
    elif g.user and g.user['role'] == 'ngo':
        mine = impact_stats(ngo_id=g.user['id'])
    donors = []
    if g.user and g.user['role'] == 'admin':
        donors = db.execute(
            "SELECT u.id, u.name, COUNT(d.id) AS total, COALESCE(SUM(d.status = 'COMPLETED'), 0) AS completed, "
            "COALESCE(SUM(CASE WHEN d.status = 'COMPLETED' THEN d.servings END), 0) AS meals "
            "FROM users u JOIN donations d ON d.donor_id = u.id AND d.status != 'CANCELLED' WHERE u.role = 'donor' "
            "GROUP BY u.id ORDER BY completed DESC, total DESC LIMIT 50").fetchall()
    return render_template('templates/impact.html', stats=impact_stats(), mine=mine, donors=donors)


# --------------------------------------------------------------------------
# Private NGO verification evidence
# --------------------------------------------------------------------------
@app.route('/admin/ngos/<int:uid>/verification-document')
@role_required('admin')
def admin_verification_document(uid):
    u = get_db().execute(
        "SELECT verification_doc, verification_doc_name FROM users WHERE id = ? AND role = 'ngo'",
        (uid,)).fetchone()
    if not u or not u['verification_doc']:
        abort(404)
    path = os.path.join(PRIVATE_UPLOAD_DIR, u['verification_doc'])
    if not os.path.isfile(path):
        abort(404)
    return send_from_directory(PRIVATE_UPLOAD_DIR, u['verification_doc'],
                               as_attachment=False, download_name=u['verification_doc_name'] or 'verification-document')


# --------------------------------------------------------------------------
# Admin
# --------------------------------------------------------------------------
def admin_stats():
    db = get_db()

    def one(sql, p=()):
        return db.execute(sql, p).fetchone()[0]
    live = "account_status != 'removed'"
    s = {
        'users': one(f'SELECT COUNT(*) FROM users WHERE {live}'),
        'donors': one(f"SELECT COUNT(*) FROM users WHERE role = 'donor' AND {live}"),
        'ngos': one(f"SELECT COUNT(*) FROM users WHERE role = 'ngo' AND {live}"),
        'verified_ngos': one("SELECT COUNT(*) FROM users WHERE role = 'ngo' AND ngo_status = 'APPROVED' AND is_verified = 1 AND account_status = 'active'"),
        'pending_ngos': one(f"SELECT COUNT(*) FROM users WHERE role = 'ngo' AND ngo_status = 'PENDING' AND {live}"),
        'active': one(f'SELECT COUNT(*) FROM donations WHERE status IN {ACTIVE_STATUSES}'),
        'open_reports': one("SELECT COUNT(*) FROM reports WHERE status = 'OPEN'"),
    }
    s.update(impact_stats())
    return s


@app.route('/admin')
@role_required('admin')
def admin_dashboard():
    recent = get_db().execute("SELECT r.*, u.name AS reporter FROM reports r JOIN users u ON u.id = r.reporter_id "
                              "WHERE r.status = 'OPEN' ORDER BY r.id DESC LIMIT 5").fetchall()
    return render_template('templates/admin_dashboard.html', s=admin_stats(), recent=recent)


@app.route('/admin/users')
@role_required('admin')
def admin_users():
    role, status, q = request.args.get('role', ''), request.args.get('status', ''), request.args.get('q', '').strip()[:100]
    where, p = ['1=1'], []
    if role in ('donor', 'ngo', 'admin'):
        where.append('role = ?')
        p.append(role)
    if status in ('active', 'suspended', 'removed'):
        where.append('account_status = ?')
        p.append(status)
    if q:
        where.append("(name LIKE ? OR email LIKE ?)")
        p += [f'%{q}%'] * 2
    rows = get_db().execute('SELECT * FROM users WHERE ' + ' AND '.join(where) + ' ORDER BY id DESC LIMIT 300', p).fetchall()
    return render_template('templates/admin_users.html', rows=rows, role=role, status=status, q=q)


@app.route('/admin/ngos')
@role_required('admin')
def admin_ngos():
    f = request.args.get('f', 'pending')
    cond = {'pending': "ngo_status = 'PENDING' AND account_status != 'removed'",
            'approved': "ngo_status = 'APPROVED' AND is_verified = 0 AND account_status != 'removed'",
            'verified': "ngo_status = 'APPROVED' AND is_verified = 1 AND account_status != 'removed'",
            'rejected': "ngo_status = 'REJECTED' AND account_status != 'removed'",
            'suspended': "account_status = 'suspended'", 'removed': "account_status = 'removed'",
            'all': '1=1'}.get(f)
    if cond is None:
        f, cond = 'pending', "ngo_status = 'PENDING' AND account_status != 'removed'"
    rows = get_db().execute(f"SELECT * FROM users WHERE role = 'ngo' AND {cond} ORDER BY created_at DESC LIMIT 300").fetchall()
    return render_template('templates/admin_ngos.html', rows=rows, f=f)


@app.route('/admin/users/<int:uid>/<action>', methods=['POST'])
@role_required('admin')
def admin_user_action(uid, action):
    db = get_db()
    u = db.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
    if not u or u['role'] == 'admin':
        abort(404)
    if action in ('approve', 'reject', 'verify', 'unverify') and u['role'] != 'ngo':
        abort(400, 'This action only applies to NGOs.')
    msg = None
    if action == 'approve':
        db.execute("UPDATE users SET ngo_status = 'APPROVED' WHERE id = ?", (uid,))
        notify(uid, 'Your NGO registration was approved. You will be able to request food once you are verified.', '/my/requests')
        msg = 'NGO approved.'
    elif action == 'reject':
        db.execute("UPDATE users SET ngo_status = 'REJECTED', is_verified = 0 WHERE id = ?", (uid,))
        release_ngo_requests(uid)
        notify(uid, 'Your NGO registration was rejected.', '/my/requests')
        msg = 'NGO rejected.'
    elif action == 'verify':
        if u['ngo_status'] != 'APPROVED':
            flash('Approve the NGO before marking it as verified.', 'error')
            return back('admin_ngos')
        if not u['ngo_darpan_id'] or not u['reg_number'] or not u['verification_doc'] or not u['email_verified']:
            flash('Verification blocked: verified email, registration ID and registration proof are required.', 'error')
            return back('admin_ngos')
        # Verification is an evidence-backed decision, not a bare checkbox.
        db.execute('UPDATE users SET is_verified = 1 WHERE id = ?', (uid,))
        notify(uid, 'Your NGO is now verified after evidence review. You can request food donations.', '/find')
        msg = 'NGO verified after evidence review.'
    elif action == 'unverify':
        db.execute('UPDATE users SET is_verified = 0 WHERE id = ?', (uid,))
        release_ngo_requests(uid)
        msg = 'Verification removed.'
    elif action in ('suspend', 'remove'):
        db.execute('UPDATE users SET account_status = ? WHERE id = ?', ('suspended' if action == 'suspend' else 'removed', uid))
        if u['role'] == 'ngo':
            release_ngo_requests(uid)
        else:
            for d in db.execute("SELECT id FROM donations WHERE donor_id = ? AND status IN ('AVAILABLE','REQUESTED','ACCEPTED')", (uid,)).fetchall():
                cancel_donation(d['id'], 'the donor account was ' + ('suspended' if action == 'suspend' else 'removed'))
        msg = 'Account suspended.' if action == 'suspend' else 'Account removed.'
    elif action == 'reactivate':
        db.execute("UPDATE users SET account_status = 'active' WHERE id = ?", (uid,))
        msg = 'Account reactivated.'
    else:
        abort(404)
    db.commit()
    flash(msg, 'success')
    return back('admin_users')


@app.route('/admin/donations')
@role_required('admin')
def admin_donations():
    status, q = request.args.get('status', ''), request.args.get('q', '').strip()[:100]
    where, p = ['1=1'], []
    if status in ('AVAILABLE', 'REQUESTED', 'ACCEPTED', 'PICKED_UP', 'COMPLETED', 'EXPIRED', 'CANCELLED'):
        where.append('d.status = ?')
        p.append(status)
    if q:
        where.append('(d.food_name LIKE ? OR u.name LIKE ?)')
        p += [f'%{q}%'] * 2
    rows = get_db().execute('SELECT d.*, u.name AS donor_name FROM donations d JOIN users u ON u.id = d.donor_id WHERE '
                            + ' AND '.join(where) + ' ORDER BY d.id DESC LIMIT 300', p).fetchall()
    return render_template('templates/admin_donations.html', rows=rows, status=status, q=q)


@app.route('/admin/donations/<int:did>/cancel', methods=['POST'])
@role_required('admin')
def admin_cancel_donation(did):
    d = get_db().execute('SELECT * FROM donations WHERE id = ?', (did,)).fetchone()
    if not d:
        abort(404)
    if cancel_donation(did, 'removed by an admin'):
        notify(d['donor_id'], f'Your donation "{d["food_name"]}" was removed by an admin.', '/my/donations')
        get_db().commit()
        flash('Donation removed from listings.', 'success')
    else:
        flash('Only donations that have not been picked up can be removed.', 'error')
    return back('admin_donations')


@app.route('/admin/reports')
@role_required('admin')
def admin_reports():
    f = request.args.get('f', 'open')
    cond = "r.status = 'RESOLVED'" if f == 'resolved' else ('1=1' if f == 'all' else "r.status = 'OPEN'")
    f = f if f in ('resolved', 'all') else 'open'
    rows = get_db().execute(
        'SELECT r.*, rep.name AS reporter, tu.name AS target_name, tu.role AS target_role, tu.id AS target_id, '
        'd.food_name FROM reports r JOIN users rep ON rep.id = r.reporter_id '
        'LEFT JOIN users tu ON tu.id = r.reported_user_id LEFT JOIN donations d ON d.id = r.donation_id '
        f'WHERE {cond} ORDER BY r.id DESC LIMIT 300').fetchall()
    return render_template('templates/admin_reports.html', rows=rows, f=f)


@app.route('/admin/reports/<int:rid>/resolve', methods=['POST'])
@role_required('admin')
def admin_resolve_report(rid):
    note = request.form.get('note', '').strip()
    if len(note) > 500:
        flash('Keep the resolution note under 500 characters.', 'error')
        return back('admin_reports')
    db = get_db()
    cur = db.execute("UPDATE reports SET status = 'RESOLVED', resolution_note = ?, resolved_by = ?, resolved_at = ? "
                     "WHERE id = ? AND status = 'OPEN'", (note or None, g.user['id'], utcnow_str(), rid))
    if not cur.rowcount:
        flash('That report was already resolved or does not exist.', 'error')
    else:
        db.commit()
        flash('Report resolved.', 'success')
    return back('admin_reports')


# --------------------------------------------------------------------------
with app.app_context():
    init_db()
    ensure_admin()

if __name__ == '__main__':
    app.run(debug=True)
