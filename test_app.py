"""Run with:  python -m unittest -v test_app   (uses a temporary database)."""
import glob
import io
import os
import re
import sqlite3
import tempfile
import unittest
from datetime import timedelta

_tmp = tempfile.mkdtemp()
os.environ.update(DATABASE_PATH=os.path.join(_tmp, 'test.db'), ADMIN_EMAIL='admin@test.local',
                  ADMIN_PASSWORD='Admin@12345', SECRET_KEY='test-secret')
import app as A  # noqa: E402

MAILS = []
A.send_mail = lambda to, subject, body: MAILS.append((to, subject, body)) or True
PNG = b'\x89PNG\r\n\x1a\n' + b'0' * 64
PDF = b'%PDF-1.4 fake verification certificate'
PW = 'Passw0rd!'


def db(sql, params=(), commit=False):
    con = sqlite3.connect(os.environ['DATABASE_PATH'])
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(sql, params).fetchall()
        if commit:
            con.commit()
        return rows
    finally:
        con.close()


def one(sql, params=()):
    r = db(sql, params)
    return r[0][0] if r else None


def dt(hours):
    """UTC 'now + hours' formatted for a datetime-local input (tz_offset=0)."""
    return (A.now_utc() + timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M')


class C:
    """Test client that automatically sends the CSRF token."""
    def __init__(self):
        self.c = A.app.test_client()

    def token(self):
        with self.c.session_transaction() as s:
            s.setdefault('csrf_token', 'tok')
            return s['csrf_token']

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, data=None, csrf=True, **kw):
        d = dict(data or {})
        if csrf:
            d['csrf_token'] = self.token()
        return self.c.post(url, data=d, **kw)


def make_user(role, email, **extra):
    c = C()
    data = dict(role=role, name=email.split('@')[0] + ' user', email=email, phone='9876543210', address='Sector 62 Noida',
                password=PW, confirm=PW)
    if role == 'ngo':
        data['reg_number'] = 'REG12345'
        data['ngo_darpan_id'] = 'DARPAN12345'
        data['verification_doc'] = (io.BytesIO(PDF), 'registration.pdf')
    data.update(extra)
    r = c.post('/signup', data, content_type='multipart/form-data')
    assert r.status_code == 302, r.data.decode()[:500]
    return c, one('SELECT id FROM users WHERE email = ?', (email,))


def admin_client():
    c = C()
    assert c.post('/login', {'email': 'admin@test.local', 'password': 'Admin@12345'}).status_code == 302
    return c


def verified_ngo(email, **extra):
    c, uid = make_user('ngo', email, **extra)
    link = re.search(r'/verify/[\\w\\-]+', MAILS[-1][2]).group(0)
    c.get(link)
    a = admin_client()
    a.post(f'/admin/users/{uid}/approve')
    a.post(f'/admin/users/{uid}/verify')
    return c, uid


def new_donation(c, **over):
    d = dict(food_name='Veg Biryani', category='Cooked meal', food_type='veg', quantity='10', unit='kg', servings='40',
             prepared_at=dt(-1), expiry_time=dt(4), address='Sector 62 Noida', contact_name='Ravi',
             contact_phone='9876543210', instructions='Use the back gate', tz_offset='0')
    d.update(over)
    r = c.post('/post', d, content_type='multipart/form-data')
    return r, one('SELECT MAX(id) FROM donations')


def dstatus(did):
    return one('SELECT status FROM donations WHERE id = ?', (did,))


def notes(uid):
    return [r['message'] for r in db('SELECT message FROM notifications WHERE user_id = ? ORDER BY id', (uid,))]


class Base(unittest.TestCase):
    def setUp(self):
        with A.app.app_context():
            d = A.get_db()
            for t in ('notifications', 'reports', 'requests', 'auth_tokens', 'donations'):
                d.execute(f'DELETE FROM {t}')
            d.execute("DELETE FROM users WHERE role != 'admin'")
            d.commit()
        A.LOGIN_FAILS.clear()
        MAILS.clear()

    def tearDown(self):
        for f in glob.glob(os.path.join(A.UPLOAD_DIR, '*.png')):
            os.remove(f)


class AuthTests(Base):
    def test_signup_login_logout(self):
        c = C()
        r = c.post('/signup', dict(role='donor', name='Ann', email='ann@x.com', phone='9876543210', password='short', confirm='short'))
        self.assertEqual(r.status_code, 400)
        self.assertIn(b'at least 8', r.data)
        r = c.post('/signup', dict(role='admin', name='Evil', email='evil@x.com', phone='9876543210', password=PW, confirm=PW))
        self.assertEqual(r.status_code, 400)                      # cannot self-register as admin
        self.assertIsNone(one("SELECT id FROM users WHERE email = 'evil@x.com'"))
        r = c.post('/signup', dict(role='ngo', name='Helpers', email='h@x.com', phone='9876543210', address='Noida', password=PW, confirm=PW))
        self.assertEqual(r.status_code, 400)                      # NGO needs registration number
        donor, uid = make_user('donor', 'ann@x.com')
        self.assertEqual(one('SELECT role FROM users WHERE id = ?', (uid,)), 'donor')
        self.assertNotEqual(one('SELECT password_hash FROM users WHERE id = ?', (uid,)), PW)   # hashed
        self.assertEqual(donor.get('/dashboard').headers['Location'], '/my/donations')
        again = C().post('/signup', dict(role='donor', name='Ann2', email='ANN@x.com', phone='9876543210', password=PW, confirm=PW))
        self.assertEqual(again.status_code, 400)                  # duplicate email (case-insensitive)
        self.assertEqual(donor.post('/logout').status_code, 302)
        self.assertEqual(donor.get('/my/donations').status_code, 302)
        bad = donor.post('/login', {'email': 'ann@x.com', 'password': 'wrong'})
        self.assertEqual(bad.status_code, 401)
        ok = donor.post('/login', {'email': 'ann@x.com', 'password': PW})
        self.assertEqual(ok.status_code, 302)
        self.assertEqual(donor.get('/my/donations').status_code, 200)

    def test_open_redirect_blocked(self):
        make_user('donor', 'a@x.com')
        c = C()
        r = c.post('/login?next=//evil.com', {'email': 'a@x.com', 'password': PW})
        self.assertEqual(r.headers['Location'], '/dashboard')      # //evil.com ignored

    def test_login_lockout(self):
        make_user('donor', 'a@x.com')
        c = C()
        for _ in range(5):
            c.post('/login', {'email': 'a@x.com', 'password': 'nope'})
        self.assertEqual(c.post('/login', {'email': 'a@x.com', 'password': PW}).status_code, 429)

    def test_csrf_required(self):
        c, _ = make_user('donor', 'a@x.com')
        self.assertEqual(c.post('/logout', csrf=False).status_code, 400)
        self.assertEqual(c.get('/my/donations').status_code, 200)            # still logged in

    def test_forgot_and_reset_password(self):
        c, _ = make_user('donor', 'a@x.com')
        MAILS.clear()
        c.post('/logout')
        c.post('/forgot', {'email': 'nobody@x.com'})
        self.assertEqual(MAILS, [])                                          # no mail, same generic response
        r = c.post('/forgot', {'email': 'a@x.com'}, follow_redirects=True)
        self.assertIn(b'reset link has been sent', r.data)
        link = re.search(r'/reset/[\w\-]+', MAILS[0][2]).group(0)
        self.assertEqual(c.get(link).status_code, 200)
        self.assertEqual(c.post(link, {'password': 'weak', 'confirm': 'weak'}).status_code, 400)
        self.assertEqual(c.post(link, {'password': 'NewPass123', 'confirm': 'NewPass123'}).status_code, 302)
        self.assertEqual(c.post('/login', {'email': 'a@x.com', 'password': PW}).status_code, 401)
        self.assertEqual(c.post('/login', {'email': 'a@x.com', 'password': 'NewPass123'}).status_code, 302)
        self.assertEqual(c.get(link).status_code, 302)                       # token is single-use
        self.assertEqual(c.get('/reset/not-a-real-token').status_code, 302)

    def test_expired_reset_token(self):
        c, uid = make_user('donor', 'a@x.com')
        c.post('/logout')
        c.post('/forgot', {'email': 'a@x.com'})
        link = re.search(r'/reset/[\w\-]+', MAILS[-1][2]).group(0)
        db("UPDATE auth_tokens SET expires_at = '2000-01-01 00:00:00'", commit=True)
        self.assertEqual(c.get(link).status_code, 302)

    def test_email_verification(self):
        c, uid = make_user('donor', 'a@x.com')
        self.assertEqual(one('SELECT email_verified FROM users WHERE id = ?', (uid,)), 0)
        link = re.search(r'/verify/[\w\-]+', MAILS[-1][2]).group(0)
        c.get(link)
        self.assertEqual(one('SELECT email_verified FROM users WHERE id = ?', (uid,)), 1)

    def test_email_verification_enforced_when_enabled(self):
        c, _ = make_user('donor', 'a@x.com')
        A.app.config['REQUIRE_EMAIL_VERIFICATION'] = True
        try:
            r, _ = new_donation(c)
            self.assertEqual(r.status_code, 403)
        finally:
            A.app.config['REQUIRE_EMAIL_VERIFICATION'] = False

    def test_profile_update(self):
        c, uid = make_user('ngo', 'n@x.com')
        r = c.post('/profile', dict(name='Helpers NGO', phone='9123456780', address='Noida', lat='28.5', lng='77.4'))
        self.assertEqual(r.status_code, 302)
        row = db('SELECT name, lat FROM users WHERE id = ?', (uid,))[0]
        self.assertEqual((row['name'], row['lat']), ('Helpers NGO', 28.5))
        self.assertEqual(c.post('/profile', dict(name='X', phone='1', address='Noida')).status_code, 400)


class AccessControlTests(Base):
    def test_guests_redirected_to_login(self):
        c = C()
        for url in ('/post', '/my/donations', '/my/requests', '/admin', '/admin/users', '/notifications', '/report', '/profile'):
            r = c.get(url)
            self.assertEqual(r.status_code, 302, url)
            self.assertIn('/login', r.headers['Location'])
        for url in ('/donations/1/request', '/requests/1/accept', '/admin/users/1/suspend', '/admin/reports/1/resolve'):
            self.assertEqual(c.post(url).status_code, 302, url)

    def test_role_boundaries(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, _ = make_user('ngo', 'n@x.com')
        for url in ('/admin', '/admin/ngos', '/admin/users', '/admin/donations', '/admin/reports', '/my/requests'):
            self.assertEqual(donor.get(url).status_code, 403, url)
        for url in ('/admin', '/post', '/my/donations'):
            self.assertEqual(ngo.get(url).status_code, 403, url)
        self.assertEqual(donor.post('/donations/1/request').status_code, 403)
        self.assertEqual(ngo.post('/requests/1/accept').status_code, 403)
        self.assertEqual(ngo.post('/admin/users/1/suspend').status_code, 403)
        self.assertEqual(donor.post('/admin/reports/1/resolve').status_code, 403)
        self.assertEqual(donor.post('/admin/donations/1/cancel').status_code, 403)

    def test_cannot_touch_other_peoples_records(self):
        donor, _ = make_user('donor', 'd@x.com')
        other, _ = make_user('donor', 'o@x.com')
        ngo, _ = verified_ngo('n@x.com')
        ngo2, _ = verified_ngo('n2@x.com')
        _, did = new_donation(donor)
        ngo.post(f'/donations/{did}/request')
        rid = one('SELECT id FROM requests')
        self.assertEqual(other.post(f'/requests/{rid}/accept').status_code, 404)
        self.assertEqual(other.post(f'/donations/{did}/cancel').status_code, 404)
        donor.post(f'/requests/{rid}/accept')
        otp = one('SELECT pickup_otp FROM requests')
        self.assertEqual(ngo2.post(f'/requests/{rid}/pickup', {'otp': otp}).status_code, 404)
        self.assertEqual(dstatus(did), 'ACCEPTED')
        self.assertEqual(other.post(f'/requests/{rid}/complete').status_code, 404)



class NGOVerificationTests(Base):
    def test_verify_requires_evidence_and_email(self):
        c, uid = make_user('ngo', 'evidence@x.com')
        a = admin_client()
        a.post(f'/admin/users/{uid}/approve')
        # Email alone is not enough.
        self.assertEqual(a.post(f'/admin/users/{uid}/verify').status_code, 302)
        self.assertEqual(one('SELECT is_verified FROM users WHERE id = ?', (uid,)), 0)
        # Once email is verified, uploaded official proof + registration ID allow review.
        link = re.search(r'/verify/[\\w\\-]+', MAILS[-1][2]).group(0)
        c.get(link)
        a.post(f'/admin/users/{uid}/verify')
        self.assertEqual(one('SELECT is_verified FROM users WHERE id = ?', (uid,)), 1)

    def test_verification_document_is_private(self):
        c, uid = make_user('ngo', 'private@x.com')
        row = db('SELECT verification_doc FROM users WHERE id = ?', (uid,))[0]
        self.assertTrue(row['verification_doc'])
        self.assertFalse(os.path.exists(os.path.join(A.app.static_folder, 'uploads', row['verification_doc'])))
        a = admin_client()
        r = a.get(f'/admin/ngos/{uid}/verification-document')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'%PDF', r.data)

class DonationTests(Base):
    def test_validation(self):
        c, _ = make_user('donor', 'd@x.com')
        cases = [dict(food_name=''), dict(category='Nope'), dict(food_type='maybe'), dict(quantity='0'), dict(quantity='abc'),
                 dict(servings='0'), dict(unit='tons'), dict(expiry_time=dt(-1)), dict(expiry_time=dt(-2)),
                 dict(expiry_time=dt(100)), dict(prepared_at=dt(5)), dict(address='x'), dict(contact_phone='12'),
                 dict(instructions='x' * 501), dict(lat='999', lng='1'), dict(expiry_time='garbage')]
        for over in cases:
            r, _ = new_donation(c, **over)
            self.assertEqual(r.status_code, 400, over)
        self.assertEqual(one('SELECT COUNT(*) FROM donations'), 0)

    def test_create_with_image_and_timezone(self):
        c, uid = make_user('donor', 'd@x.com')
        r, did = new_donation(c, image=(io.BytesIO(PNG), 'food.png'), lat='28.6', lng='77.2')
        self.assertEqual(r.status_code, 302)
        row = db('SELECT * FROM donations WHERE id = ?', (did,))[0]
        self.assertEqual((row['donor_id'], row['status'], row['servings'], row['food_type']), (uid, 'AVAILABLE', 40, 'veg'))
        self.assertTrue(os.path.exists(os.path.join(A.app.static_folder, row['image_path'])))
        with c.get('/static/' + row['image_path']) as img:
            self.assertEqual(img.status_code, 200)
        # browser in IST sends offset -330: local 18:00 must be stored as 12:30 UTC
        _, did2 = new_donation(c, tz_offset='-330', prepared_at=(A.now_utc() + timedelta(hours=5, minutes=30, seconds=-1) - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M'),
                               expiry_time='2099-01-01T18:00')
        self.assertEqual(one('SELECT COUNT(*) FROM donations'), 1)        # 2099 is beyond 72h window -> rejected
        _, did3 = new_donation(c, tz_offset='-330', prepared_at=(A.now_utc() + timedelta(hours=4, minutes=30)).strftime('%Y-%m-%dT%H:%M'),
                               expiry_time=(A.now_utc() + timedelta(hours=9, minutes=30)).strftime('%Y-%m-%dT%H:%M'))
        delta = A.datetime.strptime(one('SELECT expiry_time FROM donations WHERE id = ?', (did3,)), '%Y-%m-%d %H:%M:%S') - A.now_utc()
        self.assertTrue(timedelta(hours=3, minutes=55) < delta < timedelta(hours=4, minutes=5), delta)

    def test_bad_image_rejected(self):
        c, _ = make_user('donor', 'd@x.com')
        r, _ = new_donation(c, image=(io.BytesIO(b'<?php evil ?>'), 'shell.png'))
        self.assertEqual(r.status_code, 400)
        self.assertIn(b'JPG, PNG or WebP', r.data)
        r, _ = new_donation(c, image=(io.BytesIO(PNG + b'0' * (5 * 1024 * 1024)), 'big.png'))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(one('SELECT COUNT(*) FROM donations'), 0)
        self.assertEqual(glob.glob(os.path.join(A.UPLOAD_DIR, '*.png')), [])

    def test_cancel_by_donor_and_admin(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, ngo_id = verified_ngo('n@x.com')
        _, d1 = new_donation(donor)
        ngo.post(f'/donations/{d1}/request')
        donor.post(f'/donations/{d1}/cancel')
        self.assertEqual(dstatus(d1), 'CANCELLED')
        self.assertEqual(one('SELECT status FROM requests'), 'CANCELLED')
        self.assertTrue(any('cancelled' in m for m in notes(ngo_id)))
        self.assertNotIn(b'Veg Biryani', C().get('/find').data)
        _, d2 = new_donation(donor, food_name='Soup')
        admin_client().post(f'/admin/donations/{d2}/cancel')
        self.assertEqual(dstatus(d2), 'CANCELLED')


class ExpiryTests(Base):
    def test_expired_donations_are_hidden_and_marked(self):
        donor, donor_id = make_user('donor', 'd@x.com')
        ngo, ngo_id = verified_ngo('n@x.com')
        _, d1 = new_donation(donor, food_name='Old Rice')
        _, d2 = new_donation(donor, food_name='Fresh Roti')
        ngo.post(f'/donations/{d1}/request')                       # pending request on d1
        db("UPDATE donations SET expiry_time = '2000-01-01 00:00:00' WHERE id = ?", (d1,), commit=True)
        page = C().get('/find').data
        self.assertNotIn(b'Old Rice', page)
        self.assertIn(b'Fresh Roti', page)
        self.assertEqual(dstatus(d1), 'EXPIRED')
        self.assertEqual(dstatus(d2), 'AVAILABLE')
        self.assertEqual(one('SELECT status FROM requests'), 'CANCELLED')
        self.assertTrue(any('expired' in m for m in notes(donor_id)))
        self.assertTrue(any('expired' in m for m in notes(ngo_id)))
        # an expired donation can no longer be requested or accepted
        ngo2, _ = verified_ngo('n2@x.com')
        ngo2.post(f'/donations/{d1}/request')
        self.assertEqual(one('SELECT COUNT(*) FROM requests WHERE donation_id = ?', (d1,)), 1)
        # shows in donor history
        self.assertIn(b'EXPIRED', donor.get('/my/donations').data)

    def test_accepted_donation_expires_and_otp_dies(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, _ = verified_ngo('n@x.com')
        _, did = new_donation(donor)
        ngo.post(f'/donations/{did}/request')
        rid = one('SELECT id FROM requests')
        donor.post(f'/requests/{rid}/accept')
        otp = one('SELECT pickup_otp FROM requests')
        db("UPDATE donations SET expiry_time = '2000-01-01 00:00:00'", commit=True)
        ngo.post(f'/requests/{rid}/pickup', {'otp': otp})
        self.assertEqual(dstatus(did), 'EXPIRED')

    def test_expiring_soon_notification_once(self):
        donor, donor_id = make_user('donor', 'd@x.com')
        _, did = new_donation(donor)
        soon = A.fmt(A.now_utc() + timedelta(minutes=30))
        old = A.fmt(A.now_utc() - timedelta(minutes=10))
        db('UPDATE donations SET expiry_time = ?, created_at = ? WHERE id = ?', (soon, old, did), commit=True)
        donor.get('/my/donations')
        donor.get('/my/donations')
        self.assertEqual(sum('expires in' in m for m in notes(donor_id)), 1)


class FindTests(Base):
    def setUp(self):
        super().setUp()
        self.donor, _ = make_user('donor', 'd@x.com')
        new_donation(self.donor, food_name='Veg Biryani', expiry_time=dt(2), lat='28.6139', lng='77.2090')        # Delhi
        new_donation(self.donor, food_name='Chicken Curry', food_type='non-veg', expiry_time=dt(1), lat='28.5355', lng='77.3910')  # Noida ~20km
        new_donation(self.donor, food_name='Bread Loaves', category='Bakery & bread', expiry_time=dt(3))          # no location
        self.c = C()

    def names(self, qs):
        html = self.c.get('/find' + qs).data.decode()
        found = [(html.find(n), n) for n in ('Veg Biryani', 'Chicken Curry', 'Bread Loaves') if n in html]
        return [n for _, n in sorted(found)]

    def test_default_sort_is_expiring_soon(self):
        self.assertEqual(self.names(''), ['Chicken Curry', 'Veg Biryani', 'Bread Loaves'])

    def test_search_category_type(self):
        self.assertEqual(self.names('?q=biryani'), ['Veg Biryani'])
        self.assertEqual(self.names('?category=Bakery+%26+bread'), ['Bread Loaves'])
        self.assertEqual(self.names('?type=non-veg'), ['Chicken Curry'])
        self.assertEqual(self.names('?type=veg&category=Cooked+meal'), ['Veg Biryani'])
        self.assertEqual(self.names('?q=%25'), [])                      # wildcard characters are escaped
        self.assertIn(b'No food matches', self.c.get('/find?q=zzz').data)

    def test_nearest_and_radius(self):
        loc = '&lat=28.6139&lng=77.2090'
        self.assertEqual(self.names('?sort=nearest' + loc), ['Veg Biryani', 'Chicken Curry', 'Bread Loaves'])
        self.assertEqual(self.names('?radius=5' + loc), ['Veg Biryani'])
        self.assertEqual(self.names('?radius=50&sort=nearest' + loc), ['Veg Biryani', 'Chicken Curry'])
        self.assertIn(b'km away', self.c.get('/find?sort=nearest' + loc).data)
        self.assertIn(b'Use my location', self.c.get('/find?sort=nearest').data)   # no location -> hint, still works

    def test_newest_and_garbage_params(self):
        self.assertEqual(self.names('?sort=newest')[0], 'Bread Loaves')
        self.assertEqual(self.c.get('/find?lat=abc&lng=1&radius=zz&sort=%27%3B--').status_code, 200)


class WorkflowTests(Base):
    def test_full_workflow(self):
        donor, donor_id = make_user('donor', 'd@x.com')
        ngo, ngo_id = verified_ngo('n@x.com')
        _, did = new_donation(donor)
        self.assertEqual(dstatus(did), 'AVAILABLE')
        # AVAILABLE -> REQUESTED
        self.assertEqual(ngo.post(f'/donations/{did}/request').status_code, 302)
        self.assertEqual(dstatus(did), 'REQUESTED')
        self.assertTrue(any('New food request' in m for m in notes(donor_id)))
        self.assertIn(b'REQUESTED', C().get('/find').data)
        # duplicate request ignored
        ngo.post(f'/donations/{did}/request')
        self.assertEqual(one('SELECT COUNT(*) FROM requests'), 1)
        rid = one('SELECT id FROM requests')
        self.assertIsNone(one('SELECT pickup_otp FROM requests'))
        # REQUESTED -> ACCEPTED, unique 6-digit OTP generated
        donor.post(f'/requests/{rid}/accept')
        self.assertEqual(dstatus(did), 'ACCEPTED')
        otp = one('SELECT pickup_otp FROM requests')
        self.assertRegex(otp, r'^\d{6}$')
        self.assertTrue(any('accepted' in m for m in notes(ngo_id)))
        self.assertNotIn(b'Veg Biryani', C().get('/find').data)           # accepted food leaves public listing
        donor_page, ngo_page = donor.get('/my/donations').data, ngo.get('/my/requests').data
        self.assertIn(otp.encode(), donor_page)
        self.assertNotIn(b'Pickup OTP', ngo_page)                         # NGO must not see the OTP
        self.assertIn(b'9876543210', ngo_page)                            # contact revealed after accept
        # only an accepted request can be picked up: wrong OTP then right OTP
        wrong = '000000' if otp != '000000' else '111111'
        ngo.post(f'/requests/{rid}/pickup', {'otp': wrong})
        self.assertEqual(dstatus(did), 'ACCEPTED')
        self.assertEqual(one('SELECT otp_attempts FROM requests'), 1)
        ngo.post(f'/requests/{rid}/pickup', {'otp': 'abc'})              # malformed OTP does not burn an attempt
        self.assertEqual(one('SELECT otp_attempts FROM requests'), 1)
        ngo.post(f'/requests/{rid}/pickup', {'otp': otp})
        self.assertEqual(dstatus(did), 'PICKED_UP')                       # ACCEPTED -> PICKED_UP
        self.assertIsNone(one('SELECT pickup_otp FROM requests'))         # OTP is single-use
        self.assertTrue(any('Pickup completed' in m for m in notes(donor_id)))
        ngo.post(f'/requests/{rid}/pickup', {'otp': otp})                 # cannot be replayed
        self.assertEqual(dstatus(did), 'PICKED_UP')
        # PICKED_UP -> COMPLETED
        ngo.post(f'/requests/{rid}/complete')
        self.assertEqual(dstatus(did), 'COMPLETED')
        self.assertTrue(any('completed' in m for m in notes(donor_id)))
        # tracking / history
        self.assertIn(b'COMPLETED', donor.get('/my/donations').data)
        self.assertIn(b'COMPLETED', ngo.get('/my/requests').data)
        # impact numbers
        with A.app.app_context():
            s = A.impact_stats()
        self.assertEqual((s['total'], s['completed'], s['meals'], s['quantity']), (1, 1, 40, '10 kg'))

    def test_cannot_complete_before_pickup(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, _ = verified_ngo('n@x.com')
        _, did = new_donation(donor)
        ngo.post(f'/donations/{did}/request')
        rid = one('SELECT id FROM requests')
        ngo.post(f'/requests/{rid}/complete')
        donor.post(f'/requests/{rid}/complete')
        self.assertEqual(dstatus(did), 'REQUESTED')
        donor.post(f'/requests/{rid}/pickup', {'otp': '123456'})        # donors cannot verify pickup
        self.assertEqual(dstatus(did), 'REQUESTED')
        ngo.post(f'/requests/{rid}/pickup', {'otp': '123456'})          # pending (not accepted) cannot be picked up
        self.assertEqual(dstatus(did), 'REQUESTED')

    def test_reject_reopens_donation(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, ngo_id = verified_ngo('n@x.com')
        _, did = new_donation(donor)
        ngo.post(f'/donations/{did}/request')
        rid = one('SELECT id FROM requests')
        donor.post(f'/requests/{rid}/reject')
        self.assertEqual(dstatus(did), 'AVAILABLE')
        self.assertEqual(one('SELECT status FROM requests'), 'REJECTED')
        self.assertTrue(any('declined' in m for m in notes(ngo_id)))
        ngo.post(f'/donations/{did}/request')                            # rejected NGO cannot spam again
        self.assertEqual(dstatus(did), 'AVAILABLE')
        self.assertIn(b'REJECTED', ngo.get('/my/requests').data)
        donor.post(f'/requests/{rid}/accept')                            # rejected request cannot be accepted
        self.assertEqual(dstatus(did), 'AVAILABLE')

    def test_accepting_one_cancels_other_requests(self):
        donor, _ = make_user('donor', 'd@x.com')
        n1, _ = verified_ngo('n1@x.com')
        n2, n2_id = verified_ngo('n2@x.com')
        _, did = new_donation(donor)
        n1.post(f'/donations/{did}/request')
        n2.post(f'/donations/{did}/request')
        self.assertEqual(one('SELECT COUNT(*) FROM requests'), 2)
        r1 = one('SELECT id FROM requests WHERE ngo_id != ?', (n2_id,))
        donor.post(f'/requests/{r1}/accept')
        self.assertEqual(one("SELECT status FROM requests WHERE ngo_id = ?", (n2_id,)), 'CANCELLED')
        self.assertTrue(any('another NGO' in m for m in notes(n2_id)))
        # one rejection with another pending keeps the donation REQUESTED
        _, d2 = new_donation(donor, food_name='Dal')
        n1.post(f'/donations/{d2}/request')
        n2.post(f'/donations/{d2}/request')
        rid = one('SELECT id FROM requests WHERE donation_id = ? AND ngo_id = ?', (d2, n2_id))
        donor.post(f'/requests/{rid}/reject')
        self.assertEqual(dstatus(d2), 'REQUESTED')

    def test_otp_attempt_limit_and_regenerate(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, _ = verified_ngo('n@x.com')
        _, did = new_donation(donor)
        ngo.post(f'/donations/{did}/request')
        rid = one('SELECT id FROM requests')
        donor.post(f'/requests/{rid}/accept')
        otp = one('SELECT pickup_otp FROM requests')
        wrong = '000000' if otp != '000000' else '111111'
        for _ in range(A.MAX_OTP_ATTEMPTS):
            ngo.post(f'/requests/{rid}/pickup', {'otp': wrong})
        ngo.post(f'/requests/{rid}/pickup', {'otp': otp})                # locked even with the right OTP
        self.assertEqual(dstatus(did), 'ACCEPTED')
        donor.post(f'/requests/{rid}/new-otp')
        self.assertEqual(one('SELECT otp_attempts FROM requests'), 0)
        new = one('SELECT pickup_otp FROM requests')
        ngo.post(f'/requests/{rid}/pickup', {'otp': new})
        self.assertEqual(dstatus(did), 'PICKED_UP')


class NgoVerificationTests(Base):
    def test_only_verified_ngos_can_request(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, nid = make_user('ngo', 'n@x.com')
        admin = admin_client()
        _, did = new_donation(donor)
        self.assertIn(b'REG12345', admin.get('/admin/ngos').data)         # registration visible to admin
        ngo.post(f'/donations/{did}/request')                              # pending
        self.assertEqual(one('SELECT COUNT(*) FROM requests'), 0)
        admin.post(f'/admin/users/{nid}/verify')                           # cannot verify before approving
        self.assertEqual(one('SELECT is_verified FROM users WHERE id = ?', (nid,)), 0)
        admin.post(f'/admin/users/{nid}/approve')
        ngo.post(f'/donations/{did}/request')                              # approved but not verified
        self.assertEqual(one('SELECT COUNT(*) FROM requests'), 0)
        admin.post(f'/admin/users/{nid}/verify')
        ngo.post(f'/donations/{did}/request')
        self.assertEqual(one('SELECT COUNT(*) FROM requests'), 1)
        admin.post(f'/admin/users/{nid}/unverify')                         # revoked: pending request released
        self.assertEqual(dstatus(did), 'AVAILABLE')
        self.assertEqual(one('SELECT status FROM requests'), 'CANCELLED')
        admin.post(f'/admin/users/{nid}/reject')
        self.assertEqual(one('SELECT ngo_status FROM users WHERE id = ?', (nid,)), 'REJECTED')
        ngo.post(f'/donations/{did}/request')
        self.assertEqual(dstatus(did), 'AVAILABLE')

    def test_donor_cannot_be_verified_and_admin_untouchable(self):
        _, did_ = make_user('donor', 'd@x.com')
        admin = admin_client()
        self.assertEqual(admin.post(f'/admin/users/{did_}/verify').status_code, 400)
        admin_id = one("SELECT id FROM users WHERE role = 'admin'")
        self.assertEqual(admin.post(f'/admin/users/{admin_id}/suspend').status_code, 404)
        self.assertEqual(admin.post(f'/admin/users/{did_}/explode').status_code, 404)

    def test_suspend_and_remove(self):
        donor, donor_id = make_user('donor', 'd@x.com')
        ngo, nid = verified_ngo('n@x.com')
        admin = admin_client()
        _, did = new_donation(donor)
        ngo.post(f'/donations/{did}/request')
        rid = one('SELECT id FROM requests')
        donor.post(f'/requests/{rid}/accept')
        admin.post(f'/admin/users/{nid}/suspend')
        self.assertEqual(dstatus(did), 'AVAILABLE')                       # accepted donation released
        self.assertEqual(ngo.get('/my/requests').status_code, 302)        # live session is cut off
        self.assertEqual(C().post('/login', {'email': 'n@x.com', 'password': PW}).status_code, 403)
        admin.post(f'/admin/users/{nid}/reactivate')
        self.assertEqual(C().post('/login', {'email': 'n@x.com', 'password': PW}).status_code, 302)
        admin.post(f'/admin/users/{nid}/remove')
        self.assertEqual(C().post('/login', {'email': 'n@x.com', 'password': PW}).status_code, 403)
        admin.post(f'/admin/users/{donor_id}/suspend')                    # donor's open donations are pulled
        self.assertEqual(dstatus(did), 'CANCELLED')


class NotificationAndReportTests(Base):
    def test_nearby_notification(self):
        donor, _ = make_user('donor', 'd@x.com')
        near, near_id = verified_ngo('near@x.com', lat='28.6200', lng='77.2100')
        far, far_id = verified_ngo('far@x.com', lat='19.0760', lng='72.8777')       # Mumbai
        _, nowhere_id = verified_ngo('nowhere@x.com')
        new_donation(donor, lat='28.6139', lng='77.2090')
        self.assertTrue(any('New donation nearby' in m for m in notes(near_id)))
        nearby = lambda uid: [m for m in notes(uid) if 'nearby' in m]
        self.assertEqual(nearby(far_id), [])
        self.assertEqual(nearby(nowhere_id), [])

    def test_notification_page_and_unread_count(self):
        donor, donor_id = make_user('donor', 'd@x.com')
        ngo, _ = verified_ngo('n@x.com')
        _, did = new_donation(donor)
        ngo.post(f'/donations/{did}/request')
        page = donor.get('/dashboard', follow_redirects=True).data
        self.assertIn('bg-red-500 text-white text-xs rounded-full'.encode(), page)   # unread badge
        self.assertIn(b'New food request', donor.get('/notifications').data)
        self.assertEqual(one('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0', (donor_id,)), 0)

    def test_reports_flow(self):
        donor, donor_id = make_user('donor', 'd@x.com')
        ngo, ngo_id = verified_ngo('n@x.com')
        admin = admin_client()
        _, did = new_donation(donor)
        self.assertEqual(ngo.get(f'/report?donation_id={did}').status_code, 200)
        self.assertEqual(ngo.post('/report', dict(donation_id=did, report_type='bogus', description='x' * 20)).status_code, 400)
        self.assertEqual(ngo.post('/report', dict(donation_id=did, report_type='fake_donation', description='short')).status_code, 400)
        r = ngo.post('/report', dict(donation_id=did, report_type='unsafe_food', description='Food smelled spoiled at pickup'))
        self.assertEqual(r.status_code, 302)
        row = db('SELECT * FROM reports')[0]
        self.assertEqual((row['reporter_id'], row['reported_user_id'], row['donation_id'], row['status']), (ngo_id, donor_id, did, 'OPEN'))
        dup = ngo.post('/report', dict(donation_id=did, report_type='unsafe_food', description='Food smelled spoiled again'))
        self.assertEqual(dup.status_code, 400)
        # donor reports the NGO for a no-show
        r = donor.post('/report', dict(donation_id=did, user_id=ngo_id, report_type='no_show', description='They never turned up'))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(one("SELECT reported_user_id FROM reports WHERE report_type = 'no_show'"), ngo_id)
        self.assertTrue(any('New report' in m for m in notes(one("SELECT id FROM users WHERE role = 'admin'"))))
        page = admin.get('/admin/reports').data
        self.assertIn(b'Spoiled / unsafe food', page)
        self.assertIn(b'No-show', page)
        rid = row['id']
        self.assertEqual(ngo.post(f'/admin/reports/{rid}/resolve').status_code, 403)
        admin.post(f'/admin/reports/{rid}/resolve', {'note': 'Warned donor'})
        self.assertEqual(one('SELECT status FROM reports WHERE id = ?', (rid,)), 'RESOLVED')
        self.assertIn(b'Warned donor', admin.get('/admin/reports?f=resolved').data)
        self.assertNotIn(b'Spoiled / unsafe food', admin.get('/admin/reports').data)   # open list excludes resolved
        for kind in ('fake_donation', 'fake_ngo', 'incorrect_info'):
            self.assertIn(kind, A.REPORT_TYPES)


class DashboardTests(Base):
    def test_admin_dashboard_numbers(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, _ = verified_ngo('n@x.com')
        make_user('ngo', 'pending@x.com')
        _, d1 = new_donation(donor)                                       # will complete
        _, d2 = new_donation(donor, food_name='Soup', quantity='5', servings='10')   # will expire
        _, d3 = new_donation(donor, food_name='Roti')                     # stays active
        ngo.post(f'/donations/{d1}/request')
        rid = one('SELECT id FROM requests')
        donor.post(f'/requests/{rid}/accept')
        ngo.post(f'/requests/{rid}/pickup', {'otp': one('SELECT pickup_otp FROM requests')})
        donor.post(f'/requests/{rid}/complete')
        db("UPDATE donations SET expiry_time = '2000-01-01 00:00:00' WHERE id = ?", (d2,), commit=True)
        admin = admin_client()
        with A.app.app_context():
            A.get_db()
            s = A.admin_stats()
        self.assertEqual((s['users'], s['donors'], s['ngos'], s['verified_ngos'], s['pending_ngos']), (4, 1, 2, 1, 1))
        self.assertEqual((s['active'], s['completed'], s['expired'], s['meals'], s['quantity']), (1, 1, 1, 40, '10 kg'))
        self.assertEqual(admin.get('/admin').status_code, 200)
        self.assertEqual(one('SELECT status FROM donations WHERE id = ?', (d3,)), 'AVAILABLE')
        # impact dashboard: public totals, personal and per-donor views
        self.assertIn(b'Estimated meals served', C().get('/impact').data)
        self.assertIn(b'Your contribution', donor.get('/impact').data)
        self.assertIn(b'Donor contributions', admin.get('/impact').data)

    def test_every_page_renders_for_every_role(self):
        donor, _ = make_user('donor', 'd@x.com')
        ngo, _ = verified_ngo('n@x.com')
        admin = admin_client()
        _, d1 = new_donation(donor, image=(io.BytesIO(PNG), 'a.png'), lat='28.6', lng='77.2')
        _, d2 = new_donation(donor, food_name='Soup')
        _, d3 = new_donation(donor, food_name='Dal')
        ngo.post(f'/donations/{d1}/request')
        ngo.post(f'/donations/{d2}/request')
        r1, r2 = [one('SELECT id FROM requests WHERE donation_id = ?', (d,)) for d in (d1, d2)]
        donor.post(f'/requests/{r1}/accept')
        ngo.post('/report', dict(donation_id=d3, report_type='fake_donation', description='This looks completely fake'))
        pages = {
            C(): ['/', '/find', '/login', '/signup', '/forgot', '/impact', '/nope'],
            donor: ['/', '/post', '/my/donations', '/notifications', '/profile', '/impact', '/find', f'/report?donation_id={d1}'],
            ngo: ['/my/requests', '/notifications', '/profile', '/impact', '/find', f'/report?donation_id={d1}&user_id=1'],
            admin: ['/admin', '/admin/users', '/admin/ngos', '/admin/ngos?f=all', '/admin/ngos?f=verified', '/admin/donations',
                    '/admin/donations?status=ACCEPTED', '/admin/reports', '/admin/reports?f=all', '/impact', '/notifications'],
        }
        for client, urls in pages.items():
            for u in urls:
                want = 404 if u == '/nope' else 200
                self.assertEqual(client.get(u).status_code, want, u)


if __name__ == '__main__':
    unittest.main()
