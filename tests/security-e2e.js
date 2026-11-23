// End-to-end security test of ShostaBazar over real HTTP (65 checks).
//
// Run against a FRESH, EMPTY database (it creates users alice/bob_seller):
//   1. start the app:   npm start
//   2. run the tests:   npm test
// Reads DB_* and ADMIN_* from .env like the app does; TEST_BASE_URL defaults to APP_URL.
// The dev mailbox must be enabled (DEV_MAILBOX=true) because OTP codes are read from it.
const config = require('../src/config');
const mysql = require('mysql2/promise');
const totp = require('../src/utils/totp');
const BASE = process.env.TEST_BASE_URL || config.appUrl;
const ADMIN = config.admin;
let db;
let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log('  ✓', name); } else { fail++; console.log('  ✗', name, extra); }
}

class Client {
  constructor() { this.jar = {}; }
  cookie() { return Object.entries(this.jar).map(([k, v]) => `${k}=${v}`).join('; '); }
  async req(method, path, form) {
    const headers = { cookie: this.cookie(), 'user-agent': this.ua || 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130 TestClient' };
    let body;
    if (form) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(form).toString(); }
    const res = await fetch(BASE + path, { method, headers, body, redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';'); const i = kv.indexOf('=');
      this.jar[kv.slice(0, i)] = kv.slice(i + 1);
    }
    const text = await res.text();
    return { status: res.status, location: res.headers.get('location'), text, headers: res.headers };
  }
  get(p) { return this.req('GET', p); }
  async csrf(p) { const r = await this.get(p); const m = r.text.match(/name="_csrf" value="([a-f0-9]+)"/); return m && m[1]; }
  async post(pagePath, action, form) { const t = await this.csrf(pagePath); return this.req('POST', action, { _csrf: t, ...form }); }
}

async function lastMail(to, subjectLike) {
  const [rows] = await db.query('SELECT * FROM dev_mailbox WHERE recipient = ? AND subject LIKE ? ORDER BY id DESC LIMIT 1', [to, subjectLike]);
  return rows[0];
}
async function loginWithOtp(c, user, email, password) {
  const r = await c.post('/login', '/login', { username: user, password });
  if (r.location !== '/verify-2fa') return { step1: r };
  const mail = await lastMail(email, '%verification code%');
  const code = mail.subject.slice(0, 6);
  const r2 = await c.post('/verify-2fa', '/verify-2fa', { code });
  return { step1: r, step2: r2, code };
}

(async () => {
  db = await mysql.createConnection(config.db);
  const PW = 'S3cure!Bazar#2026';

  console.log('\n1. Registration & password policy');
  const a = new Client();
  let r = await a.post('/register', '/register', { username: 'alice', email: 'alice@test.com', password: 'password', confirm: 'password', terms: 'on' });
  check('weak password rejected (400)', r.status === 400 && r.text.includes('at least one') === false && r.text.includes('uppercase'));
  r = await a.post('/register', '/register', { username: 'alice', email: 'alice@test.com', phone: '+8801711111111', password: PW, confirm: PW, terms: 'on' });
  check('strong password accepted -> redirect /login', r.status === 302 && r.location === '/login');
  const [[u]] = await db.query('SELECT password_hash FROM users WHERE username = ?', ['alice']);
  check('password stored as bcrypt hash', /^\$2[aby]\$12\$/.test(u.password_hash) && !u.password_hash.includes(PW));
  r = await a.post('/register', '/register', { username: 'alice', email: 'other@test.com', password: PW, confirm: PW, terms: 'on' });
  check('duplicate username rejected', r.status === 400);
  const b = new Client();
  await b.post('/register', '/register', { username: 'bob_seller', email: 'bob@test.com', password: PW, confirm: PW, terms: 'on' });

  console.log('\n2. Login + email/SMS OTP 2FA');
  let L = await loginWithOtp(a, 'alice', 'alice@test.com', PW);
  check('password step redirects to /verify-2fa', L.step1.location === '/verify-2fa');
  check('OTP stored hashed, not plain', (await db.query('SELECT code_hash FROM otp_codes'))[0].every((o) => o.code_hash.length === 64));
  const [[sms]] = await db.query("SELECT * FROM dev_mailbox WHERE channel = 'sms' ORDER BY id DESC LIMIT 1");
  check('OTP also sent by SMS (phone set)', sms && sms.body.includes(L.code));
  check('correct OTP signs in -> /dashboard', L.step2.location === '/dashboard');
  check('device cookie is signed + httpOnly', !!a.jar.sb_device && a.jar.sb_device.startsWith('s%3A'));
  r = await a.get('/dashboard');
  check('dashboard loads with products', r.status === 200 && r.text.includes('Walton Primo'));
  check('security headers: CSP + frame-ancestors', (r.headers.get('content-security-policy') || '').includes("frame-ancestors 'none'"));
  check('no-store cache header on signed-in page', (r.headers.get('cache-control') || '').includes('no-store'));
  check('x-powered-by hidden', !r.headers.get('x-powered-by'));
  const sid = (r.headers.get('set-cookie') || '');
  check('session cookie HttpOnly + SameSite=Strict', /HttpOnly/i.test(sid) && /SameSite=Strict/i.test(sid));

  console.log('\n3. New device alert');
  const a2 = new Client(); a2.ua = 'Mozilla/5.0 (Windows NT 10.0) Firefox/130 OtherDevice';
  L = await loginWithOtp(a2, 'alice@test.com', 'alice@test.com', PW); // login by email works too
  check('login by email works', L.step2 && L.step2.location === '/dashboard');
  const nd = await lastMail('alice@test.com', 'New device%');
  check('new-device email sent', nd && nd.body.includes('Firefox on Windows'));
  const [[ndl]] = await db.query("SELECT COUNT(*) n FROM audit_logs WHERE event = 'NEW_DEVICE_LOGIN'");
  check('NEW_DEVICE_LOGIN logged', ndl.n === 1);

  console.log('\n4. Wrong OTP + lockout after 3 failures');
  const bc = new Client();
  r = await bc.post('/login', '/login', { username: 'bob_seller', password: 'Wrong!Pass1' });
  check('1st wrong password: 2 attempts left', r.status === 401 && r.text.includes('2 attempt(s) left'));
  r = await bc.post('/login', '/login', { username: 'bob_seller', password: 'Wrong!Pass2' });
  check('2nd wrong password: 1 attempt left', r.text.includes('1 attempt(s) left'));
  r = await bc.post('/login', '/login', { username: 'bob_seller', password: 'Wrong!Pass3' });
  check('3rd wrong password locks account (423)', r.status === 423 && r.text.includes('locked'));
  r = await bc.post('/login', '/login', { username: 'bob_seller', password: PW });
  check('correct password refused while locked', r.status === 423);
  check('lockout email sent', !!(await lastMail('bob@test.com', '%temporarily locked%')));
  await db.query('UPDATE users SET lock_until = NULL, failed_attempts = 0 WHERE username = ?', ['bob_seller']);
  r = await bc.post('/login', '/login', { username: 'bob_seller', password: PW });
  r = await bc.post('/verify-2fa', '/verify-2fa', { code: '000000' });
  check('wrong OTP rejected', r.status === 401 && r.text.includes('Incorrect verification code'));
  const [[bobRow]] = await db.query('SELECT failed_attempts FROM users WHERE username = ?', ['bob_seller']);
  check('wrong OTP counts as failed attempt', bobRow.failed_attempts === 1);

  console.log('\n5. Password recovery');
  const fc = new Client();
  r = await fc.post('/forgot', '/forgot', { email: 'nobody@test.com' });
  const genericUnknown = r.text.includes('If an account exists');
  r = await fc.post('/forgot', '/forgot', { email: 'bob@test.com' });
  check('same response for known & unknown email', genericUnknown && r.text.includes('If an account exists'));
  const rm = await lastMail('bob@test.com', 'Reset your%');
  const resetPath = new URL(rm.action_url).pathname;
  const token = resetPath.split('/').pop();
  const [[tok]] = await db.query('SELECT token_hash FROM password_resets ORDER BY id DESC LIMIT 1');
  check('reset token stored only as hash', tok.token_hash !== token && tok.token_hash.length === 64);
  const NEWPW = 'N3w!Bazar#Pass';
  r = await fc.post(resetPath, resetPath, { password: 'short', confirm: 'short' });
  check('reset enforces policy', r.status === 400);
  r = await fc.post(resetPath, resetPath, { password: NEWPW, confirm: NEWPW });
  check('reset succeeds -> /login', r.status === 302 && r.location === '/login');
  r = await fc.get(resetPath);
  check('reset link cannot be reused', r.status === 400);
  r = await fc.get('/reset/' + 'a'.repeat(64));
  check('random token rejected', r.status === 400);
  L = await loginWithOtp(bc, 'bob_seller', 'bob@test.com', NEWPW);
  check('login with new password works', L.step2 && L.step2.location === '/dashboard');

  console.log('\n6. SQL injection');
  const sq = new Client();
  r = await sq.post('/login', '/login', { username: "' OR '1'='1' -- ", password: "' OR '1'='1" });
  check("login bypass ' OR '1'='1 fails", r.status === 401 && r.text.includes('Invalid username or password'));
  r = await sq.post('/login', '/login', { username: "admin'-- ", password: 'x' });
  check("admin'-- comment injection fails", r.status === 401);
  r = await a.get('/dashboard?q=' + encodeURIComponent("%' UNION SELECT password_hash,1,1,1,1,1 FROM users -- "));
  check('UNION injection in search returns safely, no hashes', r.status === 200 && !r.text.includes('$2b$') && r.text.includes('No products match'));
  r = await a.get('/dashboard?sort=' + encodeURIComponent('price; DROP TABLE users'));
  const [[cnt]] = await db.query('SELECT COUNT(*) n FROM users');
  check('ORDER BY injection ignored (whitelist)', r.status === 200 && cnt.n >= 3);
  r = await a.get('/products/1%20OR%201=1');
  check('non-numeric id rejected (404)', r.status === 404);

  console.log('\n7. XSS');
  const XSS = '<script>alert(document.cookie)</script>';
  r = await a.get('/dashboard?q=' + encodeURIComponent(XSS));
  check('reflected XSS escaped in search', !r.text.includes(XSS) && r.text.includes('&lt;script&gt;'));
  r = await bc.post('/products/new', '/products', { title: XSS, description: '<img src=x onerror=alert(1)> stored xss test', category: 'Other', price: '10', stock: '2' });
  const pid = r.location && r.location.split('/').pop();
  r = await a.get('/products/' + pid);
  check('stored XSS escaped on product page', r.status === 200 && !r.text.includes(XSS) && !r.text.includes('<img src=x'));

  console.log('\n8. CSRF');
  const [[cb]] = await db.query("SELECT COUNT(*) n FROM audit_logs WHERE event = 'CSRF_BLOCKED'");
  r = await a.req('POST', '/products', { title: 'csrf item', description: 'should not be created', category: 'Other', price: '1', stock: '1' });
  check('POST without CSRF token -> 403', r.status === 403);
  r = await a.req('POST', '/products', { _csrf: 'f'.repeat(64), title: 'csrf item', description: 'should not be created', category: 'Other', price: '1', stock: '1' });
  check('POST with forged CSRF token -> 403', r.status === 403);
  const [[cl]] = await db.query("SELECT COUNT(*) n FROM audit_logs WHERE event = 'CSRF_BLOCKED'");
  check('CSRF_BLOCKED logged', cl.n - cb.n === 2);

  console.log('\n9. Access control & business logic');
  r = await a.get('/admin');
  check('normal user gets 403 on /admin', r.status === 403);
  r = await new Client().get('/dashboard');
  check('anonymous user redirected to /login', r.status === 302 && r.location === '/login');
  r = await a.post('/products/' + pid, `/products/${pid}/delete`, {});
  check("can't delete someone else's listing (IDOR)", r.status === 403);
  r = await a.post('/products/1', '/products/1/buy', { quantity: '2', price: '0.01' });
  const [[ord]] = await db.query('SELECT * FROM orders ORDER BY id DESC LIMIT 1');
  check('buy works, price taken from DB not form', r.location === '/orders' && Number(ord.unit_price) === 18999 && Number(ord.total) === 37998);
  const [[st]] = await db.query('SELECT stock FROM products WHERE id = 1');
  check('stock decremented', st.stock === 3);
  r = await a.post('/products/1', '/products/1/buy', { quantity: '99' });
  check('cannot buy more than stock', r.location === '/products/1');
  r = await bc.post('/products/' + pid, `/products/${pid}/buy`, { quantity: '1' });
  const [[own]] = await db.query('SELECT COUNT(*) n FROM orders WHERE product_id = ?', [pid]);
  check('cannot buy own item', own.n === 0);

  console.log('\n10. Admin dashboard');
  const ad = new Client();
  L = await loginWithOtp(ad, ADMIN.username, ADMIN.email.toLowerCase(), ADMIN.password);
  check('admin login -> /admin', L.step2 && L.step2.location === '/admin');
  for (const p of ['/admin', '/admin/users?q=bob', '/admin/logs?event=LOGIN_FAILED', '/admin/products?q=walton', '/admin/logs?q=' + encodeURIComponent(XSS)]) {
    r = await ad.get(p);
    check(`GET ${p} -> 200`, r.status === 200 && !r.text.includes(XSS), r.status);
  }
  r = await ad.get('/admin/users?q=bob');
  check('admin user search finds bob', r.text.includes('bob_seller') && !r.text.includes('alice@test.com'));
  const [[bobId]] = await db.query('SELECT id FROM users WHERE username = ?', ['bob_seller']);
  r = await ad.post('/admin/users', `/admin/users/${bobId.id}/disable`, {});
  r = await bc.get('/dashboard');
  check('disabled user is kicked out immediately', r.status === 302 && r.location === '/login');
  await ad.post('/admin/users', `/admin/users/${bobId.id}/enable`, {});

  console.log('\n11. Change password signs out other sessions');
  r = await a.post('/account', '/account/password', { current: PW, password: 'Ch4nged!Bazar#1', confirm: 'Ch4nged!Bazar#1' });
  check('password change OK', r.location === '/account');
  check('current session still valid', (await a.get('/dashboard')).status === 200);
  r = await a2.get('/dashboard');
  check('other device session revoked', r.status === 302 && r.location === '/login');

  console.log('\n12. Authenticator app (TOTP)');
  r = await a.get('/account/2fa/setup');
  const secret = r.text.match(/<code class="secret">([A-Z2-7]+)<\/code>/)[1];
  check('QR code shown', r.text.includes('data:image/png;base64'));
  r = await a.post('/account/2fa/setup', '/account/2fa/enable', { code: await totp.generate({ secret }) });
  const [[tu]] = await db.query('SELECT totp_enabled, totp_secret FROM users WHERE username = ?', ['alice']);
  check('TOTP enabled, secret encrypted at rest', tu.totp_enabled === 1 && !tu.totp_secret.includes(secret));
  const t = new Client();
  r = await t.post('/login', '/login', { username: 'alice', password: 'Ch4nged!Bazar#1' });
  r = await t.get('/verify-2fa');
  check('login now asks for authenticator code', r.text.includes('authenticator app'));
  const sameCode = await totp.generate({ secret });
  r = await t.post('/verify-2fa', '/verify-2fa', { code: sameCode });
  check('replayed TOTP code rejected', r.status === 401);
  const nextCode = await totp.generate({ secret, epoch: Math.floor(Date.now() / 1000) + 30 });
  r = await t.post('/verify-2fa', '/verify-2fa', { code: nextCode });
  check('fresh TOTP code accepted', r.location === '/dashboard', r.status + ' ' + r.location);

  console.log('\n13. Logout');
  r = await t.post('/dashboard', '/logout', {});
  r = await t.get('/dashboard');
  check('after logout, dashboard redirects to login', r.status === 302 && r.location === '/login');

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  await db.end();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('CRASH', e); process.exit(2); });
