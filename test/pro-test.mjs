// Test: kontoradering avslutar Pro i Stripe, och uppsägning/återbetalning/tvist tar bort Pro (mot låtsas-Stripe). Kör: node test/pro-test.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite'; import { fileURLToPath } from 'node:url';
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 18497, BAS = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-pro-test-'));
for (const f of fs.readdirSync(REPO)) if (f.endsWith('.js')) fs.copyFileSync(path.join(REPO, f), path.join(tmp, f));
const MOCK = path.join(tmp, 'stripe.json');
const ENV = { PATH: process.env.PATH, HOME: tmp, PORT: String(PORT), MAIL_LOGG: '1', BREVO_API_KEY: '', CHATT_HOTLISTOR: '0', CLAMD_PORT: '1',
  CHATT_NYCKEL: crypto.randomBytes(32).toString('hex'), SUPPORT_SECRET: crypto.randomBytes(32).toString('hex'),
  STRIPE_SECRET_KEY: 'sk_test_lats', STRIPE_PUBLISHABLE_KEY: 'pk_test_lats', AI_CHAT_KEY: '', STRIPE_MOCK: MOCK };
const nu = Math.floor(Date.now() / 1000);
const sub = (id, kund, extra = {}) => ({ id, customer: kund, status: 'active', cancel_at_period_end: false, current_period_end: nu + 30 * 86400, latest_invoice: { charge: { refunded: false, disputed: false } }, items: { data: [] }, ...extra });
const skriv = (st) => fs.writeFileSync(MOCK, JSON.stringify(st)); const las = () => JSON.parse(fs.readFileSync(MOCK, 'utf8'));
skriv({ subs: {} });
let logg = ''; const srv = spawn(process.execPath, ['--import', path.join(REPO, 'test/stripe-mock.mjs'), path.join(tmp, 'server.js')], { cwd: tmp, env: ENV, stdio: ['ignore', 'pipe', 'pipe'] });
srv.stdout.on('data', (d) => { logg += d; }); srv.stderr.on('data', (d) => { logg += d; });
process.on('exit', () => { try { srv.kill(); } catch {} fs.rmSync(tmp, { recursive: true, force: true }); });
for (let i = 0; i < 100 && !logg.includes('adraze-api på'); i++) await new Promise((r) => setTimeout(r, 50));
const db = new DatabaseSync(path.join(tmp, 'adraze.db'));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hashPass = (p) => { const salt = crypto.randomBytes(16).toString('hex'); return `${salt}:${crypto.scryptSync(p, salt, 64).toString('hex')}`; };
let n = 0;
function konto(subId, proKvar = true) {
  n++; const kund = 'cus_test' + n;
  const id = Number(db.prepare('INSERT INTO users(email,pass,verified,created_at,stripe_customer,pro_sub,pro_until) VALUES(?,?,1,?,?,?,?)')
    .run(`pro${n}@test.invalid`, hashPass('lösen123'), Date.now(), kund, subId, proKvar ? Date.now() + 20 * 86400_000 : null).lastInsertRowid);
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(token), id, Date.now() + 86400_000);
  return { id, token, kund };
}
const api = async (v, m, p, b) => { const r = await fetch(BAS + p, { method: m, headers: { 'cf-connecting-ip': '10.9.0.' + v.id, authorization: 'Bearer ' + v.token, ...(b ? { 'content-type': 'application/json' } : {}) }, body: b ? JSON.stringify(b) : undefined }); let j = null; try { j = await r.json(); } catch {} return { s: r.status, j }; };
let ok = 0, fel = 0; const koll = (namn, v, info) => { if (v) { ok++; console.log('  ok  ', namn); } else { fel++; console.log('  FEL ', namn, JSON.stringify(info ?? '').slice(0, 300)); } };

// 1) Radering med aktiv Pro → prenumerationen avslutas i Stripe, kontot raderas
let a = konto('sub_aaaaaaaaaa'); let st = las(); st.subs.sub_aaaaaaaaaa = sub('sub_aaaaaaaaaa', a.kund); skriv(st);
let r = await api(a, 'POST', '/me/delete', { password: 'lösen123' });
koll('radering ok', r.s === 200, r); koll('Stripe-prenumerationen avslutad', las().subs.sub_aaaaaaaaaa.status === 'canceled', las().anrop);
koll('kontot borta', !db.prepare('SELECT 1 FROM users WHERE id=?').get(a.id));
// 2) Stripe nere vid radering → kontot raderas INTE
let b = konto('sub_bbbbbbbbbb'); st = las(); st.subs.sub_bbbbbbbbbb = sub('sub_bbbbbbbbbb', b.kund); st.felVidDelete = true; skriv(st);
r = await api(b, 'POST', '/me/delete', { password: 'lösen123' });
koll('Stripe-fel → 502 och konto kvar', r.s === 502 && !!db.prepare('SELECT 1 FROM users WHERE id=?').get(b.id), r);
st = las(); st.felVidDelete = false; skriv(st);
// 3) Redan avslutad prenumeration → radering går igenom utan DELETE
let c = konto('sub_cccccccccc'); st = las(); st.subs.sub_cccccccccc = sub('sub_cccccccccc', c.kund, { status: 'canceled' }); skriv(st);
r = await api(c, 'POST', '/me/delete', { password: 'lösen123' }); koll('avslutad sub → radering ok', r.s === 200, r);
// 4) Återbetald betalning medan Pro är aktiv → Pro försvinner vid nästa koll
let d = konto('sub_dddddddddd'); st = las(); st.subs.sub_dddddddddd = sub('sub_dddddddddd', d.kund, { latest_invoice: { charge: { refunded: true, disputed: false } } }); skriv(st);
r = await api(d, 'GET', '/me'); koll('återbetald → ingen Pro', db.prepare('SELECT pro_until FROM users WHERE id=?').get(d.id).pro_until === null, db.prepare('SELECT pro_until FROM users WHERE id=?').get(d.id));
// 5) Tvist
let e = konto('sub_eeeeeeeeee'); st = las(); st.subs.sub_eeeeeeeeee = sub('sub_eeeeeeeeee', e.kund, { latest_invoice: { charge: { refunded: false, disputed: true } } }); skriv(st);
await api(e, 'GET', '/me'); koll('tvist → ingen Pro', db.prepare('SELECT pro_until FROM users WHERE id=?').get(e.id).pro_until === null);
// 6) Avslutad direkt i Stripe (t.ex. i dashboarden) → ingen Pro
let f = konto('sub_ffffffffff'); st = las(); st.subs.sub_ffffffffff = sub('sub_ffffffffff', f.kund, { status: 'canceled' }); skriv(st);
await api(f, 'GET', '/me'); koll('avslutad i Stripe → ingen Pro', db.prepare('SELECT pro_until FROM users WHERE id=?').get(f.id).pro_until === null);
// 7) Vanlig uppsägning vid periodens slut → Pro kvar perioden ut
let g = konto('sub_gggggggggg'); st = las(); st.subs.sub_gggggggggg = sub('sub_gggggggggg', g.kund, { cancel_at_period_end: true }); skriv(st);
await api(g, 'GET', '/me'); koll('uppsagd vid periodslut → Pro kvar', db.prepare('SELECT pro_until FROM users WHERE id=?').get(g.id).pro_until > Date.now());
// 8) Konto utan Pro raderas utan Stripe-anrop
const fore = las().anrop.length; let h = konto(null, false);
r = await api(h, 'POST', '/me/delete', { password: 'lösen123' }); koll('utan Pro → radering utan Stripe', r.s === 200 && las().anrop.length === fore, r);
console.log(`\n${ok} ok, ${fel} fel`); process.exit(fel ? 1 : 0);
