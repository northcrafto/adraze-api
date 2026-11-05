// Test av kontoflödena i server.js (+ support.js och synk.js) mot en tillfällig kopia med egen temp-databas.
// Mejl skickas aldrig (MAIL_LOGG=1); koderna läses ur serverns logg. Kör: node test/konto-test.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.TEST_PORT || 18494);
const BAS = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-konto-test-'));
for (const f of fs.readdirSync(REPO)) if (f.endsWith('.js')) fs.copyFileSync(path.join(REPO, f), path.join(tmp, f));

const ENV = { ...process.env, PORT: String(PORT), MAIL_LOGG: '1', BREVO_API_KEY: '', CHATT_HOTLISTOR: '0', CLAMD_PORT: '1',
  CHATT_NYCKEL: crypto.randomBytes(32).toString('hex'), SUPPORT_SECRET: crypto.randomBytes(32).toString('hex'),
  SUPPORT_TEAM: 'team@test.invalid', SUPPORT_TILL: 'team@test.invalid', FORSLAG_TILL: 'team@test.invalid',
  MAIL_PER_DAG: '9', MAIL_OPPEN_PER_DAG: '4', MAIL_DRIFT_PER_DAG: '2', STRIPE_SECRET_KEY: '', AI_CHAT_KEY: '' };
let srv, logg = '';
async function starta() {
  srv = spawn(process.execPath, [path.join(tmp, 'server.js')], { cwd: tmp, env: ENV, stdio: ['ignore', 'pipe', 'pipe'] });
  const fore = logg.length;
  srv.stdout.on('data', (d) => { logg += d; });
  srv.stderr.on('data', (d) => { logg += d; });
  for (let i = 0; i < 100 && !logg.slice(fore).includes('adraze-api på'); i++) await new Promise((r) => setTimeout(r, 50));
  if (!logg.slice(fore).includes('adraze-api på')) { console.error(logg); throw new Error('servern startade inte'); }
}
const stoppa = () => new Promise((r) => { srv.once('exit', r); srv.kill(); });
const stang = () => { try { srv.kill(); } catch {} try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} };
process.on('exit', stang);
await starta();

const db = new DatabaseSync(path.join(tmp, 'adraze.db'));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hashPass = (p) => { const salt = crypto.randomBytes(16).toString('hex'); return `${salt}:${crypto.scryptSync(p, salt, 64).toString('hex')}`; };
function dbKonto(email, pass) {
  const id = Number(db.prepare('INSERT INTO users(email,pass,verified,created_at) VALUES(?,?,1,?)').run(email, pass ? hashPass(pass) : null, Date.now()).lastInsertRowid);
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(token), id, Date.now() + 86_400_000);
  return { id, token, ip: `10.8.${id}.1` };
}
async function api(vem, metod, p, kropp, ip) {
  const r = await fetch(BAS + p, { method: metod,
    headers: { 'cf-connecting-ip': ip || vem?.ip || '10.7.0.1', ...(vem?.token ? { authorization: 'Bearer ' + vem.token } : {}), ...(kropp ? { 'content-type': 'application/json' } : {}) },
    body: kropp ? JSON.stringify(kropp) : undefined });
  let j = null; try { j = await r.json(); } catch {}
  return { s: r.status, j };
}
const kodTill = (email) => { const m = [...logg.matchAll(new RegExp(`\\[mejl loggat\\] ${email.replace(/[.]/g, '\\.')} (\\d{6}) `, 'g'))]; return m.length ? m[m.length - 1][1] : null; };
const sakert = (fn, alt) => { try { return fn(); } catch { return alt; } };   // tabeller som saknas i äldre kod
let ok = 0, fel = 0;
function koll(namn, villkor, info) {
  if (villkor) { ok++; console.log('  ok  ', namn); }
  else { fel++; console.log('  FEL ', namn, info !== undefined ? JSON.stringify(info).slice(0, 300) : ''); }
}
let r;

console.log('Registrering och inloggning');
r = await api(null, 'POST', '/auth/signup', { email: 's1@test.invalid', password: 'losenord-ett', namn: 'Ett' }, '10.7.1.1');
koll('signup s1 → kod', r.s === 200 && r.j.steg === 'kod' && kodTill('s1@test.invalid'), r);
r = await api(null, 'POST', '/auth/verify', { email: 's1@test.invalid', code: kodTill('s1@test.invalid'), app: true }, '10.7.1.1');
koll('verify s1 → inloggad i appen', r.s === 200 && r.j.token && r.j.me.namn === 'Ett', r);
const S1 = { token: r.j.token, ip: '10.7.1.1', id: db.prepare('SELECT id FROM users WHERE email=?').get('s1@test.invalid').id };

console.log('Id återanvänds inte, synk följer inte med');
const V = dbKonto('v@test.invalid');
r = await api(V, 'POST', '/synk/push', { sorts: 'bokmarken', poster: [{ url: 'https://privat.invalid/v', title: 'V privat', _t: Date.now() }] });
koll('V synkar ett bokmärke', r.s === 200 && r.j.poster.length === 1, r);
r = await api(V, 'POST', '/me/delete', {});
koll('V raderar kontot', r.s === 200, r);
koll('V:s synk raderad med kontot (trigger)', db.prepare('SELECT COUNT(*) c FROM synk WHERE user_id=?').get(V.id).c === 0);
r = await api(null, 'POST', '/auth/signup', { email: 'w@test.invalid', password: 'losenord-w' }, '10.7.2.1');
const W = { id: db.prepare('SELECT id FROM users WHERE email=?').get('w@test.invalid')?.id, ip: '10.7.2.1' };
koll('nytt konto får inte det raderade kontots id', r.s === 200 && W.id > V.id, { V: V.id, W: W.id });
r = await api(null, 'POST', '/auth/verify', { email: 'w@test.invalid', code: kodTill('w@test.invalid'), app: true }, W.ip);
W.token = r.j?.token;
db.prepare('INSERT INTO synk(user_id,sorts,data,rev,updated) VALUES(?,?,?,?,?)').run(W.id, 'kortkommandon',
  JSON.stringify({ poster: { k: { id: 'k', url: 'https://gammal.invalid/', _t: 1 } }, borttagna: {} }), 3, Date.now() - 86_400_000);
r = await api(W, 'POST', '/synk/get', { sorts: 'kortkommandon' });
koll('synkrad äldre än kontot räknas som tom', r.s === 200 && r.j.poster.length === 0 && r.j.rev === 0, r);
r = await api(W, 'POST', '/synk/push', { sorts: 'kortkommandon', poster: [{ id: 'n', url: 'https://ny.invalid/', _t: Date.now() }] });
koll('första push skriver över den gamla raden', r.s === 200 && r.j.poster.length === 1 && r.j.poster[0].id === 'n' && r.j.rev === 1, r);
koll('högvattnet ligger över alla id', sakert(() => db.prepare("SELECT max_id FROM id_hogvatten WHERE tabell='users'").get().max_id >= W.id, false));

console.log('Obekräftad registrering skrivs över helt');
r = await api(null, 'POST', '/auth/signup', { email: 's2@test.invalid', password: 'angriparens', namn: 'Angripare' }, '10.7.3.1');
koll('förregistrering med namn', r.s === 200 && db.prepare('SELECT namn FROM users WHERE email=?').get('s2@test.invalid').namn === 'Angripare', r);
r = await api(null, 'POST', '/auth/signup', { email: 's2@test.invalid', password: 'agarens-losen' }, '10.7.3.2');
koll('ny registrering utan namn nollställer namnet', r.s === 200 && db.prepare('SELECT namn FROM users WHERE email=?').get('s2@test.invalid').namn === null, r);

console.log('Mejlbudget per klass');
r = await api(null, 'POST', '/auth/signup', { email: 's3@test.invalid', password: 'losenord-tre' }, '10.7.4.1');
koll('signup s3 (fjärde öppna mejlet)', r.s === 200, r);
r = await api(null, 'POST', '/auth/signup', { email: 's4@test.invalid', password: 'losenord-fyra' }, '10.7.4.2');
koll('öppna taket nått → 502', r.s === 502, r);
koll('ingen kod sparad när mejlet inte gick iväg', !db.prepare("SELECT 1 FROM codes WHERE email='s4@test.invalid'").get());
r = await api(null, 'POST', '/auth/signup', { email: 's4@test.invalid', password: 'losenord-fyra' }, '10.7.4.2');
koll('nytt försök direkt → 502 igen (inte ett tyst "skickat")', r.s === 502, r);
r = await api(null, 'POST', '/support/nytt', { email: 'S1@test.invalid', amne: 'Planterat', text: 'Text från någon annan än ägaren', kategori: 'konto' }, '10.7.5.1');
koll('anonymt ärende i s1:s namn', r.s === 200 && r.j.nr, r);
const planterat = r.j?.nr;
r = await api(S1, 'GET', '/support/mina');
koll('s1 ser inte ärendet bara för att mejladressen stämmer', r.s === 200 && r.j.arenden.length === 0, r);
r = await api(S1, 'POST', '/support/mitt', { nr: planterat });
koll('s1 kan inte öppna det via kontot → 404', r.s === 404, r);
const driftFore = (logg.match(/Mejltaket nått för i dag \(drift\)/g) || []).length;
r = await api(null, 'POST', '/support/nytt', { email: 'annan@test.invalid', amne: 'Andra', text: 'Ett andra ärende efter taket', kategori: 'annat' }, '10.7.5.2');
koll('ärende efter drifttaket sparas men mejlas inte', r.s === 200 && (logg.match(/Mejltaket nått för i dag \(drift\)/g) || []).length === driftFore + 2, r);
r = await api(null, 'POST', '/auth/login', { email: 's1@test.invalid', password: 'losenord-ett', app: true }, '10.7.6.1');
koll('inloggningskod går fram trots fulla öppna/drift-tak', r.s === 200 && r.j.syfte === 'login' && /\[mejl loggat\] s1@test\.invalid \d{6} är din inloggningskod/.test(logg), r);
r = await api(S1, 'POST', '/support/nytt', { amne: 'Eget', text: 'Mitt eget ärende som inloggad', kategori: 'konto' });
koll('inloggat ärende', r.s === 200, r);
r = await api(S1, 'GET', '/support/mina');
koll('s1 ser sitt inloggade ärende', r.s === 200 && r.j.arenden.length === 1 && r.j.arenden[0].amne === 'Eget', r);
r = await api(S1, 'POST', '/familj/barn', { namn: 'Lill', alder: 8 });
koll('barn skapat', r.s === 200 && r.j.kod, r);
const barnKod = r.j?.kod;
const U2 = dbKonto('u2@test.invalid', 'losenord-u2'), U3 = dbKonto('u3@test.invalid', 'losenord-u3');
await api(null, 'POST', '/auth/login', { email: 'u2@test.invalid', password: 'losenord-u2', app: true }, '10.7.7.1');
r = await api(null, 'POST', '/auth/login', { email: 'u3@test.invalid', password: 'losenord-u3', app: true }, '10.7.7.2');
koll('totalen förbrukad med kontomejl', r.s === 200 && sakert(() => db.prepare('SELECT SUM(n) s FROM mejl_kvot').get().s, 0) === 9, sakert(() => db.prepare('SELECT * FROM mejl_kvot').all(), 'mejl_kvot saknas'));
r = await api(null, 'POST', '/barn/start', { kod: barnKod }, '10.7.8.1');
koll('barnkod utan mejlbudget → 502', r.s === 502, r);
r = await api(null, 'POST', '/barn/start', { kod: barnKod }, '10.7.8.1');
koll('nytt försök → 502 igen (inte "skickad")', r.s === 502 && !db.prepare('SELECT 1 FROM barn_godkann').get(), r);

console.log('Omstart nollar inte mejlbudgeten');
await stoppa(); await starta();
r = await api(null, 'POST', '/auth/signup', { email: 's5@test.invalid', password: 'losenord-fem' }, '10.7.9.1');
koll('efter omstart: fortfarande 502', r.s === 502, r);

console.log('Radering tar supportärenden');
const fore = db.prepare("SELECT COUNT(*) c FROM support_arenden WHERE user_id=? OR email='s1@test.invalid'").get(S1.id).c;
r = await api(S1, 'POST', '/me/delete', { password: 'losenord-ett' });
koll('s1 raderar kontot', r.s === 200 && fore === 2, { r, fore });
koll('s1:s ärenden (inloggat och anonymt från adressen) borta', db.prepare("SELECT COUNT(*) c FROM support_arenden WHERE user_id=? OR email='s1@test.invalid'").get(S1.id).c === 0);
koll('meddelandena följer med', db.prepare('SELECT COUNT(*) c FROM support_meddelanden m LEFT JOIN support_arenden a ON a.id=m.arende_id WHERE a.id IS NULL').get().c === 0);

console.log('Trasig adress och gränser');
const rå = await new Promise((ok2) => {
  const s = net.connect(PORT, '127.0.0.1', () => s.end('GET // HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'));
  let d = ''; s.on('data', (c) => { d += c; }); s.on('close', () => ok2(d)); s.on('error', () => ok2(d));
});
koll('GET // → 400', /^HTTP\/1\.1 400/.test(rå), rå.slice(0, 80));
r = await api(null, 'GET', '/health');
koll('servern lever efteråt', r.s === 200, r);
let sista;
for (let i = 0; i < 61; i++) sista = await api(null, 'POST', '/auth/verify', { email: `x${i}@test.invalid`, code: '000000' }, '10.7.10.1');
koll('kodförsök mot många adresser från en IP → 429', sista.s === 429, sista);
r = await api(null, 'POST', '/auth/verify', { email: 'x0@test.invalid', code: '000000' }, '10.7.10.2');
koll('annan IP påverkas inte', r.s === 400, r);

console.log(`\n${ok} ok, ${fel} fel`);
if (fel) console.log('--- serverlogg ---\n' + logg.slice(-3000));
stang();
process.exit(fel ? 1 : 0);
