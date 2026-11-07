// Familjechatt: barnkonton kan bara chatta med sin familj. Tillfällig kopia av adraze-api med egen temp-databas.
// Kör: node test/familj-chatt-test.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.TEST_PORT || 18494);
const BAS = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-familjchatt-'));
for (const f of fs.readdirSync(REPO)) if (f.endsWith('.js')) fs.copyFileSync(path.join(REPO, f), path.join(tmp, f));
const srv = spawn(process.execPath, [path.join(tmp, 'server.js')], {
  cwd: tmp, env: { ...process.env, PORT: String(PORT), MAIL_LOGG: '1', CHATT_HOTLISTOR: '0', BREVO_API_KEY: '', CLAMD_PORT: '1', CHATT_NYCKEL: crypto.randomBytes(32).toString('hex') }, stdio: ['ignore', 'pipe', 'pipe'],
});
let logg = ''; srv.stdout.on('data', (d) => { logg += d; }); srv.stderr.on('data', (d) => { logg += d; });
process.on('exit', () => { try { srv.kill(); } catch {} try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} });
for (let i = 0; i < 100 && !logg.includes('adraze-api på'); i++) await new Promise((r) => setTimeout(r, 50));
if (!logg.includes('adraze-api på')) { console.error(logg); throw new Error('servern startade inte'); }

const db = new DatabaseSync(path.join(tmp, 'adraze.db'));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
let n = 0;
function vuxen(email) {
  const id = Number(db.prepare('INSERT INTO users(email,verified,created_at) VALUES(?,1,?)').run(email, Date.now()).lastInsertRowid);
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(token), id, Date.now() + 86_400_000);
  return { id, token, ip: `10.8.${++n}.1` };
}
function barn(foralder, namn) {
  const id = 'b' + crypto.randomBytes(12).toString('hex');
  db.prepare('INSERT INTO barn(id,foralder_id,namn,alder,kod,skapad) VALUES(?,?,?,?,?,?)').run(id, foralder.id, namn, 10, namn.toUpperCase() + '-' + crypto.randomBytes(4).toString('hex'), Date.now());
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO barn_sessioner(token,barn_id,skapad,expires) VALUES(?,?,?,?)').run(sha(token), id, Date.now(), Date.now() + 86_400_000);
  return { barnId: id, token, ip: `10.8.${++n}.1` };
}
async function api(vem, metod, p, kropp) {
  const r = await fetch(BAS + p, { method: metod, headers: { authorization: 'Bearer ' + vem.token, 'cf-connecting-ip': vem.ip, ...(kropp ? { 'content-type': 'application/json' } : {}) }, body: kropp ? JSON.stringify(kropp) : undefined });
  let j = null; try { j = await r.json(); } catch {}
  return { s: r.status, j };
}
let ok = 0, fel = 0;
const koll = (namn, v, info) => { if (v) { ok++; console.log('  ok  ', namn); } else { fel++; console.log('  FEL ', namn, info !== undefined ? JSON.stringify(info).slice(0, 300) : ''); } };
const hash = (s) => crypto.createHash('sha256').update(s).digest('base64');
const reg = (vem, u) => api(vem, 'POST', '/chatt/registrera', { username: u, login_hash: hash(u), public_key: 'PK' + u, enc_priv: 'EP' + u });

const P = vuxen('pappa@test.se'), S = vuxen('sven@test.se');
const K = barn(P, 'Kalle'), K2 = barn(P, 'Kim');
let r;
r = await api(K, 'GET', '/chatt/jag'); koll('barnet kommer in i chatten (ingen profil än)', r.s === 200 && r.j.profil === null, r);
for (const [v, u] of [[P, 'Pappa'], [S, 'Sven'], [K, 'Kalle'], [K2, 'Kim']]) { r = await reg(v, u); koll('registrera ' + u, r.s === 200, r); }
r = await api(K, 'GET', '/chatt/nyckel'); koll('barnet får sin chattnyckel', r.s === 200 && r.j.secret, r);
r = await api(K, 'GET', '/chatt/contacts'); const kk = (r.j.contacts || []).map((c) => c.username).sort();
koll('barnets kontakter = familjen (av sig själv)', JSON.stringify(kk) === '["Kim","Pappa"]', r.j);
r = await api(P, 'GET', '/chatt/contacts'); koll('föräldern ser båda barnen', JSON.stringify((r.j.contacts || []).map((c) => c.username).sort()) === '["Kalle","Kim"]', r.j);
r = await api(K, 'POST', '/chatt/contacts/request', { username: 'Sven' }); koll('barnet kan inte lägga till en främling', r.s === 403 && r.j.error === 'family_only', r);
r = await api(S, 'POST', '/chatt/contacts/request', { username: 'Kalle' }); koll('främling hittar inte barnet', r.s === 404, r);
r = await api(S, 'GET', '/chatt/users/lookup?username=kalle'); koll('främling: barnet finns inte i sökningen', r.s === 200 && r.j.exists === false, r);
r = await api(K, 'POST', '/chatt/messages/send', { to_id: String(P.id), ciphertext: 'QUJD' }); koll('barnet skickar till föräldern', r.s === 200, r);
r = await api(P, 'GET', '/chatt/messages?with=' + (db.prepare('SELECT user_id FROM chatt_barn WHERE barn_id=?').get(K.barnId).user_id)); koll('föräldern läser meddelandet', r.s === 200 && (r.j.messages || []).length === 1, r);
r = await api(K, 'POST', '/chatt/contacts/block', { username: 'Pappa' }); koll('barnet kan inte blockera föräldern', r.s === 403 && r.j.error === 'family_locked', r);
r = await api(K, 'POST', '/chatt/contacts/remove', { username: 'Pappa' }); koll('barnet kan inte ta bort föräldern', r.s === 403, r);
await api(P, 'POST', '/chatt/contacts/request', { username: 'Sven' }); await api(S, 'POST', '/chatt/contacts/accept', { username: 'Pappa' });
const kid = (b) => String(db.prepare('SELECT user_id FROM chatt_barn WHERE barn_id=?').get(b.barnId).user_id);
const env = 'RU5W';
r = await api(P, 'POST', '/chatt/groups/create', { name_enc: 'TkFNTg', members: [{ user_id: String(P.id), key_envelope: env }, { user_id: kid(K), key_envelope: env }, { user_id: String(S.id), key_envelope: env }] });
koll('grupp med barn + främling stoppas', r.s === 403 && r.j.error === 'family_only', r);
r = await api(P, 'POST', '/chatt/groups/create', { name_enc: 'RkFNSUxK', members: [{ user_id: String(P.id), key_envelope: env }, { user_id: kid(K), key_envelope: env }, { user_id: kid(K2), key_envelope: env }] });
koll('familjegrupp skapas', r.s === 200 && r.j.id, r); const gid = r.j && r.j.id;
r = await api(P, 'POST', '/chatt/groups/members', { id: gid, user_id: String(S.id), key_envelope: env }); koll('främling kan inte läggas till i familjegruppen', r.s === 403 && r.j.error === 'family_only', r);
r = await api(S, 'POST', '/chatt/contacts/request', { username: 'Pappa' }); koll('vuxna kan fortfarande vara vänner', r.s === 200, r);
// Barnet tas bort → chattidentiteten försvinner
const kuid = kid(K);
db.prepare('PRAGMA foreign_keys=ON').run(); db.prepare('DELETE FROM barn WHERE id=?').run(K.barnId);
koll('borttaget barn: den dolda kontoraden är borta', !db.prepare('SELECT 1 FROM users WHERE id=?').get(kuid));
r = await api(K, 'GET', '/chatt/jag'); koll('borttaget barn kommer inte in', r.s === 401, r);
console.log(`\n${ok} ok, ${fel} fel`); process.exit(fel ? 1 : 0);
