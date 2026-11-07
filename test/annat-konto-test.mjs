// Annat konto på barnets dator: föräldern får mejl. Tillfällig kopia av adraze-api med egen temp-databas.
// Kör: node test/familj-chatt-test.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.TEST_PORT || 18496);
const BAS = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-annat-'));
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

const P = vuxen('mamma@test.se'), A = vuxen('kalle.egen@test.se');
const K = barn(P, 'Kalle');
let r;
r = await api(K, 'POST', '/barn/enhet', {}); koll('barnet får en enhetsmärkning', r.s === 200 && r.j.enhet, r); const enhet = r.j.enhet;
const mejl = () => (logg.match(/\[mejl loggat\][^\n]*/g) || []);
const fore = mejl().length;
r = await api(P, 'POST', '/barn/annat-konto', { enhet }); koll('föräldern själv: inget mejl', r.j.foralder === true, r);
await new Promise((x) => setTimeout(x, 200)); koll('inget mejl skickat för föräldern', mejl().length === fore, mejl());
r = await api(A, 'POST', '/barn/annat-konto', { enhet }); koll('annat konto: föräldern meddelas', r.s === 200 && r.j.foralder === false, r);
await new Promise((x) => setTimeout(x, 200)); const m = mejl();
koll('mejlet gick till mamma', m.length === fore + 1 && m[m.length - 1].includes('mamma@test.se') && m[m.length - 1].includes('Kalle'), m);
r = await api(A, 'POST', '/barn/annat-konto', { enhet }); await new Promise((x) => setTimeout(x, 200));
koll('samma konto igen: inget nytt mejl inom 6 h', mejl().length === fore + 1, mejl());
r = await api({ token: 'x', ip: '10.9.9.9' }, 'POST', '/barn/annat-konto', { enhet: 'fel' }); koll('okänd märkning: inget', r.j.kand === false, r);
r = await api(A, 'POST', '/barn/enhet', {}); koll('vuxen kan inte skapa barnmärkning', r.s === 401, r);
console.log(`\n${ok} ok, ${fel} fel`); process.exit(fel ? 1 : 0);
