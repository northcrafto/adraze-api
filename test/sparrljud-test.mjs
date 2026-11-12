// Spärrljud: föräldern väljer ett ljud per barn, barnet får det med sina regler. Kör: node test/sparrljud-test.mjs

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
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-sparrljud-'));
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

const P = vuxen('mamma@test.se'), A = vuxen('annan@test.se');
const K = barn(P, 'Kalle');
let r;
r = await api(K, 'POST', '/barn/jag', {}); koll('av från början', r.j.sparrljud && r.j.sparrljud.id === '' && r.j.sparrljud.volym === 60, r.j);
r = await api(P, 'POST', '/familj/sparrljud', { barn_id: K.barnId, ljud: 'stotar', volym: 50 }); koll('föräldern väljer ljud', r.s === 200 && r.j.sparrljud.id === 'stotar' && r.j.sparrljud.volym === 50, r);
r = await api(K, 'POST', '/barn/jag', {}); koll('barnet får ljudet', r.j.sparrljud.id === 'stotar' && r.j.sparrljud.volym === 50, r.j);
r = await api(P, 'POST', '/familj/lista', {}); koll('föräldern ser valet i listan', r.j.barn[0].sparrljud.id === 'stotar', r.j);
r = await api(P, 'POST', '/familj/sparrljud', { barn_id: K.barnId, ljud: 'kort', volym: 500 }); koll('volymen har tak (80)', r.j.sparrljud.volym === 80, r);
r = await api(P, 'POST', '/familj/sparrljud', { barn_id: K.barnId, ljud: '../../etc/passwd' }); koll('okänt ljud nekas', r.s === 400, r);
r = await api(A, 'POST', '/familj/sparrljud', { barn_id: K.barnId, ljud: '' }); koll('annan vuxen kan inte ändra', r.s === 403, r);
r = await api(K, 'POST', '/familj/sparrljud', { barn_id: K.barnId, ljud: '' }); koll('barnet kan inte stänga av själv', r.s === 401, r);
r = await api(P, 'POST', '/familj/sparrljud', { barn_id: K.barnId, ljud: '' }); koll('föräldern stänger av', r.j.sparrljud.id === '', r);
console.log(`\n${ok} ok, ${fel} fel`); process.exit(fel ? 1 : 0);
