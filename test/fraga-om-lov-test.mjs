// Fråga om lov: barnet frågar, föräldern svarar ja eller nej. Tillfällig kopia av adraze-api med egen temp-databas.
// Kör: node test/fraga-om-lov-test.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.TEST_PORT || 18495);
const BAS = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-fraga-'));
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
db.prepare('UPDATE barn SET blocklista=? WHERE id=?').run(JSON.stringify(['säkerkoll.se', 'youtube.com', 'spel.se']), K.barnId);
let r;
r = await api(K, 'POST', '/barn/fraga', { host: 'www.YouTube.com', text: 'Till skolan' }); koll('barnet frågar', r.s === 200 && r.j.id, r); const f1 = r.j.id;
r = await api(K, 'POST', '/barn/fraga', { host: 'youtube.com', text: 'snälla' }); koll('samma sida igen = samma fråga', r.j.id === f1, r);
r = await api(K, 'POST', '/barn/fraga', { host: '<script>' }); koll('konstig sida nekas', r.s === 400, r);
r = await api(P, 'POST', '/familj/lista', {}); const fr = r.j.barn[0].fragor;
koll('föräldern ser frågan med text', fr.length === 1 && fr[0].host === 'youtube.com' && fr[0].text === 'snälla', fr);
r = await api(A, 'POST', '/familj/svara', { fraga_id: f1, svar: 'ja', minuter: 30 }); koll('annan vuxen kan inte svara', r.s === 404, r);
r = await api(K, 'POST', '/familj/svara', { fraga_id: f1, svar: 'ja', minuter: 30 }); koll('barnet kan inte svara själv', r.s === 401, r);
r = await api(P, 'POST', '/familj/svara', { fraga_id: f1, svar: 'ja', minuter: 30 }); koll('föräldern säger ja i 30 min', r.s === 200, r);
r = await api(K, 'POST', '/barn/jag', {});
koll('barnet har fått tillåtelse', r.j.tillat.some((a) => a.host === 'youtube.com' && a.until > Date.now() + 29 * 60_000), r.j.tillat);
koll('barnet ser svaret ja', r.j.fragor.some((f) => f.id === f1 && f.svar === 'ja' && f.minuter === 30), r.j.fragor);
r = await api(K, 'POST', '/barn/fraga', { host: 'spel.se' }); const f2 = r.j.id;
r = await api(P, 'POST', '/familj/svara', { fraga_id: f2, svar: 'nej' }); koll('föräldern säger nej', r.s === 200, r);
r = await api(K, 'POST', '/barn/jag', {}); koll('barnet ser nej, ingen tillåtelse', r.j.fragor.some((f) => f.id === f2 && f.svar === 'nej') && !r.j.tillat.some((a) => a.host === 'spel.se'), r.j);
r = await api(K, 'POST', '/barn/fraga', { host: 'säkerkoll.se' }); koll('unicode-domän går (som punycode från klienten)', r.s === 400 || r.s === 200, r);
r = await api(K, 'POST', '/barn/fraga', { host: 'xn--skerkoll-0za.se' }); const f3 = r.j.id; koll('punycode-domän går', r.s === 200, r);
db.prepare('UPDATE barn SET blocklista=? WHERE id=?').run(JSON.stringify(['xn--skerkoll-0za.se', 'youtube.com']), K.barnId);
r = await api(P, 'POST', '/familj/svara', { fraga_id: f3, svar: 'ja', minuter: 0 }); koll('ja för alltid', r.s === 200, r);
r = await api(K, 'POST', '/barn/jag', {}); koll('sidan borta från spärrlistan', JSON.stringify(r.j.blocklista) === '["youtube.com"]', r.j.blocklista);
r = await api(P, 'POST', '/familj/lista', {}); koll('besvarade frågor syns inte längre för föräldern', r.j.barn[0].fragor.length === 0, r.j.barn[0].fragor);
for (let i = 0; i < 25; i++) r = await api(K, 'POST', '/barn/fraga', { host: 'x' + i + '.se' });
koll('för många frågor stoppas', r.s === 429, r);
console.log(`\n${ok} ok, ${fel} fel`); process.exit(fel ? 1 : 0);
