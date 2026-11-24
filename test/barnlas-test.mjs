// Barnlås: föräldern låser webbläsaren till barnet, glömt lösenord ger en kod till föräldern.
// Tillfällig kopia av adraze-api med egen temp-databas. Kör: node test/barnlas-test.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.TEST_PORT || 18497);
const BAS = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-las-'));
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
async function api(vem, p, kropp) {
  const h = { 'content-type': 'application/json', 'x-forwarded-for': (vem && vem.ip) || '10.9.9.9' };
  if (vem && vem.token) h.authorization = 'Bearer ' + vem.token;
  const r = await fetch(BAS + p, { method: 'POST', headers: h, body: JSON.stringify(kropp || {}) });
  return { status: r.status, ...(await r.json().catch(() => ({}))) };
}
let ok = 0, fel = 0;
const koll = (namn, v) => { if (v) { ok++; console.log('  ok  ' + namn); } else { fel++; console.log('  FEL ' + namn); } };
const kodUrLogg = () => { const m = [...logg.matchAll(/\[mejl loggat\] (\S+) (\d{6}) /g)]; return m.length ? m[m.length - 1][2] : null; };

const mamma = vuxen('mamma@test.se'), annan = vuxen('annan@test.se');
const alva = barn(mamma, 'Alva');

let r = await api(annan, '/familj/las', { barn_id: alva.barnId });
koll('en annan vuxen kan inte låsa till någon annans barn', r.status === 403);
r = await api({ ip: '10.1.1.1' }, '/familj/las', { barn_id: alva.barnId });
koll('utloggad kan inte låsa', r.status === 401);
r = await api(mamma, '/familj/las', { barn_id: alva.barnId });
koll('föräldern låser: barnsession + märkning', r.ok && r.token && r.las && r.barn && r.barn.id === alva.barnId);
const las = r.las, barnTok = r.token;
r = await api({ token: barnTok, ip: '10.2.2.2' }, '/barn/jag');
koll('barnsessionen från låset fungerar', r.ok && r.namn === 'Alva');
koll('märkningen sparas bara som hash', !db.prepare('SELECT 1 FROM barn_las WHERE token=?').get(las) && !!db.prepare('SELECT 1 FROM barn_las WHERE token=?').get(sha(las)));

r = await api({ ip: '10.3.3.3' }, '/barn/las-verifiera', { las, kod: '123456' });
koll('ingen kod begärd → kan inte verifiera', r.status === 410);
r = await api({ ip: '10.3.3.3' }, '/barn/las-kod', { las: 'x'.repeat(43) });
koll('okänd märkning → 404', r.status === 404);
r = await api({ ip: '10.3.3.3' }, '/barn/las-kod', { las });
await new Promise((x) => setTimeout(x, 300));
const kod = kodUrLogg();
koll('kod mejlas till föräldern', r.ok && r.skickad && !!kod && /mamma@test\.se/.test(logg));
r = await api({ ip: '10.3.3.3' }, '/barn/las-kod', { las });
koll('ny begäran inom 45 s skickar inget nytt mejl', r.ok && kodUrLogg() === kod);
const felKod = kod === '000000' ? '111111' : '000000';
r = await api({ ip: '10.3.3.3' }, '/barn/las-verifiera', { las, kod: felKod });
koll('fel kod nekas', r.status === 400);
r = await api({ ip: '10.3.3.3' }, '/barn/las-verifiera', { las, kod });
koll('rätt kod godkänns', r.ok && r.godkand === true);
r = await api({ ip: '10.3.3.3' }, '/barn/las-verifiera', { las, kod });
koll('koden fungerar bara en gång', r.status === 410);

// sex fel försök spärrar koden
db.prepare('UPDATE barn_las SET kod_sent=0 WHERE token=?').run(sha(las));
await api({ ip: '10.4.4.4' }, '/barn/las-kod', { las });
await new Promise((x) => setTimeout(x, 300));
const kod2 = kodUrLogg();
for (let i = 0; i < 6; i++) await api({ ip: '10.4.4.4' }, '/barn/las-verifiera', { las, kod: kod2 === '999999' ? '888888' : '999999' });
r = await api({ ip: '10.4.4.4' }, '/barn/las-verifiera', { las, kod: kod2 });
koll('efter sex fel försök nekas även rätt kod', r.status === 429);

r = await api({ ip: '10.5.5.5' }, '/barn/las-bort', { las });
koll('märkningen tas bort vid upplåsning', r.ok && !db.prepare('SELECT 1 FROM barn_las WHERE token=?').get(sha(las)));
r = await api({ ip: '10.5.5.5' }, '/barn/las-kod', { las });
koll('borttagen märkning ger ingen ny kod', r.status === 404);

console.log(`\n${ok} ok, ${fel} fel`);
process.exit(fel ? 1 : 0);
