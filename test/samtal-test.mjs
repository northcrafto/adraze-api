// Test av närvaro (online), samtalsringning och mejl om missat samtal i chatt.js (egen temp-databas, port 18497).
// Kör: node test/samtal-test.mjs   (rör aldrig adraze.db i repot)
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
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-samtal-test-'));

// Kopia av server.js med modulen inkopplad precis före http.createServer
let src = fs.readFileSync(path.join(REPO, 'server.js'), 'utf8');
if (!src.includes("require('./chatt.js')")) {
  const i = src.lastIndexOf('http.createServer(');
  if (i < 0) throw new Error('hittar inte http.createServer i server.js');
  src = src.slice(0, i) + "require('./chatt.js')({ rutt, q, db, fel, kravInloggad, begransad, now, sha, ipAv, crypto });\n" + src.slice(i);
}
fs.writeFileSync(path.join(tmp, 'server.js'), src);
for (const f of fs.readdirSync(REPO)) if (f.endsWith('.js') && f !== 'server.js') fs.copyFileSync(path.join(REPO, f), path.join(tmp, f));

const srv = spawn(process.execPath, [path.join(tmp, 'server.js')], {
  cwd: tmp, env: { ...process.env, PORT: String(PORT), MAIL_LOGG: '1', CHATT_HOTLISTOR: '0', BREVO_API_KEY: '', CLAMD_PORT: '1', CHATT_NYCKEL: crypto.randomBytes(32).toString('hex') }, stdio: ['ignore', 'pipe', 'pipe'],
});
let logg = '';
srv.stdout.on('data', (d) => { logg += d; });
srv.stderr.on('data', (d) => { logg += d; });
const stang = () => { try { srv.kill(); } catch {} try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} };
process.on('exit', stang);

for (let i = 0; i < 100 && !logg.includes('adraze-api på'); i++) await new Promise((r) => setTimeout(r, 50));
if (!logg.includes('adraze-api på')) { console.error(logg); throw new Error('servern startade inte'); }

const db = new DatabaseSync(path.join(tmp, 'adraze.db'));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
function nyAnvandare(email) {
  const id = Number(db.prepare('INSERT INTO users(email,verified,created_at) VALUES(?,1,?)').run(email, Date.now()).lastInsertRowid);
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(token), id, Date.now() + 86_400_000);
  return { id, token, ip: `10.9.${id}.1` };
}

async function api(vem, metod, p, kropp) {
  const r = await fetch(BAS + p, { method: metod,
    headers: { ...(vem ? { authorization: 'Bearer ' + vem.token, 'cf-connecting-ip': vem.ip } : {}), ...(kropp ? { 'content-type': 'application/json' } : {}) },
    body: kropp ? JSON.stringify(kropp) : undefined });
  let j = null; try { j = await r.json(); } catch {}
  return { s: r.status, j };
}

let ok = 0, fel = 0;
function koll(namn, villkor, info) {
  if (villkor) { ok++; console.log('  ok  ', namn); }
  else { fel++; console.log('  FEL ', namn, info !== undefined ? JSON.stringify(info).slice(0, 300) : ''); }
}
const b64 = (n, c = 'A') => c.repeat(n);
const hash = (s) => crypto.createHash('sha256').update(s).digest('base64');


const reg = async (vem, namn) => (await api(vem, 'POST', '/chatt/registrera', { username: namn, login_hash: hash(namn), public_key: 'PK' + namn, enc_priv: 'EP' + namn })).s;
const A = nyAnvandare('a@test.se'), B = nyAnvandare('b@test.se'), C = nyAnvandare('c@test.se');
let r;
koll('tre profiler', (await reg(A, 'Alfa')) === 200 && (await reg(B, 'Beta')) === 200 && (await reg(C, 'Gamma')) === 200);
await api(A, 'POST', '/chatt/contacts/request', { username: 'Beta' });
await api(B, 'POST', '/chatt/contacts/accept', { username: 'Alfa' });

console.log('Närvaro');
r = await api(A, 'GET', '/chatt/contacts');
let beta = r.j.contacts.find((c) => c.username === 'Beta');
koll('kontakt aktiv nyss → online:true', beta && beta.online === true && beta.last_seen > 0 && beta.last_seen % 300_000 === 0, beta);
db.prepare('UPDATE chatt_profiler SET last_seen=? WHERE user_id=?').run(Date.now() - 10 * 60_000, B.id);
r = await api(A, 'GET', '/chatt/contacts'); beta = r.j.contacts.find((c) => c.username === 'Beta');
koll('inaktiv 10 min → online:false', beta.online === false, beta);
koll('inga andra nya fält i kontaktlistan', Object.keys(beta).sort().join() === 'avatar,bubble,id,last_seen,online,username', Object.keys(beta));
r = await api(A, 'GET', '/chatt/users/privacy'); koll('privacy har presence och call_mail på som standard', r.j.privacy.presence === true && r.j.privacy.call_mail === true, r.j);
r = await api(B, 'POST', '/chatt/users/privacy', { presence: false }); koll('Beta döljer sin närvaro', r.j.privacy.presence === false);
r = await api(A, 'GET', '/chatt/contacts'); beta = r.j.contacts.find((c) => c.username === 'Beta');
koll('dold närvaro → online:null, last_seen:null', beta.online === null && beta.last_seen === null, beta);
r = await api(B, 'GET', '/chatt/contacts'); const alfa = r.j.contacts.find((c) => c.username === 'Alfa');
koll('den som döljer sin ser inte heller andras', alfa.online === null, alfa);
await api(B, 'POST', '/chatt/users/privacy', { presence: true });
// grupp: Gamma är inte kontakt med Alfa → ingen närvaro för Gamma
await api(B, 'POST', '/chatt/contacts/request', { username: 'Gamma' }); await api(C, 'POST', '/chatt/contacts/accept', { username: 'Beta' });
r = await api(B, 'POST', '/chatt/groups/create', { name_enc: 'TkFNTg==', members: [{ user_id: String(B.id), key_envelope: 'RU5W' }, { user_id: String(A.id), key_envelope: 'RU5W' }, { user_id: String(C.id), key_envelope: 'RU5W' }] });
const gid = r.j.id;
r = await api(A, 'GET', '/chatt/groups/members?id=' + gid);
const gm = Object.fromEntries(r.j.members.map((m) => [m.username, m]));
koll('gruppmedlem som är kontakt får närvaro', gm.Beta.online === true, gm.Beta);
koll('gruppmedlem som inte är kontakt får ingen närvaro', gm.Gamma.online === null && gm.Gamma.last_seen === null, gm.Gamma);

console.log('Samtal');
const cid = () => crypto.randomBytes(12).toString('base64url');
r = await api(A, 'POST', '/chatt/samtal/ring', { to_id: String(C.id), call_id: cid() }); koll('ringa icke-kontakt → 403', r.s === 403 && r.j.error === 'not_contacts', r);
r = await api(A, 'POST', '/chatt/samtal/ring', { to_id: String(B.id), call_id: 'kort' }); koll('ogiltigt samtals-id → 400', r.s === 400, r);
const s1 = cid();
r = await api(A, 'POST', '/chatt/samtal/ring', { to_id: String(B.id), call_id: s1 }); koll('ringa kontakt', r.s === 200 && r.j.call_id === s1 && r.j.ring_ms === 30000, r);
r = await api(B, 'GET', '/chatt/samtal'); koll('mottagaren ser ringningen (bara vem + id)', r.j.incoming.length === 1 && r.j.incoming[0].call_id === s1 && r.j.incoming[0].from_username === 'Alfa' && Object.keys(r.j.incoming[0]).sort().join() === 'call_id,from_id,from_username,ring_ms,started_at', r.j);
r = await api(C, 'GET', '/chatt/samtal'); koll('ingen annan ser den', r.j.incoming.length === 0);
r = await api(C, 'POST', '/chatt/samtal/svar', { call_id: s1, svar: 'svara' }); koll('annan kan inte svara → 404', r.s === 404);
r = await api(B, 'POST', '/chatt/samtal/svar', { call_id: s1, svar: 'svara' }); koll('svara', r.j.state === 'svarat', r);
r = await api(A, 'GET', '/chatt/samtal'); koll('uppringaren ser svarat', r.j.calls.find((c) => c.call_id === s1)?.state === 'svarat', r.j);
r = await api(B, 'GET', '/chatt/samtal'); koll('ringer inte längre hos mottagaren', r.j.incoming.length === 0);
r = await api(A, 'POST', '/chatt/samtal/avsluta', { call_id: s1 }); koll('lägga på', r.j.state === 'avslutat', r);
const s2 = cid(); await api(A, 'POST', '/chatt/samtal/ring', { to_id: String(B.id), call_id: s2 });
r = await api(B, 'POST', '/chatt/samtal/svar', { call_id: s2, svar: 'avboj' }); koll('avböja', r.j.state === 'avbojt', r);
koll('avböjt ger inget mejl', !logg.includes('försökte ringa dig'));
// Missat: uppringaren lägger på efter > 8 s ringning → mejl (loggat)
const s3 = cid(); await api(A, 'POST', '/chatt/samtal/ring', { to_id: String(B.id), call_id: s3 });
await new Promise((ok) => setTimeout(ok, 8300));
r = await api(A, 'POST', '/chatt/samtal/avsluta', { call_id: s3 }); koll('lägger på efter 8 s → missat', r.j.state === 'missat', r);
await new Promise((ok) => setTimeout(ok, 300));
koll('mejl om missat samtal (loggat) till b@test.se', /\[mejl loggat\] b@test\.se Alfa försökte ringa dig i AdRaze/.test(logg), logg.slice(-500));
const s4 = cid(); await api(A, 'POST', '/chatt/samtal/ring', { to_id: String(B.id), call_id: s4 });
await new Promise((ok) => setTimeout(ok, 8300));
await api(A, 'POST', '/chatt/samtal/avsluta', { call_id: s4 });
await new Promise((ok) => setTimeout(ok, 300));
koll('högst ett mejl per par och 30 min', (logg.match(/försökte ringa dig/g) || []).length === 1);
const s5 = cid(); await api(A, 'POST', '/chatt/samtal/ring', { to_id: String(B.id), call_id: s5 });
r = await api(A, 'POST', '/chatt/samtal/avsluta', { call_id: s5 }); koll('lägger på direkt → inte missat', r.j.state === 'avslutat', r);
// Mejl av: Gamma stänger av, Beta ringer (tidsgränsen 30 s → missat)
await api(C, 'POST', '/chatt/users/privacy', { call_mail: false });
const s6 = cid(); await api(B, 'POST', '/chatt/samtal/ring', { to_id: String(C.id), call_id: s6 });
console.log('  (väntar 31 s på tidsgränsen)');
await new Promise((ok) => setTimeout(ok, 31_500));
r = await api(B, 'GET', '/chatt/samtal'); koll('ingen svarar på 30 s → missat', r.j.calls.find((c) => c.call_id === s6)?.state === 'missat', r.j);
koll('mejl avstängt → inget mejl till Gamma', !/c@test\.se/.test(logg));
r = await api(B, 'POST', '/chatt/samtal/ring', { to_id: String(C.id), call_id: s6 }); koll('samma id igen → 409', r.s === 409, r);

// Olästa utan att läsa: klienten räknar själv bort kontrollposter och markerar de inledande som lästa
for (let i = 0; i < 3; i++) { await api(A, 'POST', '/chatt/messages/send', { to_id: String(B.id), ciphertext: b64(40, 'ABC'[i]) }); await new Promise((ok) => setTimeout(ok, 15)); }
r = await api(B, 'GET', '/chatt/messages/unread?with=' + A.id);
koll('unread: tre olästa med chiffertext', r.s === 200 && r.j.messages.length === 3 && r.j.total === 3 && r.j.messages[0].ciphertext.startsWith('A'), r.j);
r = await api(B, 'GET', '/chatt/messages/overview'); koll('unread: att titta läser inte', r.j.unread.find((u) => u.id === String(A.id))?.n === 3, r.j);
const mitten = (await api(B, 'GET', '/chatt/messages/unread?with=' + A.id)).j.messages[1].created_at;
r = await api(B, 'POST', '/chatt/messages/read', { with: String(A.id), until: mitten }); koll('read: markerar bara t.o.m. until', r.j.marked === 2, r);
r = await api(B, 'GET', '/chatt/messages/overview'); koll('read: en kvar oläst', r.j.unread.find((u) => u.id === String(A.id))?.n === 1, r.j);
r = await api(A, 'GET', '/chatt/messages?with=' + B.id); koll('read: avsändaren ser läst t.o.m. until', r.j.peer_read_until === mitten, r.j.peer_read_until);
r = await api(C, 'GET', '/chatt/messages/unread?with=' + A.id); koll('unread: bara kontakter', r.s === 403, r);
r = await api(B, 'POST', '/chatt/messages/read', { with: String(A.id), until: 'x' }); koll('read: fel indata → 400', r.s === 400, r);
// Grupp
r = await api(A, 'POST', '/chatt/groups/create', { name_enc: b64(40), members: [{ user_id: String(A.id), key_envelope: b64(60) }, { user_id: String(B.id), key_envelope: b64(60) }] });
const ugid = r.j && r.j.id; koll('grupp skapad', !!ugid, r);
for (let i = 0; i < 2; i++) { await api(A, 'POST', '/chatt/groups/messages', { id: ugid, ciphertext: b64(40, 'XY'[i]) }); await new Promise((ok) => setTimeout(ok, 15)); }
r = await api(B, 'GET', '/chatt/groups/messages/unread?id=' + encodeURIComponent(ugid));
koll('grupp unread: två olästa', r.s === 200 && r.j.messages.length === 2 && r.j.total === 2 && r.j.messages[0].sender_username, r.j);
const g1 = r.j.messages[0].created_at;
r = await api(B, 'POST', '/chatt/groups/read', { id: ugid, until: g1 }); koll('grupp read: markerar', r.j.marked === 1, r);
r = await api(B, 'GET', '/chatt/groups'); koll('grupp read: en kvar oläst', r.j.groups.find((g) => g.id === ugid)?.unread === 1, r.j);
r = await api(C, 'GET', '/chatt/groups/messages/unread?id=' + encodeURIComponent(ugid)); koll('grupp unread: bara medlemmar', r.s === 403, r);

console.log(`\n${ok} ok, ${fel} fel`);
if (fel) console.log('--- serverlogg ---\n' + logg.slice(-3000));
stang();
process.exit(fel ? 1 : 0);
