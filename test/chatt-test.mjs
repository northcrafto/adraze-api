// Test av chatt.js mot en tillfällig kopia av adraze-api (egen temp-databas, port 18493).
// Kör: node test/chatt-test.mjs   (rör aldrig adraze.db i repot)
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.TEST_PORT || 18493);
const BAS = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-chatt-test-'));

// Kopia av server.js med modulen inkopplad precis före http.createServer
let src = fs.readFileSync(path.join(REPO, 'server.js'), 'utf8');
if (!src.includes("require('./chatt.js')")) {
  const i = src.lastIndexOf('http.createServer(');
  if (i < 0) throw new Error('hittar inte http.createServer i server.js');
  src = src.slice(0, i) + "require('./chatt.js')({ rutt, q, db, fel, kravInloggad, begransad, now, sha, ipAv, crypto });\n" + src.slice(i);
}
fs.writeFileSync(path.join(tmp, 'server.js'), src);
fs.copyFileSync(path.join(REPO, 'chatt.js'), path.join(tmp, 'chatt.js'));

const srv = spawn(process.execPath, [path.join(tmp, 'server.js')], {
  cwd: tmp, env: { ...process.env, PORT: String(PORT), MAIL_LOGG: '1', CHATT_HOTLISTOR: '0', BREVO_API_KEY: '', CLAMD_PORT: '1' }, stdio: ['ignore', 'pipe', 'pipe'],
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

const A = nyAnvandare('a@test.se'), B = nyAnvandare('b@test.se'), C = nyAnvandare('c@test.se');
let r;

console.log('Profil');
r = await api(null, 'GET', '/chatt/jag'); koll('utan inloggning → 401', r.s === 401, r);
r = await api(A, 'GET', '/chatt/jag'); koll('ingen profil → profil:null', r.s === 200 && r.j.profil === null, r);
r = await api(A, 'GET', '/chatt/contacts'); koll('chatt utan profil → 403 no_profile', r.s === 403 && r.j.error === 'no_profile', r);
r = await api(A, 'POST', '/chatt/registrera', { username: 'a!', login_hash: hash('a'), public_key: 'PKa', enc_priv: 'EPa' }); koll('ogiltigt namn → 400 invalid_username', r.s === 400 && r.j.error === 'invalid_username' && r.j.message, r);
r = await api(A, 'POST', '/chatt/registrera', { username: 'Alfa', login_hash: hash('a'), public_key: 'PKa', enc_priv: 'EPa' }); koll('registrera Alfa', r.s === 200 && r.j.ok && r.j.id === String(A.id) && r.j.username === 'Alfa', r);
r = await api(B, 'POST', '/chatt/registrera', { username: 'alfa', login_hash: hash('b'), public_key: 'PKb', enc_priv: 'EPb' }); koll('upptaget namn (versalokänsligt) → 409', r.s === 409 && r.j.error === 'username_taken', r);
r = await api(B, 'POST', '/chatt/registrera', { username: 'Beta', login_hash: hash('b'), public_key: 'PKb', enc_priv: 'EPb', salt: 'c2FsdA==', rec_auth: 'cmVjYg==', rec_blob: 'YmxvYg==' }); koll('registrera Beta med räddning', r.s === 200 && r.j.has_recovery === true, r);
r = await api(C, 'POST', '/chatt/registrera', { username: 'Gamma', login_hash: hash('c'), public_key: 'PKc', enc_priv: 'EPc' }); koll('registrera Gamma', r.s === 200, r);
r = await api(A, 'POST', '/chatt/registrera', { username: 'Alfa2', login_hash: hash('a'), public_key: 'PKa', enc_priv: 'EPa' }); koll('andra profil → 409 already_registered', r.s === 409, r);
db.prepare('UPDATE users SET avatar=? WHERE id=?').run('data:image/jpeg;base64,/9j/AAAA', A.id);
r = await api(A, 'GET', '/chatt/jag'); koll('jag: profil + avatar + public_key', r.j.profil === true && r.j.username === 'Alfa' && r.j.avatar === 'data:image/jpeg;base64,/9j/AAAA' && r.j.public_key === 'PKa' && r.j.has_recovery === false, r);
r = await api(A, 'GET', '/chatt/users/me'); koll('users/me', r.s === 200 && r.j.id === String(A.id) && r.j.has_account === false, r);
r = await api(A, 'POST', '/chatt/users/login', { login_hash: hash('fel') }); koll('lås upp med fel kod → 401 invalid_login', r.s === 401 && r.j.error === 'invalid_login', r);
r = await api(A, 'POST', '/chatt/users/login', { username: 'Alfa', login_hash: hash('a') }); koll('lås upp nycklar → enc_priv', r.s === 200 && r.j.enc_priv === 'EPa', r);
r = await api(A, 'POST', '/chatt/users/verify-code', { login_hash: hash('a') }); koll('verify-code', r.j.enc_priv === 'EPa', r);
r = await api(A, 'POST', '/chatt/users/verify-code', { login_hash: hash('x') }); koll('verify-code fel → 403 wrong_code', r.s === 403 && r.j.error === 'wrong_code', r);
r = await api(A, 'POST', '/chatt/users/bio', { bio: '  Hej  ' }); koll('bio', r.j.bio === 'Hej', r);
r = await api(A, 'POST', '/chatt/users/bubble', { color: '#FF0000', frame: 'katt' }); koll('bubbla', r.j.bubble.color === '#ff0000' && r.j.bubble.frame === 'katt', r);
r = await api(A, 'POST', '/chatt/users/bubble', { frame: 'hund' }); koll('ogiltig bubbla → 400', r.s === 400, r);
r = await api(A, 'GET', '/chatt/users/privacy'); koll('privacy standard', r.j.privacy.read_receipts === true && r.j.privacy.requests === 'all', r);

console.log('Uppslag och nyckel');
r = await api(A, 'GET', '/chatt/users/lookup?username=beta'); koll('lookup Beta', r.j.exists && r.j.id === String(B.id) && r.j.public_key === 'PKb', r);
r = await api(A, 'GET', '/chatt/users/lookup?username=finnsinte'); koll('lookup okänd → exists:false', r.s === 200 && r.j.exists === false, r);
r = await api(A, 'GET', `/chatt/users/key?id=${B.id}`); koll('key utan kontakt → 403 not_contacts', r.s === 403 && r.j.error === 'not_contacts', r);
r = await api(A, 'GET', `/chatt/users/key?id=${A.id}`); koll('egen key', r.s === 200 && r.j.public_key === 'PKa', r);

console.log('Vänförfrågan');
r = await api(A, 'POST', '/chatt/contacts/request', { username: 'Beta' }); koll('förfrågan → pending', r.j.status === 'pending', r);
r = await api(B, 'GET', '/chatt/contacts'); koll('Beta ser inkommande', r.j.incoming.length === 1 && r.j.incoming[0].username === 'Alfa' && r.j.incoming[0].avatar, r);
r = await api(A, 'POST', '/chatt/messages/send', { to_id: String(B.id), ciphertext: 'Y2lwaGVy' }); koll('DM före accept → 403', r.s === 403 && r.j.error === 'not_contacts', r);
r = await api(B, 'POST', '/chatt/contacts/accept', { username: 'alfa' }); koll('accept', r.s === 200, r);
r = await api(A, 'GET', '/chatt/contacts'); koll('kontaktlista med bubbla/avatar', r.j.contacts.length === 1 && r.j.contacts[0].id === String(B.id), r);
r = await api(A, 'GET', `/chatt/users/key?id=${B.id}`); koll('key efter accept', r.s === 200 && r.j.public_key === 'PKb', r);
r = await api(A, 'GET', `/chatt/users/profile?id=${B.id}`); koll('profil Beta', r.s === 200 && r.j.friends === 1 && r.j.is_self === false && r.j.pro === false, r);
r = await api(C, 'GET', `/chatt/users/profile?id=${A.id}`); koll('Gamma ser inte Alfas profil', r.s === 403, r);
await api(B, 'POST', '/chatt/users/privacy', { requests: 'none' });
r = await api(C, 'POST', '/chatt/contacts/request', { username: 'Beta' }); koll('requests:none → 403 requests_closed', r.s === 403 && r.j.error === 'requests_closed', r);
await api(B, 'POST', '/chatt/users/privacy', { requests: 'all' });
r = await api(C, 'POST', '/chatt/contacts/request', { username: 'Alfa' }); koll('Gamma → Alfa pending', r.j.status === 'pending', r);
r = await api(A, 'POST', '/chatt/contacts/request', { username: 'Gamma' }); koll('ömsesidig förfrågan → accepted', r.j.status === 'accepted', r);

console.log('DM');
const t0 = Date.now() - 1;
r = await api(A, 'POST', '/chatt/messages/send', { to_id: String(B.id), ciphertext: 'aGVq' }); koll('skicka DM', r.s === 200 && typeof r.j.id === 'number', r);
const m1 = r.j.id;
r = await api(A, 'POST', '/chatt/messages/send', { to_id: String(B.id), ciphertext: b64(16 * 1024 + 1) }); koll('för stort meddelande → 400', r.s === 400 && r.j.error === 'invalid_input', r);
r = await api(A, 'POST', '/chatt/messages/send', { to_id: String(B.id), ciphertext: b64(16 * 1024) }); koll('16 kB-meddelande går igenom kroppsgränsen', r.s === 200, r);
r = await api(C, 'GET', `/chatt/messages?with=${B.id}`); koll('Gamma kan inte läsa A↔B', r.s === 403, r);
r = await api(B, 'GET', '/chatt/messages/overview'); koll('overview: 2 olästa från Alfa', r.j.unread.length === 1 && r.j.unread[0].id === String(A.id) && r.j.unread[0].n === 2, r);
r = await api(A, 'POST', '/chatt/messages/typing', { to_id: String(B.id) }); koll('typing-ping', r.s === 200, r);
r = await api(B, 'GET', `/chatt/messages?with=${A.id}&since=${t0}`); koll('Beta hämtar: 2 meddelanden + typing', r.j.messages.length === 2 && r.j.messages[0].ciphertext === 'aGVq' && r.j.messages[0].mine === false && r.j.typing === true && r.j.server_time > 0, r);
const sync = r.j.server_time;
r = await api(A, 'GET', `/chatt/messages?with=${B.id}`); koll('läskvitto syns för Alfa', r.j.peer_read_until > 0 && r.j.peer_read_at > 0, r);
await api(B, 'POST', '/chatt/users/privacy', { read_receipts: false });
r = await api(A, 'GET', `/chatt/messages?with=${B.id}`); koll('läskvitton av → 0', r.j.peer_read_until === 0, r);
await api(B, 'POST', '/chatt/users/privacy', { read_receipts: true });
await new Promise((x) => setTimeout(x, 5));
r = await api(B, 'POST', '/chatt/messages/edit', { id: m1, ciphertext: 'Zm9v' }); koll('redigera annans → 403 not_sender', r.s === 403 && r.j.error === 'not_sender', r);
r = await api(A, 'POST', '/chatt/messages/edit', { id: m1, ciphertext: 'cmVkaWdlcmFk' }); koll('redigera eget', r.s === 200, r);
r = await api(B, 'GET', `/chatt/messages?with=${A.id}&since=${Date.now()}&changed_since=${sync}`); koll('changed_since ger redigeringen', r.j.messages.length === 0 && r.j.changes.some((c) => c.id === m1 && c.edited && c.ciphertext === 'cmVkaWdlcmFk'), r);
r = await api(C, 'POST', '/chatt/messages/hide', { id: m1 }); koll('hide för utomstående → 403', r.s === 403 && r.j.error === 'not_participant', r);
r = await api(B, 'POST', '/chatt/messages/hide', { id: m1 }); koll('dölj för mig', r.s === 200, r);
r = await api(B, 'GET', `/chatt/messages?with=${A.id}`); koll('dolt meddelande syns inte för Beta', !r.j.messages.some((m) => m.id === m1), r);
r = await api(A, 'GET', `/chatt/messages?with=${B.id}`); koll('men syns för Alfa', r.j.messages.some((m) => m.id === m1), r);
r = await api(A, 'POST', '/chatt/messages/delete', { id: m1 }); koll('ta bort för alla', r.s === 200, r);
r = await api(A, 'GET', `/chatt/messages?with=${B.id}`); koll('borttaget: tom chiffertext', r.j.messages.find((m) => m.id === m1)?.deleted === true && r.j.messages.find((m) => m.id === m1).ciphertext === '', r);

console.log('Bilagor');
const bild = b64(2_000_000, 'Q');
r = await api(A, 'POST', '/chatt/messages/attachment', { to_id: String(B.id), ciphertext: bild }); koll('ladda upp 2 MB-bilaga', r.s === 200 && /^[a-f0-9]{32}$/.test(r.j.id), r);
const att = r.j.id;
r = await api(A, 'POST', '/chatt/messages/attachment', { to_id: String(B.id), ciphertext: b64(2_200_001) }); koll('för stor bilaga → 400', r.s === 400, r);
r = await api(C, 'POST', '/chatt/messages/attachment', { to_id: String(B.id), ciphertext: 'QQ==' }); koll('bilaga till icke-kontakt → 403', r.s === 403, r);
r = await api(A, 'POST', '/chatt/messages/send', { to_id: String(B.id), ciphertext: 'YmlsZA==', attachment_id: att }); koll('skicka med bilaga', r.s === 200, r);
const mAtt = r.j.id;
r = await api(A, 'POST', '/chatt/messages/send', { to_id: String(B.id), ciphertext: 'YmlsZA==', attachment_id: att }); koll('samma bilaga två gånger → 400 bad_attachment', r.s === 400 && r.j.error === 'bad_attachment', r);
r = await api(B, 'GET', `/chatt/messages/attachment?id=${att}`); koll('mottagaren hämtar bilagan', r.s === 200 && r.j.ciphertext.length === bild.length, r?.s);
r = await api(C, 'GET', `/chatt/messages/attachment?id=${att}`); koll('tredje person nekas bilagan → 403', r.s === 403 && r.j.error === 'forbidden', r);
await api(A, 'POST', '/chatt/messages/delete', { id: mAtt });
r = await api(B, 'GET', `/chatt/messages/attachment?id=${att}`); koll('bilagan borta efter radering → 404', r.s === 404, r);
r = await fetch(BAS + '/chatt/messages/send', { method: 'POST', headers: { authorization: 'Bearer ' + A.token, 'content-type': 'application/json' }, body: JSON.stringify({ to_id: String(B.id), ciphertext: b64(100_000) }) });
koll('stor kropp på vanlig rutt → 413', r.status === 413);

console.log('Stickers');
r = await api(A, 'POST', '/chatt/stickers', { ciphertext: b64(800_000, 'S') }); koll('spara sticker 800 kB', r.s === 200 && r.j.id, r);
const st = r.j.id;
r = await api(A, 'GET', '/chatt/stickers'); koll('lista stickers', r.j.stickers.length === 1 && r.j.max === 120, r);
r = await api(A, 'GET', `/chatt/stickers?id=${st}`); koll('hämta sticker', r.j.ciphertext?.length === 800_000, r?.s);
r = await api(B, 'GET', `/chatt/stickers?id=${st}`); koll('annans sticker → 404', r.s === 404, r);
r = await api(A, 'POST', '/chatt/stickers/delete', { id: st });
r = await api(A, 'GET', '/chatt/stickers'); koll('sticker borttagen', r.j.stickers.length === 0, r);

console.log('Grupper');
r = await api(A, 'POST', '/chatt/groups/create', { name_enc: 'bmFtbg==', members: [{ user_id: String(A.id), key_envelope: 'a2E=' }, { user_id: String(B.id), key_envelope: 'a2I=' }] });
koll('skapa grupp A+B', r.s === 200 && r.j.id, r);
const gid = r.j.id;
r = await api(B, 'POST', '/chatt/groups/create', { name_enc: 'bmFtbg==', members: [{ user_id: String(B.id), key_envelope: 'a2I=' }, { user_id: String(C.id), key_envelope: 'a2M=' }] });
koll('grupp med icke-kontakt → 403', r.s === 403 && r.j.error === 'not_contacts', r);
r = await api(B, 'GET', '/chatt/groups'); koll('Beta ser gruppen', r.j.groups.length === 1 && r.j.groups[0].owner_id === String(A.id) && r.j.groups[0].wrapped_by === String(A.id) && r.j.groups[0].member_count === 2, r);
r = await api(C, 'GET', `/chatt/groups/messages?id=${gid}`); koll('Gamma inte medlem → 403', r.s === 403 && r.j.error === 'not_member', r);
r = await api(A, 'POST', '/chatt/groups/members', { id: gid, user_id: String(C.id), key_envelope: 'a2M=' }); koll('Alfa lägger till Gamma', r.s === 200, r);
r = await api(C, 'POST', '/chatt/groups/messages', { id: gid, ciphertext: 'Z3J1cHA=' }); koll('Gamma skickar gruppmeddelande', r.s === 200 && r.j.id, r);
const gm = r.j.id;
r = await api(C, 'POST', '/chatt/messages/typing', { group_id: gid });
r = await api(A, 'GET', `/chatt/groups/messages?id=${gid}`); koll('Alfa läser gruppen + typing', r.j.messages.length === 1 && r.j.messages[0].sender_username === 'Gamma' && r.j.typing.includes('Gamma'), r);
r = await api(A, 'GET', `/chatt/groups/members?id=${gid}`); koll('medlemslista', r.j.members.length === 3 && r.j.owner_id === String(A.id), r);
r = await api(A, 'POST', '/chatt/groups/messages/edit', { gid, id: gm, ciphertext: 'eA==' }); koll('redigera annans gruppmeddelande → 403', r.s === 403 && r.j.error === 'not_sender', r);
r = await api(C, 'POST', '/chatt/groups/messages/edit', { gid, id: gm, ciphertext: 'ZWRpdA==' }); koll('redigera eget gruppmeddelande', r.s === 200, r);
r = await api(B, 'POST', '/chatt/groups/messages/hide', { gid, id: gm }); koll('dölj gruppmeddelande', r.s === 200, r);
r = await api(B, 'GET', `/chatt/groups/messages?id=${gid}`); koll('dolt för Beta', r.j.messages.length === 0, r);
const gatt = (await api(C, 'POST', '/chatt/messages/attachment', { group_id: gid, ciphertext: 'R1JQ' })).j.id;
r = await api(C, 'POST', '/chatt/groups/messages', { id: gid, ciphertext: 'Yg==', attachment_id: gatt }); koll('gruppmeddelande med bilaga', r.s === 200, r);
r = await api(B, 'GET', `/chatt/messages/attachment?id=${gatt}`); koll('medlem hämtar gruppbilaga', r.s === 200, r);
r = await api(B, 'POST', '/chatt/groups/rename', { id: gid, name_enc: 'bnk=' }); koll('icke-admin byter namn → 403 not_admin', r.s === 403 && r.j.error === 'not_admin', r);
r = await api(A, 'POST', '/chatt/groups/promote', { id: gid, user_id: String(B.id) }); koll('promote Beta', r.s === 200, r);
r = await api(B, 'POST', '/chatt/groups/rename', { id: gid, name_enc: 'bnk=' }); koll('admin byter namn', r.s === 200, r);
r = await api(B, 'POST', '/chatt/groups/avatar', { id: gid, avatar_enc: b64(150_000, 'G') }); koll('gruppbild 150 kB', r.s === 200, r);
r = await api(B, 'POST', '/chatt/groups/demote', { id: gid, user_id: String(A.id) }); koll('degradera ägaren → 403', r.s === 403 && r.j.error === 'cant_demote_owner', r);
r = await api(B, 'POST', '/chatt/groups/kick', { id: gid, user_id: String(A.id) }); koll('kicka ägaren → 403', r.s === 403 && r.j.error === 'cant_kick_owner', r);
r = await api(A, 'POST', '/chatt/groups/kick', { id: gid, user_id: String(C.id) }); koll('kicka Gamma', r.s === 200, r);
r = await api(C, 'GET', `/chatt/groups/messages?id=${gid}`); koll('kickad läser inte → 403', r.s === 403, r);
r = await api(C, 'GET', `/chatt/messages/attachment?id=${gatt}`); koll('kickad avsändare får fortf. sin egen bilaga', r.s === 200, r);
r = await api(C, 'POST', '/chatt/groups/messages', { id: gid, ciphertext: 'eA==' }); koll('kickad skickar inte → 403', r.s === 403, r);
r = await api(B, 'POST', '/chatt/groups/leave', { id: gid }); koll('Beta lämnar', r.s === 200, r);
r = await api(A, 'POST', '/chatt/groups/leave', { id: gid }); koll('Alfa lämnar (sista)', r.s === 200, r);
koll('tom grupp raderad', !db.prepare('SELECT 1 FROM chatt_grupper WHERE id=?').get(gid));
koll('gruppbilaga raderad med gruppen', !db.prepare('SELECT 1 FROM chatt_bilagor WHERE id=?').get(gatt));

console.log('Blockering');
r = await api(B, 'POST', '/chatt/contacts/block', { username: 'Alfa' }); koll('Beta blockerar Alfa', r.s === 200, r);
r = await api(A, 'POST', '/chatt/messages/send', { to_id: String(B.id), ciphertext: 'aGVq' }); koll('DM till den som blockerat → 403', r.s === 403, r);
r = await api(A, 'POST', '/chatt/contacts/request', { username: 'Beta' }); koll('ny förfrågan → 403 blocked', r.s === 403 && r.j.error === 'blocked', r);
r = await api(A, 'POST', '/chatt/messages/typing', { to_id: String(B.id) }); koll('typing till blockerare → 403', r.s === 403, r);
r = await api(A, 'GET', `/chatt/users/key?id=${B.id}`); koll('nyckel efter block → 403', r.s === 403, r);
r = await api(B, 'GET', '/chatt/contacts'); koll('blocked-lista', r.j.blocked.length === 1 && r.j.blocked[0].username === 'Alfa' && r.j.contacts.length === 0, r);

console.log('Rapport');
r = await api(B, 'POST', '/chatt/reports', { username: 'Alfa', reason: 'spam', message_id: String(m1), message_kind: 'dm', excerpt: 'köp nu' }); koll('rapportera (blockerad relation räcker)', r.s === 200, r);
r = await api(B, 'POST', '/chatt/reports', { username: 'Alfa', reason: 'spam', message_id: String(m1), message_kind: 'dm' }); koll('dubblett → duplicate:true', r.j.duplicate === true, r);
r = await api(B, 'POST', '/chatt/reports', { username: 'Alfa', reason: 'nej' }); koll('ogiltig anledning → 400', r.s === 400 && r.j.error === 'invalid_reason', r);
const D = nyAnvandare('d@test.se');
await api(D, 'POST', '/chatt/registrera', { username: 'Delta', login_hash: hash('d'), public_key: 'PKd', enc_priv: 'EPd' });
r = await api(D, 'POST', '/chatt/reports', { username: 'Alfa', reason: 'spam' }); koll('rapport utan relation → 403 no_relation', r.s === 403 && r.j.error === 'no_relation', r);
koll('rapport sparad i chatt_rapporter', db.prepare('SELECT COUNT(*) c FROM chatt_rapporter').get().c === 1);
r = await api(B, 'POST', '/chatt/contacts/unblock', { username: 'Alfa' }); koll('avblockera', r.s === 200, r);

console.log('Länkar');
r = await api(A, 'POST', '/chatt/links/check', { url: 'https://example.com/' }); koll('länkkoll ren', r.j.verdict === 'clean', r);
r = await api(A, 'POST', '/chatt/links/check', { url: 'javascript:alert(1)' }); koll('icke-webblänk → danger', r.j.verdict === 'danger', r);
r = await api(A, 'POST', '/chatt/links/preview', { url: 'http://127.0.0.1:' + PORT + '/health' }); koll('SSRF: localhost:port → unreachable', r.s === 200 && r.j.error === 'unreachable' && !r.j.title, r);
r = await api(A, 'POST', '/chatt/links/preview', { url: 'http://127.0.0.1/' }); koll('SSRF: 127.0.0.1 → unreachable', r.j.error === 'unreachable', r);
r = await api(A, 'POST', '/chatt/links/preview', { url: 'http://localhost/' }); koll('SSRF: localhost via DNS → unreachable', r.j.error === 'unreachable', r);
r = await api(A, 'POST', '/chatt/links/preview', { url: 'http://[::ffff:7f00:1]/' }); koll('SSRF: ::ffff:7f00:1 → unreachable', r.j.error === 'unreachable', r);
r = await api(A, 'POST', '/chatt/links/preview', { url: 'http://100.83.66.87/' }); koll('SSRF: tailnet → unreachable', r.j.error === 'unreachable', r);
r = await api(A, 'POST', '/chatt/links/preview', { url: 'ftp://x' }); koll('fel protokoll → 400 invalid_url', r.s === 400 && r.j.error === 'invalid_url', r);

console.log('Namnbyte och räddning');
r = await api(A, 'POST', '/chatt/users/rename', { new_username: 'Alfa_1', old_login_hash: hash('fel'), new_login_hash: hash('a1'), enc_priv: 'EPa1' }); koll('namnbyte med fel kod → 403', r.s === 403 && r.j.error === 'wrong_code', r);
let kod = 'a';
for (const [i, nytt] of ['Alfa_1', 'Alfa_2', 'Alfa_3'].entries()) {
  r = await api(A, 'POST', '/chatt/users/rename', { new_username: nytt, old_login_hash: hash(kod), new_login_hash: hash(nytt), enc_priv: 'EP' + nytt });
  koll(`namnbyte ${i + 1} → ${nytt}`, r.s === 200 && r.j.username === nytt, r);
  kod = nytt;
}
r = await api(A, 'POST', '/chatt/users/rename', { new_username: 'Alfa_4', old_login_hash: hash(kod), new_login_hash: hash('x'), enc_priv: 'EPx' }); koll('fjärde namnbytet i veckan → 429 too_many_renames', r.s === 429 && r.j.error === 'too_many_renames', r);
r = await api(A, 'GET', '/chatt/users/lookup?username=alfa'); koll('gamla namnet ledigt', r.j.exists === false, r);
r = await api(B, 'POST', '/chatt/users/rename', { new_username: 'Gamma', old_login_hash: hash('b'), new_login_hash: hash('x'), enc_priv: 'EPx' }); koll('byte till upptaget → 409', r.s === 409, r);
r = await api(A, 'POST', '/chatt/users/recovery/params', { username: 'Beta' }); koll('recovery/params ger riktigt salt', r.j.salt === 'c2FsdA==', r);
const falskt = (await api(A, 'POST', '/chatt/users/recovery/params', { username: 'Nobody' })).j.salt;
r = await api(A, 'POST', '/chatt/users/recovery/params', { username: 'Nobody' }); koll('låtsas-salt stabilt', falskt && r.j.salt === falskt, r);
r = await api(B, 'POST', '/chatt/users/recovery/reveal', { username: 'Beta', rec_auth: 'cmVjYg==' }); koll('reveal rätt lösen', r.j.rec_blob === 'YmxvYg==', r);
r = await api(A, 'POST', '/chatt/users/recovery/reveal', { username: 'Beta', rec_auth: 'cmVjYg==' }); koll('reveal av annans namn → 403', r.s === 403 && r.j.error === 'invalid_recovery', r);
r = await api(A, 'POST', '/chatt/users/recovery/set', { login_hash: hash(kod), salt: 'czI=', rec_auth: 'cmE=', rec_blob: 'YmE=' }); koll('recovery/set', r.j.has_recovery === true, r);
r = await api(A, 'POST', '/chatt/users/recovery/remove', { rec_auth: 'cmE=' }); koll('recovery/remove', r.j.has_recovery === false, r);

console.log('Gränser och radering');
r = await api(C, 'POST', '/chatt/users/login', { login_hash: hash('fel') });
for (let i = 0; i < 5; i++) r = await api(C, 'POST', '/chatt/users/login', { login_hash: hash('fel') });
koll('brute force-lås efter 5 fel → 429 login_locked', r.s === 429 && r.j.error === 'login_locked', r);
r = await api(C, 'POST', '/chatt/users/delete', { login_hash: hash('fel') }); koll('radera med fel kod → 403', r.s === 403, r);
r = await api(C, 'POST', '/chatt/users/delete', { login_hash: hash('c') }); koll('radera chattprofil', r.s === 200, r);
r = await api(C, 'GET', '/chatt/jag'); koll('profilen borta, kontot kvar', r.s === 200 && r.j.profil === null, r);
koll('Gammas meddelanden/kontakter borta', db.prepare('SELECT COUNT(*) c FROM chatt_kontakter WHERE requester_id=? OR addressee_id=?').get(C.id, C.id).c === 0);
db.prepare('DELETE FROM users WHERE id=?').run(D.id);
koll('raderat AdRaze-konto tar chattprofilen (CASCADE)', !db.prepare('SELECT 1 FROM chatt_profiler WHERE user_id=?').get(D.id));
db.prepare('UPDATE chatt_profiler SET suspended_until=? WHERE user_id=?').run(Date.now() + 86_400_000, B.id);
r = await api(B, 'GET', '/chatt/contacts'); koll('avstängd → 403 suspended', r.s === 403 && r.j.error === 'suspended' && r.j.suspended_until > 0, r);

console.log(`\n${ok} ok, ${fel} fel`);
if (fel) console.log('--- serverlogg ---\n' + logg.slice(-3000));
stang();
process.exit(fel ? 1 : 0);
