// Temagalleriet: publicera, validering, listor, röster, nedladdningar, anmälningar, borttagning och barnfilter.
// Tillfällig kopia av adraze-api med egen temp-databas (rör aldrig adraze.db i repot).
// Kör: node test/galleri-test.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.TEST_PORT || 18511);
const BAS = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-galleri-'));
for (const f of fs.readdirSync(REPO)) if (f.endsWith('.js')) fs.copyFileSync(path.join(REPO, f), path.join(tmp, f));
const srv = spawn(process.execPath, [path.join(tmp, 'server.js')], {
  cwd: tmp, env: { ...process.env, PORT: String(PORT), MAIL_LOGG: '1', CHATT_HOTLISTOR: '0', BREVO_API_KEY: '', CLAMD_PORT: '1', CHATT_NYCKEL: crypto.randomBytes(32).toString('hex') }, stdio: ['ignore', 'pipe', 'pipe'],
});
let logg = ''; srv.stdout.on('data', (d) => { logg += d; }); srv.stderr.on('data', (d) => { logg += d; });
process.on('exit', () => { try { srv.kill(); } catch {} try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} });
for (let i = 0; i < 100 && !logg.includes('adraze-api på'); i++) await new Promise((r) => setTimeout(r, 50));
if (!logg.includes('adraze-api på')) { console.error(logg); throw new Error('servern startade inte'); }

const db = new DatabaseSync(path.join(tmp, 'adraze.db'));
db.exec('PRAGMA foreign_keys=ON');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
let n = 0;
function vuxen(email) {
  const id = Number(db.prepare('INSERT INTO users(email,verified,created_at) VALUES(?,1,?)').run(email, Date.now()).lastInsertRowid);
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(token), id, Date.now() + 86_400_000);
  return { id, token, ip: `10.7.${++n}.1` };
}
function barn(foralder, namn) {
  const id = 'b' + crypto.randomBytes(12).toString('hex');
  db.prepare('INSERT INTO barn(id,foralder_id,namn,alder,kod,skapad) VALUES(?,?,?,?,?,?)').run(id, foralder.id, namn, 10, namn.toUpperCase() + '-' + crypto.randomBytes(4).toString('hex'), Date.now());
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO barn_sessioner(token,barn_id,skapad,expires) VALUES(?,?,?,?)').run(sha(token), id, Date.now(), Date.now() + 86_400_000);
  return { barnId: id, token, ip: `10.7.${++n}.1` };
}
const anonym = (ip) => ({ token: null, ip });
async function api(vem, metod, p, kropp) {
  const r = await fetch(BAS + p, { method: metod, headers: { ...(vem && vem.token ? { authorization: 'Bearer ' + vem.token } : {}), 'cf-connecting-ip': (vem && vem.ip) || '10.7.0.1', ...(kropp ? { 'content-type': 'application/json' } : {}) }, body: kropp ? JSON.stringify(kropp) : undefined });
  let j = null; try { j = await r.json(); } catch {}
  return { s: r.status, j };
}
let ok = 0, fel = 0;
const koll = (namn, v, info) => { if (v) { ok++; console.log('  ok  ', namn); } else { fel++; console.log('  FEL ', namn, info !== undefined ? JSON.stringify(info).slice(0, 300) : ''); } };
const hash = (s) => crypto.createHash('sha256').update(s).digest('base64');
const reg = (vem, u) => api(vem, 'POST', '/chatt/registrera', { username: u, login_hash: hash(u), public_key: 'PK' + u, enc_priv: 'EP' + u });
const kod = (o) => 'ADRZ1.' + Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const avkoda = (k) => JSON.parse(Buffer.from(k.slice(6), 'base64url').toString('utf8'));
const farg = () => '#' + crypto.randomBytes(3).toString('hex');
const publicera = (vem, namn, varden, extra = {}) => api(vem, 'POST', '/galleri/publicera', { namn, beskrivning: extra.beskrivning || '', kod: typeof varden === 'string' ? varden : kod(varden), anonym: !!extra.anonym });
const lista = (vem, sort, sida = 0, barnflagga) => api(vem, 'GET', `/galleri/lista?sort=${sort}&sida=${sida}${barnflagga ? '&barn=1' : ''}`);
const ids = (r) => ((r.j && r.j.teman) || []).map((t) => t.id);

const A = vuxen('anna@test.se'), B = vuxen('bo@test.se'), C = vuxen('cia@test.se'), D = vuxen('dan@test.se');
const K = barn(A, 'Kalle');
await reg(A, 'Anna_A');
let r;

console.log('Schema');
r = await api(null, 'GET', '/galleri/schema');
koll('schema utan inloggning', r.s === 200 && r.j.val['tema.lage'].includes('mork') && r.j.namnMax === 40 && r.j.beskMax === 140 && r.j.perDygn === 5, r.j);

console.log('Publicera');
const midnatt = { 'tema.accent': '#FF4B1F', 'tema.bakgrund': '#0e2a47', 'tema.lage': 'mork' };
r = await publicera(null, 'Midnatt', midnatt); koll('utan inloggning → 401', r.s === 401, r);
r = await publicera(K, 'Midnatt', midnatt); koll('barnkonto kan inte publicera → 401', r.s === 401, r);
r = await publicera(A, 'Midnatt', midnatt, { beskrivning: 'Mörkblått med orange.' });
koll('vuxen publicerar', r.s === 200 && /^t[0-9a-f]{20}$/.test(r.j.tema.id) && r.j.kvarIdag === 4, r);
const M = r.j.tema;
koll('färger normaliseras (#FF4B1F → #ff4b1f)', M.varden['tema.accent'] === '#ff4b1f' && M.varden['tema.lage'] === 'mork', M.varden);
koll('skaparen = användarnamnet i chatten', M.skapare === 'Anna_A' && M.egen === true, M);
r = await publicera(B, 'x'.repeat(41), { 'tema.accent': farg() }); koll('namn över 40 tecken → 400', r.s === 400 && /40/.test(r.j.error), r);
r = await publicera(B, 'Fyrtio', { 'tema.accent': farg() }, { beskrivning: 'y'.repeat(141) }); koll('beskrivning över 140 tecken → 400', r.s === 400 && /140/.test(r.j.error), r);
r = await publicera(B, 'å'.repeat(40), { 'tema.accent': farg() }, { beskrivning: 'ö'.repeat(140) }); koll('exakt 40 + 140 tecken (åäö) går', r.s === 200, r);
r = await publicera(B, 'https://evil.example/', { 'tema.accent': farg() }); koll('namn som bara är en länk → 400', r.s === 400, r);
r = await publicera(A, '<b>Skog</b> https://evil.example/x', { 'tema.accent': '#2f9e67', 'tema.yta': '#eef3f9' },
  { beskrivning: 'Besök evil.com/x eller discord.gg/abc, mejla mig@test.se, www.spam.se och <script>alert(1)</script> nu' });
koll('HTML och länkar rensas ur namnet', r.s === 200 && r.j.tema.namn === 'Skog', r.j && r.j.tema);
koll('länkar, domäner och mejl rensas ur beskrivningen', r.s === 200 && r.j.tema.beskrivning === 'Besök eller mejla och alert(1) nu', r.j && r.j.tema && r.j.tema.beskrivning);
const SKOG = r.j.tema.id;
r = await publicera(B, 'Tecken‮​fusk\u0007', { 'tema.accent': farg() }); koll('osynliga tecken och riktningstecken rensas', r.s === 200 && r.j.tema.namn === 'Tecken fusk', r.j && r.j.tema && r.j.tema.namn);
r = await publicera(B, 'Version 2.0', { 'tema.accent': farg() }); koll('punkt i vanlig text står kvar (2.0)', r.s === 200 && r.j.tema.namn === 'Version 2.0', r.j && r.j.tema && r.j.tema.namn);

console.log('Bara tema.* med giltiga värden');
const ogiltiga = [
  ['ingen ADRZ1-kod', 'hej'],
  ['trasig kod', 'ADRZ1.!!!'],
  ['lista i stället för objekt', kod([1, 2])],
  ['tomt tema', kod({})],
  ['annat område (sajt.*)', kod({ 'sajt.exempel.se': '#ffffff' })],
  ['skript-nyckel', kod({ 'avancerat.skript': 'alert(1)' })],
  ['url som färg', kod({ 'tema.accent': 'url(https://evil.example/x.png)' })],
  ['bildadress', kod({ 'tema.bild': 'https://evil.example/a.png' })],
  ['CSS-text', kod({ 'tema.css': 'body{display:none}' })],
  ['okänt val', kod({ 'tema.lage': 'neon' })],
  ['tal', kod({ 'tema.accent': 5 })],
  ['objekt som värde', kod({ 'tema.accent': { a: 1 } })],
  ['__proto__-nyckel', kod('{"__proto__":"#ffffff"}')],
  ['två nivåer', kod({ 'tema.a.b': '#ffffff' })],
  ['ogiltig hex', kod({ 'tema.accent': '#12345' })],
  ['färg + en ogiltig nyckel', kod({ 'tema.accent': '#ffffff', 'flikar.lage': 'vertikal' })],
  ['41 nycklar', kod(Object.fromEntries(Array.from({ length: 41 }, (_, i) => ['tema.f' + i, '#ffffff'])))],
  ['för stor kod', 'ADRZ1.' + 'A'.repeat(9000)],
];
for (const [namn, k] of ogiltiga) { r = await publicera(C, 'Testtema', k); koll('avvisas: ' + namn, r.s === 400, r); }
r = await publicera(C, 'Glas', { 'tema.glas': true, 'tema.yta': '#ABC', 'tema.rundning': 'rund' });
koll('sant/falskt, kort hex och kända val godtas', r.s === 200 && r.j.tema.varden['tema.glas'] === true && r.j.tema.varden['tema.yta'] === '#aabbcc' && r.j.tema.varden['tema.rundning'] === 'rund', r.j);
const GLAS = r.j && r.j.tema.id;
r = await publicera(B, 'Kopia', { 'tema.lage': 'mork', 'tema.bakgrund': '#0E2A47', 'tema.accent': '#ff4b1f' }); koll('likadant tema som redan finns → 409', r.s === 409 && r.j.error.includes('Midnatt'), r);
r = await api(A, 'GET', '/galleri/mina'); koll('mina: två teman, tre kvar i dag', r.s === 200 && r.j.teman.length === 2 && r.j.kvarIdag === 3, r.j);
r = await api(K, 'GET', '/galleri/mina'); koll('barn har inga egna teman → 401', r.s === 401, r);

console.log('Rösta');
r = await api(null, 'POST', '/galleri/rosta', { id: M.id, rost: 1 }); koll('utan inloggning → 401', r.s === 401, r);
r = await api(A, 'POST', '/galleri/rosta', { id: M.id, rost: 1 }); koll('eget tema → 403', r.s === 403, r);
r = await api(B, 'POST', '/galleri/rosta', { id: M.id, rost: 1 }); koll('B gillar', r.s === 200 && r.j.gillar === 1 && r.j.min_rost === 1, r);
r = await api(B, 'POST', '/galleri/rosta', { id: M.id, rost: 1 }); koll('en röst per konto', r.s === 200 && r.j.gillar === 1, r);
r = await api(C, 'POST', '/galleri/rosta', { id: M.id, rost: 1 }); koll('C gillar', r.j.gillar === 2, r);
r = await api(K, 'POST', '/galleri/rosta', { id: M.id, rost: 1 }); koll('barnet får gilla', r.s === 200 && r.j.gillar === 3, r);
r = await api(B, 'POST', '/galleri/rosta', { id: M.id, rost: 0 }); koll('B tar bort sin röst', r.j.gillar === 2 && r.j.min_rost === 0, r);
r = await api(B, 'POST', '/galleri/rosta', { id: M.id, rost: 2 }); koll('ogiltig röst → 400', r.s === 400, r);
r = await api(B, 'POST', '/galleri/rosta', { id: 'tfinnsinte', rost: 1 }); koll('okänt tema → 404', r.s === 404, r);
r = await api(D, 'POST', '/galleri/rosta', { id: SKOG, rost: -1 }); koll('D ogillar Skog (antalet gillar oförändrat)', r.s === 200 && r.j.gillar === 0 && r.j.min_rost === -1, r);
r = await api(D, 'POST', '/galleri/rosta', { id: GLAS, rost: 1 }); koll('D gillar Glas', r.j.gillar === 1, r);
r = await lista(C, 'populara');
koll('populära: Midnatt först, ogillat Skog sist', r.s === 200 && r.j.teman[0].id === M.id && r.j.teman[r.j.teman.length - 1].id === SKOG, r.j.teman.map((t) => [t.namn, t.gillar]));
koll('listan visar min röst', r.j.teman.find((t) => t.id === M.id).min_rost === 1, r.j.teman[0]);
r = await lista(A, 'nya'); koll('nya: nyast först, egna markerade', r.j.teman[0].id === GLAS && r.j.teman.find((t) => t.id === M.id).egen === true && r.j.teman.find((t) => t.id === GLAS).egen === false, r.j.teman.map((t) => t.namn));
koll('listan avslöjar inte ägarens konto-id', !('agare' in r.j.teman[0]), r.j.teman[0]);

console.log('Nedladdningar');
r = await api(anonym('10.9.9.1'), 'POST', '/galleri/nedladdad', { id: M.id }); koll('utan konto räknas', r.s === 200 && r.j.nedladdningar === 1, r);
r = await api(anonym('10.9.9.1'), 'POST', '/galleri/nedladdad', { id: M.id }); koll('samma adress räknas en gång', r.j.nedladdningar === 1, r);
r = await api(anonym('10.9.9.2'), 'POST', '/galleri/nedladdad', { id: M.id }); koll('annan adress räknas', r.j.nedladdningar === 2, r);
r = await api(B, 'POST', '/galleri/nedladdad', { id: M.id }); koll('inloggad räknas', r.j.nedladdningar === 3, r);
r = await api(A, 'POST', '/galleri/nedladdad', { id: M.id }); koll('ägaren räknas inte', r.j.nedladdningar === 3, r);
koll('ingen ip-adress sparas i klartext', !db.prepare("SELECT 1 FROM galleri_nedladdningar WHERE vem LIKE '%10.9.9%'").get());

console.log('Hämta');
r = await api(null, 'GET', '/galleri/tema?id=' + M.id);
koll('hämta ett tema med sin kod', r.s === 200 && JSON.stringify(avkoda(r.j.tema.kod)) === JSON.stringify(M.varden) && r.j.tema.gillar === 2, r.j);
r = await api(null, 'GET', '/galleri/tema?id=../../etc'); koll('ogiltigt id → 404', r.s === 404, r);

console.log('Topplistan (vecka)');
r = await lista(null, 'vecka');
koll('topplistan har plats och bara teman med aktivitet', r.s === 200 && r.j.teman[0].id === M.id && r.j.teman[0].plats === 1 && !ids(r).includes(SKOG), r.j.teman.map((t) => [t.plats, t.namn]));
db.prepare('UPDATE galleri_roster SET ts=? WHERE tema_id=?').run(Date.now() - 8 * 86_400_000, M.id);
db.prepare('UPDATE galleri_nedladdningar SET ts=? WHERE tema_id=?').run(Date.now() - 8 * 86_400_000, M.id);
r = await lista(null, 'vecka'); koll('gamla röster räknas inte i veckans topplista', !ids(r).includes(M.id) && ids(r)[0] === GLAS, r.j.teman.map((t) => t.namn));
r = await lista(null, 'populara'); koll('men temat ligger kvar bland populära', ids(r)[0] === M.id, r.j.teman.map((t) => t.namn));

console.log('Anonymt');
r = await publicera(A, 'Hemligt', { 'tema.accent': '#123456' }, { anonym: true }); koll('anonymt tema visar ingen skapare', r.s === 200 && r.j.tema.skapare === null, r.j);
const HEMLIGT = r.j.tema.id;
r = await api(null, 'GET', '/galleri/tema?id=' + GLAS); koll('konto utan chattnamn → Anonym', r.j.tema.skapare === null, r.j.tema);

console.log('Anmäla');
r = await api(null, 'POST', '/galleri/anmal', { id: GLAS, orsak: 'spam' }); koll('utan inloggning → 401', r.s === 401, r);
r = await api(C, 'POST', '/galleri/anmal', { id: GLAS }); koll('eget tema → 400', r.s === 400, r);
r = await api(B, 'POST', '/galleri/anmal', { id: GLAS, orsak: 'olampligt' }); koll('B anmäler Glas', r.s === 200, r);
r = await lista(K, 'nya'); koll('barnet ser inte ett anmält tema', !ids(r).includes(GLAS) && ids(r).includes(M.id), r.j.teman.map((t) => t.namn));
r = await lista(null, 'nya', 0, true); koll('barn=1 (barnläge utan barnkonto) döljer också', !ids(r).includes(GLAS), r.j.teman.map((t) => t.namn));
r = await api(K, 'GET', '/galleri/tema?id=' + GLAS); koll('barnet kan inte hämta det anmälda temat', r.s === 404, r);
r = await lista(A, 'nya'); koll('vuxna ser det fortfarande (en anmälan)', ids(r).includes(GLAS), r.j.teman.map((t) => t.namn));
await api(B, 'POST', '/galleri/anmal', { id: GLAS, orsak: 'olampligt' });
r = await api(D, 'POST', '/galleri/anmal', { id: GLAS, orsak: 'spam' }); koll('D anmäler', r.s === 200, r);
r = await lista(A, 'nya'); koll('två olika konton räcker inte för att dölja', ids(r).includes(GLAS), r.j.teman.map((t) => t.namn));
r = await api(K, 'POST', '/galleri/anmal', { id: GLAS, orsak: 'annat' }); koll('barnet får anmäla (tredje kontot)', r.s === 200, r);
r = await lista(A, 'nya'); koll('tre anmälningar → dolt för alla', !ids(r).includes(GLAS), r.j.teman.map((t) => t.namn));
r = await api(A, 'GET', '/galleri/tema?id=' + GLAS); koll('dolt tema går inte att hämta', r.s === 404, r);
r = await api(C, 'GET', '/galleri/mina'); koll('ägaren ser sitt dolda tema i Mina', r.j.teman.some((t) => t.id === GLAS && t.dold === true), r.j);

console.log('Ta bort');
r = await api(B, 'POST', '/galleri/ta-bort', { id: SKOG }); koll('någon annans tema → 404', r.s === 404, r);
r = await api(K, 'POST', '/galleri/ta-bort', { id: SKOG }); koll('barn kan inte ta bort → 401', r.s === 401, r);
r = await api(A, 'POST', '/galleri/ta-bort', { id: SKOG }); koll('ägaren tar bort sitt tema', r.s === 200, r);
r = await lista(A, 'nya'); koll('borta ur listan', !ids(r).includes(SKOG), r.j.teman.map((t) => t.namn));
r = await api(null, 'GET', '/galleri/tema?id=' + SKOG); koll('går inte att hämta', r.s === 404, r);
koll('inget innehåll sparas efter borttagning', !db.prepare('SELECT namn, varden FROM galleri_teman WHERE id=?').get(SKOG).varden);
koll('röster på borttaget tema raderas', !db.prepare('SELECT 1 FROM galleri_roster WHERE tema_id=?').get(SKOG));

console.log('Fem per dygn');
r = await publicera(A, 'Fyra', { 'tema.accent': farg() }); koll('fjärde', r.s === 200, r);
r = await publicera(A, 'Fem', { 'tema.accent': farg() }); koll('femte', r.s === 200 && r.j.kvarIdag === 0, r);
r = await publicera(A, 'Sex', { 'tema.accent': farg() }); koll('sjätte samma dygn → 429 (borttagna räknas)', r.s === 429, r);

console.log('Sidvis');
for (let i = 0; i < 6; i++) { const E = vuxen(`e${i}@test.se`); for (let j = 0; j < 5; j++) await publicera(E, `Tema ${i}-${j}`, { 'tema.accent': farg(), 'tema.bakgrund': farg() }); }
r = await lista(null, 'nya', 0); const s0 = ids(r);
koll('första sidan: 24 och fler finns', s0.length === 24 && r.j.mer === true, { n: s0.length, mer: r.j.mer });
r = await lista(null, 'nya', 1); const s1 = ids(r);
koll('andra sidan: resten och inga fler', s1.length > 0 && s1.length < 24 && r.j.mer === false && !s1.some((x) => s0.includes(x)), { n: s1.length, mer: r.j.mer });
r = await lista(null, 'nya', 99999); koll('sida utanför → tom lista', r.s === 200 && r.j.teman.length === 0, r.j);
r = await lista(null, 'konstig'); koll('okänd sortering → populära', r.s === 200 && r.j.sort === 'populara', r.j.sort);

console.log('Radering av konton');
db.prepare('DELETE FROM barn WHERE id=?').run(K.barnId);
r = await api(null, 'GET', '/galleri/tema?id=' + M.id); koll('raderat barnkonto: rösten försvinner', r.j.tema.gillar === 1, r.j.tema);
db.prepare('DELETE FROM users WHERE id=?').run(B.id);
r = await api(null, 'GET', '/galleri/tema?id=' + M.id); koll('raderat konto: nedladdningen försvinner', r.j.tema.nedladdningar === 2, r.j.tema);
db.prepare('DELETE FROM users WHERE id=?').run(A.id);
r = await api(null, 'GET', '/galleri/tema?id=' + M.id); koll('raderat konto: dess teman försvinner', r.s === 404, r);
r = await api(null, 'GET', '/galleri/tema?id=' + HEMLIGT); koll('även de anonyma', r.s === 404, r);

console.log(`\n${ok} ok, ${fel} fel`); process.exit(fel ? 1 : 0);
