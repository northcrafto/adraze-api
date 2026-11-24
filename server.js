// AdRaze konto-API (doxing, systemd --user adraze-api, 127.0.0.1:8492, publikt som https://api.adraze.app via Cloudflare-tunneln)
// Konton med lösenord + 6-siffrig kod i mejlet (registrering, ny enhet, glömt lösenord), Google-inloggning,
// och statistik som AdRaze-tillägget skickar in (hur mycket reklam, spårare och popups det stoppat).
// Ren Node 22 utan beroenden: node:sqlite, mejl via Brevo.
'use strict';
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const DIR = __dirname;
for (const rad of (fs.existsSync(path.join(DIR, '.env')) ? fs.readFileSync(path.join(DIR, '.env'), 'utf8') : '').split('\n')) {
  const m = /^([A-Z_]+)=(.*)$/.exec(rad.trim());
  if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
}
const PORT = Number(process.env.PORT || 8492);
const KOLLA_PORT = Number(process.env.KOLLA_PORT || 8493);
const SAJT = (process.env.SITE_URL || 'https://adraze.app').replace(/\/$/, '');
const ORIGINS = new Set((process.env.ORIGINS || 'https://adraze.app,https://accounts.adraze.app,https://support.adraze.app').split(',').map((s) => s.trim()));
const BREVO_KEY = process.env.BREVO_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || 'konto@adraze.app';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const COOKIE = 'adr_s'; // inloggning
const ENHET = 'adr_e'; // betrodd webbläsare: hit behövs ingen kod vid inloggning
const SESSION_DAGAR = 90;
const ENHET_DAGAR = 365;
const KOD_TTL = 15 * 60_000;

// ---------- databas ----------
const db = new DatabaseSync(path.join(DIR, 'adraze.db'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pass TEXT, google_sub TEXT UNIQUE,
  verified INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS codes(email TEXT NOT NULL, purpose TEXT NOT NULL, hash TEXT NOT NULL, tries INTEGER NOT NULL DEFAULT 0,
  expires INTEGER NOT NULL, sent_at INTEGER NOT NULL, PRIMARY KEY(email, purpose));
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS trusted(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL, created_at INTEGER NOT NULL, last_sync INTEGER);
CREATE TABLE IF NOT EXISTS stats(device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, day TEXT NOT NULL,
  reklam INTEGER NOT NULL DEFAULT 0, sparare INTEGER NOT NULL DEFAULT 0, farliga INTEGER NOT NULL DEFAULT 0,
  popups INTEGER NOT NULL DEFAULT 0, omdirigeringar INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(device_id, day));`);
const q = (sql) => db.prepare(sql);
// Samma tillägg (installation) får bara räknas en gång, även om det kopplas om till ett annat konto
if (!q("SELECT 1 FROM pragma_table_info('devices') WHERE name='install_id'").get()) db.exec('ALTER TABLE devices ADD COLUMN install_id TEXT');
// Förnamnet som kontosidan hälsar med ("Välkommen, Cetto")
if (!q("SELECT 1 FROM pragma_table_info('users') WHERE name='namn'").get()) db.exec('ALTER TABLE users ADD COLUMN namn TEXT');
// Profilbild: färdigbeskuren JPEG (256×256) som data-URL, visas på kontosidan, i webbläsaren och i chatten
if (!q("SELECT 1 FROM pragma_table_info('users') WHERE name='avatar'").get()) db.exec('ALTER TABLE users ADD COLUMN avatar TEXT');
// Obekräftad registrering: nytt lösenord/namn sparas med koden och sätts först när just den koden skrivs in
if (!q("SELECT 1 FROM pragma_table_info('codes') WHERE name='pending_pass'").get()) db.exec('ALTER TABLE codes ADD COLUMN pending_pass TEXT');
if (!q("SELECT 1 FROM pragma_table_info('codes') WHERE name='pending_namn'").get()) db.exec('ALTER TABLE codes ADD COLUMN pending_namn TEXT');
// users.id saknar AUTOINCREMENT, så SQLite skulle ge ett raderat kontos id (om det var det högsta) till nästa nya
// konto, och allt som pekar på id:t utan FK (synk, support, chattgrupper, rapporter) skulle hamna hos fel person.
// Nya konton får därför alltid ett id över det högsta som någonsin delats ut (id_hogvatten, hålls av en trigger).
db.exec(`CREATE TABLE IF NOT EXISTS id_hogvatten(tabell TEXT PRIMARY KEY, max_id INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS users_id_hogvatten AFTER INSERT ON users BEGIN
  INSERT OR REPLACE INTO id_hogvatten(tabell, max_id)
    VALUES('users', MAX(NEW.id, COALESCE((SELECT max_id FROM id_hogvatten WHERE tabell='users'), 0)));
END;`);
function nyttKonto(f) {
  return q(`INSERT INTO users(id,email,pass,google_sub,verified,namn,created_at) VALUES(
    MAX(COALESCE((SELECT max_id FROM id_hogvatten WHERE tabell='users'), 0), COALESCE((SELECT MAX(id) FROM users), 0)) + 1, ?,?,?,?,?,?)`)
    .run(f.email, f.pass ?? null, f.google_sub ?? null, f.verified, f.namn ?? null, now());
}
// Familj: barnkonton tillhör en förälder och loggar in i webbläsaren med sin barnkod + en kod som mejlas till föräldern
db.exec(`CREATE TABLE IF NOT EXISTS barn(id TEXT PRIMARY KEY, foralder_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  namn TEXT NOT NULL, alder INTEGER NOT NULL, kod TEXT UNIQUE NOT NULL, blocklista TEXT NOT NULL DEFAULT '[]', tillat TEXT NOT NULL DEFAULT '[]',
  skapad INTEGER NOT NULL, senast INTEGER);
CREATE TABLE IF NOT EXISTS barn_sessioner(token TEXT PRIMARY KEY, barn_id TEXT NOT NULL REFERENCES barn(id) ON DELETE CASCADE,
  ip TEXT, skapad INTEGER NOT NULL, senast INTEGER, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS barn_historik(barn_id TEXT NOT NULL REFERENCES barn(id) ON DELETE CASCADE, url TEXT NOT NULL, titel TEXT, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS barn_historik_ts ON barn_historik(barn_id, ts);
CREATE TABLE IF NOT EXISTS barn_godkann(barn_id TEXT PRIMARY KEY REFERENCES barn(id) ON DELETE CASCADE, hash TEXT NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL, sent_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS barn_fragor(id INTEGER PRIMARY KEY, barn_id TEXT NOT NULL REFERENCES barn(id) ON DELETE CASCADE,
  host TEXT NOT NULL, text TEXT, skapad INTEGER NOT NULL, svar TEXT, minuter INTEGER, svarad INTEGER);
CREATE INDEX IF NOT EXISTS barn_fragor_barn ON barn_fragor(barn_id, skapad);
CREATE TABLE IF NOT EXISTS barn_enheter(token TEXT PRIMARY KEY, barn_id TEXT NOT NULL REFERENCES barn(id) ON DELETE CASCADE, skapad INTEGER NOT NULL);`);
// Barnlås: föräldern låser en webbläsare till barnets konto. Låset får en egen märkning (token) som följer webbläsaren.
// Lösenordet till låset finns bara på datorn; märkningen används när föräldern glömt det och behöver en kod för att välja ett nytt.
db.exec(`CREATE TABLE IF NOT EXISTS barn_las(token TEXT PRIMARY KEY, barn_id TEXT NOT NULL REFERENCES barn(id) ON DELETE CASCADE, skapad INTEGER NOT NULL,
  kod_hash TEXT, kod_tries INTEGER NOT NULL DEFAULT 0, kod_expires INTEGER NOT NULL DEFAULT 0, kod_sent INTEGER NOT NULL DEFAULT 0);`);
// Spärrljud: föräldern kan välja ett ljud som spelas när barnet hamnar på en spärrad sida (av från början)
if (!q("SELECT 1 FROM pragma_table_info('barn') WHERE name='sparrljud'").get()) db.exec("ALTER TABLE barn ADD COLUMN sparrljud TEXT NOT NULL DEFAULT ''");
if (!q("SELECT 1 FROM pragma_table_info('barn') WHERE name='sparrljud_vol'").get()) db.exec('ALTER TABLE barn ADD COLUMN sparrljud_vol INTEGER NOT NULL DEFAULT 60');
const SPARRLJUD = ['', 'hangd', 'summer', 'stotar', 'kort', 'stotar-kort'];
const ljudUt = (c) => ({ id: SPARRLJUD.includes(c.sparrljud) ? c.sparrljud : '', volym: Math.min(80, Math.max(10, c.sparrljud_vol | 0)) });


// ---------- hjälpare ----------
const now = () => Date.now();
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
// Engångskoder hashas med HMAC och en hemlig nyckel ur .env (inte osaltad SHA-256), och binds till adressen,
// så att den som bara kan läsa databasen inte kan knäcka de sex siffrorna. KOD_NYCKEL måste sättas i .env.
const KOD_NYCKEL = process.env.KOD_NYCKEL || '';
if (!KOD_NYCKEL) console.error('VARNING: KOD_NYCKEL saknas i .env – engångskoder hashas utan hemlig nyckel och går att knäcka från databasen');
const hmac = (data) => crypto.createHmac('sha256', KOD_NYCKEL).update(data).digest('hex');
const kodHash = (syfte, email, kod) => hmac(`${syfte}:${email}:${kod}`);
const fel = (status, text) => Object.assign(new Error(text), { status, expose: true });

function hashPass(p) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(p, salt, 64).toString('hex')}`;
}
function checkPass(p, stored) {
  const [salt, dk] = String(stored || DUMMY).split(':');
  return eq(crypto.scryptSync(p, salt, 64).toString('hex'), dk);
}
// Okända konton prövas mot en påhittad hash så att svarstiden inte avslöjar vilka mejl som finns
const DUMMY = hashPass(crypto.randomBytes(8).toString('hex'));

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i;
const normEmail = (e) => (typeof e === 'string' ? e.trim().toLowerCase() : '');
const passFel = (p) => (typeof p !== 'string' || p.length < 8 || p.length > 200 ? 'Lösenordet måste vara minst 8 tecken.' : null);

const traffar = new Map();
function begransad(nyckel, max, fonsterMs) {
  const t = now();
  const lista = (traffar.get(nyckel) || []).filter((x) => t - x < fonsterMs);
  const over = lista.length >= max;
  if (!over) lista.push(t);
  traffar.set(nyckel, lista);
  return over;
}
setInterval(() => { const t = now(); for (const [k, v] of traffar) if (!v.some((x) => t - x < 86_400_000)) traffar.delete(k); }, 600_000).unref();
// Gränser som skyddar enskilda konton (kod, login, familjekoder) läggs i databasen så att de överlever omstarter
// (annars nollas de i snitt nära en gång per dygn och ger angriparen nya gissningar). Fast fönster, som mejl_kvot.
db.exec('CREATE TABLE IF NOT EXISTS granser(nyckel TEXT NOT NULL, bucket INTEGER NOT NULL, n INTEGER NOT NULL, utgang INTEGER NOT NULL, PRIMARY KEY(nyckel, bucket))');
function begransadDb(nyckel, max, fonsterMs) {
  const bucket = Math.floor(now() / fonsterMs);
  const rad = q('SELECT n FROM granser WHERE nyckel=? AND bucket=?').get(nyckel, bucket);
  if ((rad?.n || 0) >= max) return true;
  q('INSERT INTO granser(nyckel,bucket,n,utgang) VALUES(?,?,1,?) ON CONFLICT(nyckel,bucket) DO UPDATE SET n=n+1').run(nyckel, bucket, (bucket + 1) * fonsterMs);
  return false;
}

// ---------- mejl ----------
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Citatförslag från kontosidan går hit
const FORSLAG_TILL = process.env.FORSLAG_TILL || 'cetoari9@gmail.com';
const MAIL_PER_DAG = Number(process.env.MAIL_PER_DAG || 150);
// Dygnsbudgeten delas upp per mejlklass och sparas i databasen (en omstart nollar den inte):
//  oppen  – koder som vem som helst kan begära till en adress (registrering, glömt lösenord)
//  drift  – supportärenden och citatförslag
//  konto  – inloggningskod efter rätt lösenord, familjekoder och teamets svar i support
// oppen och drift har egna tak, så de kan aldrig ta det som konto behöver; konto får resten av totalen.
// familj = förälderns inloggningskod för barnet; support = anonyma supportärenden. Egna, låga tak skilda från drift.
const MAIL_KLASSTAK = { oppen: Number(process.env.MAIL_OPPEN_PER_DAG || 60), drift: Number(process.env.MAIL_DRIFT_PER_DAG || 40), samtal: Number(process.env.MAIL_SAMTAL_PER_DAG || 30), familj: Number(process.env.MAIL_FAMILJ_PER_DAG || 20), support: Number(process.env.MAIL_SUPPORT_PER_DAG || 20) };
// En reserv av totalen hålls åt klass konto (inloggningskoder m.m.), så att övriga klasser inte kan tömma budgeten
const MAIL_RESERV = Number(process.env.MAIL_RESERV || 50);
db.exec('CREATE TABLE IF NOT EXISTS mejl_kvot(dag TEXT NOT NULL, klass TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY(dag, klass))');
function taMejlKvot(klass) {
  const dag = new Date().toISOString().slice(0, 10);
  const rader = q('SELECT klass, n FROM mejl_kvot WHERE dag=?').all(dag);
  const totalt = rader.reduce((s, r) => s + r.n, 0), egen = rader.find((r) => r.klass === klass)?.n || 0;
  const totaltTak = klass === 'konto' ? MAIL_PER_DAG : MAIL_PER_DAG - MAIL_RESERV;
  if (totalt >= totaltTak || egen >= (MAIL_KLASSTAK[klass] ?? Infinity)) return false;
  q('INSERT INTO mejl_kvot(dag,klass,n) VALUES(?,?,1) ON CONFLICT(dag,klass) DO UPDATE SET n=n+1').run(dag, klass);
  return true;
}
async function skickaMejl(till, amne, html, text, svaraTill, klass = 'drift') {
  if (!taMejlKvot(klass)) { console.error(`Mejltaket nått för i dag (${klass})`); return false; }
  // MAIL_LOGG=1: skriv mejlet i loggen i stället för att skicka (för test utan riktiga utskick)
  if (process.env.MAIL_LOGG === '1' || !BREVO_KEY) { console.log('[mejl loggat]', till, amne); return process.env.MAIL_LOGG === '1'; }
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': BREVO_KEY, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { email: MAIL_FROM, name: 'AdRaze' }, to: [{ email: till }], subject: amne, htmlContent: html, textContent: text, ...(svaraTill ? { replyTo: { email: svaraTill } } : {}) }),
  }).catch((e) => ({ ok: false, status: 0, text: async () => String(e) }));
  if (!r.ok) console.error('Brevo-mejl', r.status, (await r.text()).slice(0, 400));
  return r.ok;
}

// Gemensam layout: vit, figuren från loggan vinkar överst, kort rubrik och koden stor i orange
function mejlLayout(rubrik, kropp) {
  return `<!doctype html><html lang="sv"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="color-scheme" content="light"></head>
<body style="margin:0;padding:0;background:#ffffff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#17171a">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff"><tr><td align="center" style="padding:40px 20px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:460px">
<tr><td align="center"><img src="${SAJT}/mail/vinkar.gif" width="150" alt="" style="display:block;width:150px;height:auto;border:0"></td></tr>
<tr><td align="center" style="padding-top:26px;font-size:24px;line-height:1.25;font-weight:700;letter-spacing:-0.01em">${esc(rubrik)}</td></tr>
<tr><td align="center" style="padding-top:14px"><div style="width:44px;height:3px;border-radius:2px;background:#ff4b1f"></div></td></tr>
${kropp}
<tr><td align="center" style="padding-top:40px;font-size:12px;line-height:1.6;color:#8a8a93">AdRaze · <a href="${SAJT}" style="color:#8a8a93">adraze.app</a><br>Du får det här mejlet eftersom någon skrev in din adress på AdRaze.</td></tr>
</table></td></tr></table></body></html>`;
}
const mejlText = (t) => `<tr><td align="center" style="padding-top:18px;font-size:15px;line-height:1.65;color:#4a4a52">${t}</td></tr>`;
const mejlKod = (kod) => `<tr><td align="center" style="padding-top:26px"><div style="display:inline-block;font-size:38px;line-height:1;font-weight:700;letter-spacing:10px;padding:18px 18px 18px 28px;border-radius:14px;background:#fff3ef;color:#ff4b1f;font-family:'SF Mono',Menlo,Consolas,monospace">${kod}</div></td></tr>`;
const mejlRuta = (t) => `<tr><td style="padding-top:26px"><div style="border-radius:12px;background:#fff8e6;border:1px solid #f5dfa0;padding:14px 16px;font-size:13px;line-height:1.6;color:#6b5310">${t}</div></td></tr>`;

const KODMEJL = {
  verify: (kod) => ({
    amne: `${kod} är din kod till AdRaze`,
    html: mejlLayout('Välkommen till AdRaze', mejlText('Skriv in koden för att bekräfta din mejladress och starta ditt konto.') + mejlKod(kod) +
      mejlText('Koden gäller i 15 minuter.')),
    text: `Välkommen till AdRaze!\n\nDin kod: ${kod}\n\nSkriv in den för att bekräfta din mejladress. Koden gäller i 15 minuter.`,
  }),
  login: (kod) => ({
    amne: `${kod} är din inloggningskod till AdRaze`,
    html: mejlLayout('Logga in på AdRaze', mejlText('Någon loggar just nu in på ditt konto med rätt lösenord, från en webbläsare vi inte känner igen.') + mejlKod(kod) +
      mejlText('Koden gäller i 15 minuter.') +
      mejlRuta('<b>Var det inte du?</b> Då har någon ditt lösenord. Skriv inte in koden, och byt lösenord via <i>Glömt lösenordet?</i> på inloggningssidan.')),
    text: `Din inloggningskod till AdRaze: ${kod}\n\nNågon loggar in på ditt konto med rätt lösenord från en ny webbläsare. Var det inte du? Skriv inte in koden och byt lösenord via "Glömt lösenordet?".`,
  }),
  reset: (kod) => ({
    amne: `${kod} är din kod för nytt lösenord`,
    html: mejlLayout('Nytt lösenord', mejlText('Skriv in koden på AdRaze och välj ett nytt lösenord.') + mejlKod(kod) +
      mejlText('Koden gäller i 15 minuter. Har du inte bett om ett nytt lösenord kan du strunta i det här mejlet.')),
    text: `Din kod för nytt lösenord på AdRaze: ${kod}\n\nKoden gäller i 15 minuter. Har du inte bett om den kan du strunta i mejlet.`,
  }),
  delete: (kod) => ({
    amne: `${kod} är din kod för att radera kontot`,
    html: mejlLayout('Radera ditt konto', mejlText('Skriv in koden på AdRaze för att bekräfta att du vill radera ditt konto. Det går inte att ångra.') + mejlKod(kod) +
      mejlText('Koden gäller i 15 minuter. Har du inte bett om att radera kontot kan du strunta i det här mejlet.')),
    text: `Din kod för att radera AdRaze-kontot: ${kod}\n\nKoden gäller i 15 minuter. Har du inte bett om den kan du strunta i mejlet.`,
  }),
};

async function skickaKod(email, syfte, pending) {
  const rad = q('SELECT * FROM codes WHERE email=? AND purpose=?').get(email, syfte);
  if (rad && now() - rad.sent_at < 45_000) return 'vanta';
  // Högst 12 koder per adress och dygn (i databasen, så taket överlever omstarter)
  if (begransadDb(`kodmejl:${email}`, 12, 86_400_000)) return 'tak';
  const kod = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  q('INSERT OR REPLACE INTO codes(email,purpose,hash,tries,expires,sent_at,pending_pass,pending_namn) VALUES(?,?,?,0,?,?,?,?)')
    .run(email, syfte, kodHash(syfte, email, kod), now() + KOD_TTL, now(), pending?.pass ?? null, pending?.namn ?? null);
  const m = KODMEJL[syfte](kod);
  if (await skickaMejl(email, m.amne, m.html, m.text, undefined, (syfte === 'login' || syfte === 'delete') ? 'konto' : 'oppen')) return 'skickad';
  // Mejlet gick inte iväg: lägg tillbaka förra koden (den kan redan ligga i mejlkorgen) eller ta bort den nya
  if (rad) q('INSERT OR REPLACE INTO codes(email,purpose,hash,tries,expires,sent_at,pending_pass,pending_namn) VALUES(?,?,?,?,?,?,?,?)').run(rad.email, rad.purpose, rad.hash, rad.tries, rad.expires, rad.sent_at, rad.pending_pass ?? null, rad.pending_namn ?? null);
  else q('DELETE FROM codes WHERE email=? AND purpose=?').run(email, syfte);
  return 'fel';
}
function anvandKod(email, syfte, kod) {
  const rad = q('SELECT * FROM codes WHERE email=? AND purpose=?').get(email, syfte);
  if (!rad || rad.expires < now()) return 'utgangen';
  if (rad.tries >= 6) return 'last';
  if (typeof kod !== 'string' || !eq(kodHash(syfte, email, kod.replace(/\s/g, '')), rad.hash)) {
    q('UPDATE codes SET tries=tries+1 WHERE email=? AND purpose=?').run(email, syfte);
    return 'fel';
  }
  q('DELETE FROM codes WHERE email=? AND purpose=?').run(email, syfte);
  return 'ok';
}
const KODSVAR = { utgangen: [400, 'Fel eller utgången kod. Be om en ny.'], last: [429, 'För många fel försök. Be om en ny kod.'], fel: [400, 'Fel eller utgången kod. Be om en ny.'] };
function krav(svar) { if (svar !== 'ok') throw fel(...KODSVAR[svar]); }
function kodSkickad(svar) {
  if (svar === 'fel') throw fel(502, 'Vi kunde inte skicka mejlet just nu. Försök igen om en stund.');
  if (svar === 'tak') throw fel(429, 'Vi har skickat många koder till den adressen i dag. Försök igen i morgon.');
}

// ---------- kakor och sessioner ----------
function kakor(req) {
  const ut = {};
  for (const del of (req.headers.cookie || '').split(';')) {
    const i = del.indexOf('=');
    if (i > 0) ut[del.slice(0, i).trim()] = decodeURIComponent(del.slice(i + 1).trim());
  }
  return ut;
}
const kaka = (namn, varde, dagar) => `${namn}=${varde}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.round(dagar * 86400)}`;
function laggTillKaka(res, k) { res.setHeader('Set-Cookie', [...[].concat(res.getHeader('Set-Cookie') || []), k]); }
// AdRaze-webbläsaren skickar app:true och får nycklarna i svaret i stället för som kakor
const iAppen = (b) => !!b && b.app === true;
const bearer = (req) => /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(String(req.headers.authorization || ''))?.[1] || null;
function nySession(res, userId, app) {
  const t = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(t), userId, now() + SESSION_DAGAR * 86_400_000);
  if (app) return t;
  laggTillKaka(res, kaka(COOKIE, t, SESSION_DAGAR));
  return null;
}
function litaPa(res, userId, app) {
  const t = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO trusted(token,user_id,expires) VALUES(?,?,?)').run(sha(t), userId, now() + ENHET_DAGAR * 86_400_000);
  if (app) return t;
  laggTillKaka(res, kaka(ENHET, t, ENHET_DAGAR));
  return null;
}
// Inloggad efter kod: session + betrodd webbläsare. I appen följer båda nycklarna med i svaret.
function loggaIn(res, u, b) {
  const app = iAppen(b);
  const token = nySession(res, u.id, app), enhet = litaPa(res, u.id, app);
  return app ? { me: mig(u), token, enhet } : { me: mig(u) };
}
const betrodd = (req, userId, b) => {
  const t = kakor(req)[ENHET] || (iAppen(b) && typeof b.enhet === 'string' ? b.enhet : '');
  return !!t && !!q('SELECT 1 FROM trusted WHERE token=? AND user_id=? AND expires>?').get(sha(t), userId, now());
};
function inloggad(req) {
  const t = kakor(req)[COOKIE] || bearer(req);
  return t ? q('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?').get(sha(t), now()) || null : null;
}
function kravInloggad(req) { const u = inloggad(req); if (!u) throw fel(401, 'Du är inte inloggad.'); return u; }
setInterval(() => {
  q('DELETE FROM sessions WHERE expires<?').run(now());
  q('DELETE FROM trusted WHERE expires<?').run(now());
  q('DELETE FROM codes WHERE expires<?').run(now() - 86_400_000);
  // Konton som aldrig bekräftades frigör sin adress efter ett dygn
  q('DELETE FROM users WHERE verified=0 AND created_at<?').run(now() - 86_400_000);
  q('DELETE FROM mejl_kvot WHERE dag<?').run(new Date(now() - 7 * 86_400_000).toISOString().slice(0, 10));
  q('DELETE FROM granser WHERE utgang<?').run(now());
}, 3_600_000).unref();

// ---------- Google ----------
// ID-token (JWT, RS256) från Google Identity Services, verifierad mot Googles publika nycklar
let jwks = { keys: [], tills: 0 };
async function googleNycklar(tvinga) {
  if (!tvinga && jwks.tills > now()) return jwks.keys;
  const r = await fetch('https://www.googleapis.com/oauth2/v3/certs');
  const maxAge = Number(/max-age=(\d+)/.exec(r.headers.get('cache-control') || '')?.[1] || 3600);
  jwks = { keys: (await r.json()).keys, tills: now() + maxAge * 1000 };
  return jwks.keys;
}
async function verifieraGoogle(token) {
  if (!GOOGLE_CLIENT_ID) throw fel(503, 'Google-inloggning är inte påslagen än.');
  const delar = String(token || '').split('.');
  if (delar.length !== 3) throw fel(400, 'Ogiltig Google-inloggning.');
  const [h, p, sig] = delar;
  let huvud, c;
  try { huvud = JSON.parse(Buffer.from(h, 'base64url')); c = JSON.parse(Buffer.from(p, 'base64url')); } catch { throw fel(400, 'Ogiltig Google-inloggning.'); }
  if (huvud.alg !== 'RS256') throw fel(400, 'Ogiltig Google-inloggning.');
  let jwk = (await googleNycklar()).find((k) => k.kid === huvud.kid) || (await googleNycklar(true)).find((k) => k.kid === huvud.kid);
  if (!jwk) throw fel(400, 'Ogiltig Google-inloggning.');
  const giltig = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(sig, 'base64url'));
  const iss = c.iss === 'accounts.google.com' || c.iss === 'https://accounts.google.com';
  if (!giltig || !iss || c.aud !== GOOGLE_CLIENT_ID || c.exp * 1000 < now() || !c.email_verified || !c.sub || !c.email)
    throw fel(401, 'Google-inloggningen kunde inte bekräftas. Försök igen.');
  return { sub: String(c.sub), email: normEmail(c.email), namn: rensaNamn(c.given_name) };
}

// ---------- statistik ----------
const FALT = ['reklam', 'sparare', 'farliga', 'popups', 'omdirigeringar'];
// Högsta rimliga antal per webbläsare och dag, så att ingen kan blåsa upp den publika siffran
const TAK = { reklam: 100_000, sparare: 100_000, farliga: 1_000, popups: 2_000, omdirigeringar: 2_000 };
const DAG_RE = /^\d{4}-\d{2}-\d{2}$/;
function statistik(userId) {
  const fran = new Date(now() - 29 * 86_400_000).toISOString().slice(0, 10);
  const summa = FALT.map((f) => `SUM(s.${f}) AS ${f}`).join(',');
  const totalt = q(`SELECT ${summa} FROM stats s JOIN devices d ON d.id=s.device_id WHERE d.user_id=?`).get(userId);
  const dagar = q(`SELECT s.day, ${summa} FROM stats s JOIN devices d ON d.id=s.device_id WHERE d.user_id=? AND s.day>=? GROUP BY s.day ORDER BY s.day`).all(userId, fran);
  for (const f of FALT) totalt[f] = totalt[f] || 0;
  const enheter = q('SELECT id, name, created_at, last_sync FROM devices WHERE user_id=? ORDER BY created_at').all(userId);
  return { totalt, dagar, enheter };
}

// ---------- svar och förfrågningar ----------
function skicka(res, status, kropp) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(kropp));
}
function lasKropp(req, max) {
  return new Promise((resolve, reject) => {
    if (Number(req.headers['content-length']) > max) { req.resume(); return reject(fel(413, 'För stor förfrågan.')); }
    const bitar = []; let n = 0;
    // För stort: sluta spara men läs klart, så att svaret (413) hinner fram
    req.on('data', (c) => { n += c.length; if (n > max) { reject(fel(413, 'För stor förfrågan.')); bitar.length = 0; } else bitar.push(c); });
    req.on('end', () => resolve(Buffer.concat(bitar)));
    req.on('error', reject);
  });
}
async function json(req, max = 16_384) {
  if (!(req.headers['content-type'] || '').startsWith('application/json')) throw fel(415, 'Fel format.');
  try { const v = JSON.parse((await lasKropp(req, max)).toString('utf8') || '{}'); return v && typeof v === 'object' ? v : {}; } catch (e) { throw e.status ? e : fel(400, 'Ogiltig JSON.'); }
}
// Tunneln går via Cloudflare, som sätter besökarens adress
const ipAv = (req) => String(req.headers['cf-connecting-ip'] || req.socket.remoteAddress);
const enhetsNamn = (req) => {
  const ua = String(req.headers['user-agent'] || '');
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'Mac' : /Android/.test(ua) ? 'Android' : /Linux/.test(ua) ? 'Linux' : /CrOS/.test(ua) ? 'ChromeOS' : 'Dator';
  const wb = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Brave/.test(ua) ? 'Brave' : /Chrome\//.test(ua) ? 'Chrome' : 'Webbläsare';
  return `${wb} på ${os}`;
};

const rutter = {};
const rutt = (metod, p, fn) => { rutter[`${metod} ${p}`] = fn; };
// Större kropp än standard (16 kB) för enstaka rutter, t.ex. bilder: rutt.max('/me/avatar', 200_000)
const kroppMax = {};
rutt.max = (p, n) => { kroppMax[p] = n; };
// Bara bokstäver, mellanslag, bindestreck och apostrof; högst 40 tecken
const rensaNamn = (n) => String(n || '').normalize('NFC').replace(/[^\p{L}\p{M} '’-]/gu, '').replace(/\s+/g, ' ').trim().slice(0, 40);
// Pro gäller om prenumerationen eller en inlöst gåva (egen kolumn) räcker, det senaste av datumen
const proTillMs = (u) => Math.max(Number(u.pro_until) || 0, Number(u.pro_gift_until) || 0);
const mig = (u) => ({ email: u.email, namn: u.namn || '', avatar: u.avatar || null, google: !!u.google_sub, losenord: !!u.pass, skapad: u.created_at, pro: proTillMs(u) > now(), proTill: proTillMs(u) || null });

rutt('GET', '/health', () => ({}));
rutt('GET', '/auth/config', () => ({ googleClientId: GOOGLE_CLIENT_ID || null }));

rutt('POST', '/auth/signup', async (req, res, b) => {
  const email = normEmail(b.email);
  if (!EMAIL_RE.test(email)) throw fel(400, 'Skriv en giltig mejladress.');
  const pf = passFel(b.password); if (pf) throw fel(400, pf);
  if (begransad(`signup:${ipAv(req)}`, 8, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const finns = q('SELECT * FROM users WHERE email=?').get(email);
  const namn = rensaNamn(b.namn) || null;
  if (finns?.verified) {
    // Avslöja inte via 409 att kontot finns: svara som för en ny adress och mejla ägaren att kontot redan finns
    await skickaMejl(email, 'Du har redan ett AdRaze-konto',
      mejlLayout('Du har redan ett konto', mejlText('Någon försökte skapa ett AdRaze-konto med din adress, men du har redan ett. Logga in i stället, eller välj "Glömt lösenord?" om du inte kommer in.')),
      'Du har redan ett AdRaze-konto. Logga in i stället, eller välj "Glömt lösenord?".', undefined, 'oppen').catch(() => {});
    return { steg: 'kod', syfte: 'verify', email };
  }
  // Obekräftat konto skrivs INTE över: spara nytt lösenord/namn med koden och sätt dem först när just den koden skrivs in
  if (!finns) nyttKonto({ email, pass: hashPass(b.password), verified: 0, namn });
  kodSkickad(await skickaKod(email, 'verify', finns ? { pass: hashPass(b.password), namn } : null));
  return { steg: 'kod', syfte: 'verify', email };
});

rutt('POST', '/auth/verify', async (req, res, b) => {
  const email = normEmail(b.email);
  if (begransadDb(`kod:${email}:${ipAv(req)}`, 20, 3_600_000) || begransad(`kodip:${ipAv(req)}`, 60, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const u = q('SELECT * FROM users WHERE email=?').get(email);
  if (!u) throw fel(400, 'Fel eller utgången kod. Be om en ny.');
  const syfte = u.verified ? 'login' : 'verify';
  // Obekräftat konto: hämta väntande lösenord/namn ur koden innan den används (anvandKod raderar raden)
  const pend = !u.verified ? q('SELECT pending_pass, pending_namn FROM codes WHERE email=? AND purpose=?').get(email, syfte) : null;
  krav(anvandKod(email, syfte, b.code));
  if (!u.verified) q('UPDATE users SET verified=1, pass=COALESCE(?,pass), namn=COALESCE(?,namn) WHERE id=?').run(pend?.pending_pass ?? null, pend?.pending_namn ?? null, u.id);
  return loggaIn(res, q('SELECT * FROM users WHERE id=?').get(u.id), b);
});

rutt('POST', '/auth/resend', async (req, res, b) => {
  const email = normEmail(b.email);
  const u = q('SELECT * FROM users WHERE email=?').get(email);
  if (begransad(`resend:${ipAv(req)}`, 10, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  // Bara om det finns en väntande kod, så att man inte kan skicka koder till vem som helst
  const syfte = b.syfte === 'reset' ? 'reset' : u?.verified ? 'login' : 'verify';
  if (!u || !q('SELECT 1 FROM codes WHERE email=? AND purpose=?').get(email, syfte)) return {};
  // Svara alltid {}: ett 429 (väntar) eller mejlfel skulle annars avslöja att kontot finns och att någon loggar in
  await skickaKod(email, syfte).catch(() => {});
  return {};
});

rutt('POST', '/auth/login', async (req, res, b) => {
  const email = normEmail(b.email);
  // Räkna per (mejl, IP), inte bara per mejl, så att en angripare inte kan låsa ut en utvald användare
  if (begransad(`login:${ipAv(req)}`, 20, 900_000) || begransadDb(`login:${email}:${ipAv(req)}`, 10, 900_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const u = q('SELECT * FROM users WHERE email=?').get(email);
  const pass = typeof b.password === 'string' ? b.password : '';
  // Samma svar för Google-konton som för fel lösenord, så att det inte avslöjar att adressen har ett Google-konto
  if (!checkPass(pass, u?.pass) || !u) throw fel(401, 'Fel mejladress eller lösenord.');
  if (!u.verified) { kodSkickad(await skickaKod(email, 'verify')); return { steg: 'kod', syfte: 'verify', email }; }
  if (betrodd(req, u.id, b)) { const token = nySession(res, u.id, iAppen(b)); return token ? { me: mig(u), token } : { me: mig(u) }; }
  const svar = await skickaKod(email, 'login');
  kodSkickad(svar);
  return { steg: 'kod', syfte: 'login', email };
});

rutt('POST', '/auth/google', async (req, res, b) => {
  if (begransad(`google:${ipAv(req)}`, 20, 900_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const g = await verifieraGoogle(b.credential);
  let u = q('SELECT * FROM users WHERE google_sub=?').get(g.sub) || q('SELECT * FROM users WHERE email=?').get(g.email);
  const obekraftad = !!(u && !u.verified);
  if (u && !u.verified) q('UPDATE users SET pass=NULL WHERE id=?').run(u.id);
  if (u) q('UPDATE users SET google_sub=?, verified=1 WHERE id=?').run(g.sub, u.id);
  else nyttKonto({ email: g.email, google_sub: g.sub, verified: 1 });
  // Ett obekräftat konto kan ha fått ett namn av någon annan: ersätt det med Googles
  if (g.namn && obekraftad) q('UPDATE users SET namn=? WHERE google_sub=?').run(g.namn, g.sub);
  else if (g.namn) q("UPDATE users SET namn=? WHERE google_sub=? AND COALESCE(namn,'')=''").run(g.namn, g.sub);
  u = q('SELECT * FROM users WHERE google_sub=?').get(g.sub);
  return loggaIn(res, u, b);
});

rutt('POST', '/auth/forgot', async (req, res, b) => {
  const email = normEmail(b.email);
  if (!EMAIL_RE.test(email)) throw fel(400, 'Skriv en giltig mejladress.');
  if (begransad(`forgot:${ipAv(req)}`, 6, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  // Samma svar oavsett om kontot finns, även om mejlet inte går iväg (annars avslöjar 502 att kontot finns)
  if (q('SELECT 1 FROM users WHERE email=? AND verified=1').get(email)) await skickaKod(email, 'reset').catch(() => {});
  return { steg: 'kod', syfte: 'reset', email };
});

rutt('POST', '/auth/reset', async (req, res, b) => {
  const email = normEmail(b.email);
  const pf = passFel(b.password); if (pf) throw fel(400, pf);
  if (begransadDb(`kod:${email}:${ipAv(req)}`, 20, 3_600_000) || begransad(`kodip:${ipAv(req)}`, 60, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const u = q('SELECT * FROM users WHERE email=? AND verified=1').get(email);
  if (!u) throw fel(400, 'Fel eller utgången kod. Be om en ny.');
  krav(anvandKod(email, 'reset', b.code));
  q('UPDATE users SET pass=? WHERE id=?').run(hashPass(b.password), u.id);
  // Nytt lösenord: logga ut överallt och glöm betrodda webbläsare
  q('DELETE FROM sessions WHERE user_id=?').run(u.id);
  q('DELETE FROM trusted WHERE user_id=?').run(u.id);
  return loggaIn(res, u, b);
});

rutt('POST', '/auth/logout', (req, res) => {
  const t = kakor(req)[COOKIE] || bearer(req);
  if (t) q('DELETE FROM sessions WHERE token=?').run(sha(t));
  laggTillKaka(res, kaka(COOKIE, '', 0));
  return {};
});

// Publik summa för alla användare (statistiksidan). Räknas om högst var 30:e sekund.
let globalt = { tid: 0, data: null };
rutt('GET', '/stats/global', () => {
  if (now() - globalt.tid < 30_000) return globalt.data;
  // Samma installation kopplad till flera konton räknas en gång per dag (största värdet)
  const summa = FALT.map((f) => `COALESCE(SUM(${f}),0) AS ${f}`).join(',');
  const perInstallation = `SELECT s.day, ${FALT.map((f) => `MAX(s.${f}) AS ${f}`).join(',')} FROM stats s JOIN devices d ON d.id=s.device_id
    GROUP BY COALESCE(d.install_id, 'enhet' || d.id), s.day`;
  const idag = new Date().toISOString().slice(0, 10);
  globalt = { tid: now(), data: {
    totalt: q(`SELECT ${summa} FROM (${perInstallation})`).get(),
    idag: q(`SELECT ${summa} FROM (${perInstallation}) WHERE day=?`).get(idag),
    webblasare: q('SELECT COUNT(*) AS n FROM devices WHERE last_sync>?').get(now() - 30 * 86_400_000).n,
  } };
  return globalt.data;
});
rutt('GET', '/me', async (req) => { const u = await pro.uppdatera(kravInloggad(req)); return { me: mig(u), ...statistik(u.id) }; });

rutt('POST', '/me/namn', async (req, res, b) => {
  const u = kravInloggad(req);
  const namn = rensaNamn(b.namn);
  if (!namn) throw fel(400, 'Skriv ett namn med bokstäver.');
  q('UPDATE users SET namn=? WHERE id=?').run(namn, u.id);
  return { namn };
});

// Förslag på dagens citat: bara inloggade, högst 5 per timme och konto
rutt('POST', '/forslag', async (req, res, b) => {
  const u = kravInloggad(req);
  if (begransad(`forslag:${u.id}`, 5, 3_600_000)) throw fel(429, 'För många förslag. Vänta en stund.');
  const citat = String(b.citat || '').replace(/\s+/g, ' ').trim().slice(0, 400);
  const vem = String(b.vem || '').replace(/\s+/g, ' ').trim().slice(0, 80);
  if (citat.length < 3) throw fel(400, 'Skriv citatet först.');
  const ok = await skickaMejl(FORSLAG_TILL, `Citatförslag: ${citat.slice(0, 60)}${citat.length > 60 ? '…' : ''}`,
    mejlLayout('Nytt citatförslag', mejlText(`<b style="color:#17171a;font-size:18px">”${esc(citat)}”</b>`) +
      mejlText(vem ? `– ${esc(vem)}` : '<i>Ingen upphovsperson angiven</i>') +
      mejlText(`Från ${esc(u.email)}${u.namn ? ` (${esc(u.namn)})` : ''}. Svara på mejlet för att svara personen.`)),
    `Nytt citatförslag:\n\n"${citat}"\n– ${vem || 'okänd'}\n\nFrån ${u.email}`, u.email);
  if (!ok) throw fel(503, 'Förslaget kunde inte skickas just nu. Försök igen senare.');
  return {};
});

// Profilbild: klienten beskär och skalar själv till 256×256 JPEG; här kollas bara att det verkligen är en liten JPEG
const AVATAR_MAX = 120_000;
rutt.max('/me/avatar', AVATAR_MAX + 1_000);
rutt('POST', '/me/avatar', async (req, res, b) => {
  const u = kravInloggad(req);
  if (begransad(`avatar:${u.id}`, 20, 3_600_000)) throw fel(429, 'För många byten. Vänta en stund.');
  if (b.bild === null) { q('UPDATE users SET avatar=NULL WHERE id=?').run(u.id); return { avatar: null }; }
  const m = typeof b.bild === 'string' && b.bild.length <= AVATAR_MAX && /^data:image\/jpeg;base64,([A-Za-z0-9+/]+=*)$/.exec(b.bild);
  const bytes = m && Buffer.from(m[1], 'base64');
  if (!bytes || bytes.length < 200 || bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes[2] !== 0xff) throw fel(400, 'Bilden kunde inte sparas. Försök med en annan bild.');
  q('UPDATE users SET avatar=? WHERE id=?').run(b.bild, u.id);
  return { avatar: b.bild };
});

rutt('POST', '/me/delete', async (req, res, b) => {
  const u = kravInloggad(req);
  // Lösenordskonto: kräv lösenordet. Konto utan lösenord (Google): kräv en färsk Google-credential eller en mejlad kod,
  // så att en stulen eller lånad session inte räcker för att radera kontot för gott.
  if (u.pass) {
    if (!checkPass(typeof b.password === 'string' ? b.password : '', u.pass)) throw fel(401, 'Fel lösenord.');
  } else if (u.google_sub && typeof b.credential === 'string') {
    const g = await verifieraGoogle(b.credential);
    if (g.sub !== u.google_sub) throw fel(401, 'Google-inloggningen stämmer inte med kontot.');
  } else {
    if (typeof b.code !== 'string' || !b.code.trim()) { kodSkickad(await skickaKod(u.email, 'delete')); return { steg: 'kod', syfte: 'delete' }; }
    krav(anvandKod(u.email, 'delete', b.code));
  }
  await pro.avslutaVidRadering(u);   // Pro i Stripe avslutas först, annars debiteras kunden vidare efter raderingen
  // Supportärenden (även de som skickats från adressen utan inloggning) raderas med kontot; meddelandena följer med
  // (CASCADE) och synk tas av en trigger i synk.js
  db.exec('BEGIN IMMEDIATE');
  try {
    q('DELETE FROM support_arenden WHERE user_id=? OR email=?').run(u.id, normEmail(u.email));
    q('DELETE FROM users WHERE id=?').run(u.id);
    db.exec('COMMIT');
  } catch (e) { try { db.exec('ROLLBACK'); } catch {} throw e; }
  laggTillKaka(res, kaka(COOKIE, '', 0));
  laggTillKaka(res, kaka(ENHET, '', 0));
  return {};
});

// Koppla tillägget: sidan hämtar en nyckel åt tillägget, som sedan skickar in statistik med den
rutt('POST', '/devices', async (req) => {
  const u = kravInloggad(req);
  if (q('SELECT COUNT(*) AS n FROM devices WHERE user_id=?').get(u.id).n >= 20) throw fel(400, 'Du har redan 20 kopplade webbläsare. Ta bort någon först.');
  if (begransad(`koppla:${u.id}`, 10, 86_400_000)) throw fel(429, 'För många kopplingar i dag. Försök i morgon.');
  const token = crypto.randomBytes(32).toString('base64url');
  const r = q('INSERT INTO devices(user_id,token,name,created_at) VALUES(?,?,?,?)').run(u.id, sha(token), enhetsNamn(req), now());
  return { token, id: Number(r.lastInsertRowid) };
});
rutt('POST', '/devices/remove', async (req, res, b) => {
  const u = kravInloggad(req);
  q('DELETE FROM devices WHERE id=? AND user_id=?').run(Number(b.id) || 0, u.id);
  return {};
});

// Tillägget skickar dagssummor (inte ökningar), så samma dag kan skickas om och om igen
rutt('POST', '/stats/sync', async (req, res, b) => {
  const t = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''))?.[1];
  const d = t && q('SELECT * FROM devices WHERE token=?').get(sha(t));
  if (!d) throw fel(401, 'Okänd webbläsare.');
  if (begransad(`sync:${d.id}`, 30, 3_600_000)) throw fel(429, 'För ofta.');
  const dagar = b.dagar && typeof b.dagar === 'object' ? Object.entries(b.dagar).slice(-60) : [];
  const idag = new Date(now() + 86_400_000).toISOString().slice(0, 10);
  const spara = q(`INSERT INTO stats(device_id,day,${FALT.join(',')}) VALUES(?,?,${FALT.map(() => '?').join(',')})
    ON CONFLICT(device_id,day) DO UPDATE SET ${FALT.map((f) => `${f}=MAX(${f},excluded.${f})`).join(',')}`);
  for (const [dag, v] of dagar) {
    if (!DAG_RE.test(dag) || dag > idag || !v || typeof v !== 'object') continue;
    spara.run(d.id, dag, ...FALT.map((f) => Math.max(0, Math.min(TAK[f], Math.floor(Number(v[f]) || 0)))));
  }
  const install = typeof b.installId === 'string' && /^[0-9a-f-]{36}$/.test(b.installId) ? b.installId : null;
  if (install) {
    // Tillägget har kopplats om inom kontot: den gamla kopplingen (och dess dubbletter av samma siffror) tas bort.
    // Andra konton rörs aldrig (id:t kan inte bevisas); den globala summan räknar varje installation en gång i stället.
    q('DELETE FROM devices WHERE install_id=? AND id<>? AND user_id=?').run(install, d.id, d.user_id);
    q('UPDATE devices SET install_id=? WHERE id=?').run(install, d.id);
  }
  q('UPDATE devices SET last_sync=? WHERE id=?').run(now(), d.id);
  return {};
});


// ---------- Familj (AdRaze-webbläsaren) ----------
// Föräldern skapar barnkonton. Barnet loggar in med sin barnkod, och för varje inloggning mejlas en
// sexsiffrig kod till föräldern som barnet måste skriva in. Barnkoden ensam räcker alltså aldrig.
const BARN_MAX = 10;
const BARN_SESSIONER = 5;
const BARN_DAGAR = 365;
const KOD_TECKEN = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 tecken, inga som förväxlas (0/O, 1/I)
function barnKod(namn) {
  const bas = String(namn || '').normalize('NFD').replace(/[^A-Za-z]/g, '').toUpperCase().slice(0, 5) || 'BARN';
  const bytes = crypto.randomBytes(8);
  let r = '';
  for (const x of bytes) r += KOD_TECKEN[x % 32];
  return `${bas}-${r}`;
}
function nyBarnKod(namn) {
  for (let i = 0; i < 10; i++) { const k = barnKod(namn); if (!q('SELECT 1 FROM barn WHERE kod=?').get(k)) return k; }
  throw fel(500, 'Försök igen.');
}
const normBarnKod = (k) => String(k || '').toUpperCase().replace(/\s+/g, '').slice(0, 40);
const lasLista = (x) => { try { const v = JSON.parse(x || '[]'); return Array.isArray(v) ? v : []; } catch { return []; } };
const aktivaTillat = (x) => lasLista(x).filter((a) => a && a.host && a.until > now());
const ettBarn = (u, id) => { const c = q('SELECT * FROM barn WHERE id=? AND foralder_id=?').get(String(id || ''), u.id); if (!c) throw fel(403, 'Det är inte ditt barn.'); return c; };
function barnInloggad(req) {
  const t = bearer(req);
  const s = t && q('SELECT s.token, s.senast, b.* FROM barn_sessioner s JOIN barn b ON b.id=s.barn_id WHERE s.token=? AND s.expires>?').get(sha(t), now());
  if (!s) throw fel(401, 'Du är inte inloggad.');
  if (!s.senast || now() - s.senast > 300_000) {
    q('UPDATE barn_sessioner SET senast=? WHERE token=?').run(now(), s.token);
    q('UPDATE barn SET senast=? WHERE id=?').run(now(), s.id);
  }
  return s;
}
setInterval(() => {
  q('DELETE FROM barn_sessioner WHERE expires<?').run(now());
  q('DELETE FROM barn_godkann WHERE expires<?').run(now());
}, 3_600_000).unref();

const godkannMejl = (barn, kod, enhet) => ({
  amne: `${kod} – ${barn.namn} vill logga in på AdRaze`,
  html: mejlLayout(`${barn.namn} vill logga in`, mejlText(`<b style="color:#17171a">${esc(barn.namn)}</b> försöker logga in i AdRaze-webbläsaren (${esc(enhet)}). Ge koden till ${esc(barn.namn)} om det är hen som frågar.`) +
    mejlKod(kod) + mejlText('Koden gäller i 15 minuter och fungerar bara en gång.') +
    mejlRuta(`<b>Frågar ingen efter koden?</b> Då har någon annan fått tag i ${esc(barn.namn)}s barnkod. Skriv inte in den här koden någonstans, och tryck <i>Byt kod</i> på ${esc(barn.namn)} under Familj i AdRaze.`)),
  text: `${barn.namn} vill logga in i AdRaze-webbläsaren (${enhet}).\n\nKod: ${kod}\n\nGe koden till ${barn.namn} om det är hen som frågar. Koden gäller i 15 minuter.\nFrågar ingen efter koden? Byt ${barn.namn}s kod under Familj i AdRaze.`,
});

// Barnet steg 1: barnkoden → en kod mejlas till föräldern
rutt('POST', '/barn/start', async (req, res, b) => {
  const kod = normBarnKod(b.kod);
  if (kod.length < 4) throw fel(400, 'Skriv koden du fick av din förälder.');
  if (begransad(`barnstart:${ipAv(req)}`, 15, 900_000) || begransad(`barnkod:${kod}`, 8, 900_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const barn = q('SELECT * FROM barn WHERE kod=?').get(kod);
  if (!barn) throw fel(404, 'Fel kod. Fråga din förälder.');
  const foralder = q('SELECT email FROM users WHERE id=?').get(barn.foralder_id);
  const forra = q('SELECT sent_at FROM barn_godkann WHERE barn_id=?').get(barn.id);
  if (forra && now() - forra.sent_at < 45_000) return { steg: 'godkann', namn: barn.namn, skickad: true };
  // Tak per förälder och dygn (i databasen, överlever omstarter), lågt så att familjekoder inte kan tömma mejlbudgeten
  if (begransadDb(`barnmejl:${barn.foralder_id}`, 5, 86_400_000)) throw fel(429, 'Din förälder har fått många koder i dag. Försök igen i morgon.');
  const engang = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const forraRad = q('SELECT * FROM barn_godkann WHERE barn_id=?').get(barn.id);
  q('INSERT OR REPLACE INTO barn_godkann(barn_id,hash,tries,expires,sent_at) VALUES(?,?,0,?,?)').run(barn.id, hmac(`barn:${barn.id}:${engang}`), now() + KOD_TTL, now());
  const m = godkannMejl(barn, engang, String(b.enhet || 'en dator').replace(/[^\p{L}\p{N} ._-]/gu, '').slice(0, 40) || 'en dator');
  // Egen mejlklass 'familj' med eget litet tak, skild från inloggningskodernas klass konto
  if (!(await skickaMejl(foralder.email, m.amne, m.html, m.text, undefined, 'familj'))) {
    // Inget mejl: lägg tillbaka förra koden eller ta bort den nya, så att nästa försök inte tror att koden redan skickats
    if (forraRad) q('INSERT OR REPLACE INTO barn_godkann(barn_id,hash,tries,expires,sent_at) VALUES(?,?,?,?,?)').run(forraRad.barn_id, forraRad.hash, forraRad.tries, forraRad.expires, forraRad.sent_at);
    else q('DELETE FROM barn_godkann WHERE barn_id=?').run(barn.id);
    throw fel(502, 'Vi kunde inte skicka koden till din förälder just nu. Försök igen om en stund.');
  }
  return { steg: 'godkann', namn: barn.namn };
});

// Barnet steg 2: koden från föräldern → inloggad
rutt('POST', '/barn/verifiera', async (req, res, b) => {
  const kod = normBarnKod(b.kod);
  if (begransad(`barnverif:${ipAv(req)}`, 30, 900_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const barn = q('SELECT * FROM barn WHERE kod=?').get(kod);
  const g = barn && q('SELECT * FROM barn_godkann WHERE barn_id=?').get(barn.id);
  if (!g || g.expires < now()) throw fel(410, 'Koden har gått ut. Be om en ny.');
  if (g.tries >= 6) throw fel(429, 'För många fel försök. Be om en ny kod.');
  if (typeof b.godkannande !== 'string' || !eq(hmac(`barn:${barn.id}:${b.godkannande.replace(/\s/g, '')}`), g.hash)) {
    q('UPDATE barn_godkann SET tries=tries+1 WHERE barn_id=?').run(barn.id);
    throw fel(400, 'Fel kod. Fråga din förälder igen.');
  }
  q('DELETE FROM barn_godkann WHERE barn_id=?').run(barn.id);
  const t = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO barn_sessioner(token,barn_id,ip,skapad,senast,expires) VALUES(?,?,?,?,?,?)').run(sha(t), barn.id, ipAv(req), now(), now(), now() + BARN_DAGAR * 86_400_000);
  q('DELETE FROM barn_sessioner WHERE barn_id=? AND token NOT IN (SELECT token FROM barn_sessioner WHERE barn_id=? ORDER BY skapad DESC LIMIT ?)').run(barn.id, barn.id, BARN_SESSIONER);
  q('UPDATE barn SET senast=? WHERE id=?').run(now(), barn.id);
  return { token: t, barn: { id: barn.id, namn: barn.namn, alder: barn.alder } };
});

rutt('POST', '/barn/jag', (req) => {
  const c = barnInloggad(req);
  return { namn: c.namn, alder: c.alder, blocklista: lasLista(c.blocklista), tillat: aktivaTillat(c.tillat), sparrljud: ljudUt(c),
    fragor: q('SELECT id, host, skapad, svar, minuter, svarad FROM barn_fragor WHERE barn_id=? AND skapad>? ORDER BY skapad DESC LIMIT 20').all(c.id, now() - 86_400_000) };
});
// Barnets dator får en egen märkning som finns kvar när barnet loggar ut. Loggar någon sedan in med ett ANNAT
// vuxenkonto än förälderns på den datorn (barnspärren släpper då) får föräldern ett mejl – barnet låses inte ute.
rutt('POST', '/barn/enhet', (req) => {
  const c = barnInloggad(req);
  const t = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO barn_enheter(token,barn_id,skapad) VALUES(?,?,?)').run(sha(t), c.id, now());
  q('DELETE FROM barn_enheter WHERE barn_id=? AND token NOT IN (SELECT token FROM barn_enheter WHERE barn_id=? ORDER BY skapad DESC LIMIT 20)').run(c.id, c.id);
  return { enhet: t };
});
rutt('POST', '/barn/annat-konto', async (req, res, b) => {
  const e = q('SELECT b.id, b.namn, b.foralder_id, u.email AS foralder_epost FROM barn_enheter e JOIN barn b ON b.id=e.barn_id JOIN users u ON u.id=b.foralder_id WHERE e.token=?').get(sha(String(b.enhet || '')));
  if (!e) return { kand: false };                       // okänd/borttagen märkning: datorn hör inte till någon familj längre
  const vuxen = inloggad(req);
  if (vuxen && vuxen.id === e.foralder_id) return { kand: true, foralder: true };   // föräldern själv låser upp: inget mejl
  const vem = vuxen ? vuxen.email : String(b.epost || '').slice(0, 200);
  if (begransad(`annatkonto:${e.id}:${vem}`, 1, 6 * 3_600_000) || begransad(`annatkonto:${e.id}`, 5, 86_400_000)) return { kand: true, foralder: false };
  const tid = new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Stockholm', dateStyle: 'long', timeStyle: 'short' });
  const namn = e.namn;
  await skickaMejl(e.foralder_epost, `${namn} loggade in med ett annat konto i AdRaze`,
    mejlLayout(`${namn} loggade in med ett annat konto`,
      mejlText(`På ${esc(namn)}s dator loggade någon in i AdRaze med kontot <b>${esc(vem || 'okänt konto')}</b> (${esc(tid)}).`) +
      mejlText(`Med ett annat konto gäller inte ${esc(namn)}s spärrar. Var det inte okej kan ni prata om det, och du kan byta ${esc(namn)}s kod i AdRaze under Inställningar › Familj.`) +
      mejlRuta(`Var det du eller någon annan vuxen i familjen? Då behöver du inte göra något.`)),
    `På ${namn}s dator loggade någon in i AdRaze med kontot ${vem || 'okänt konto'} (${tid}). Med ett annat konto gäller inte ${namn}s spärrar. Du kan byta ${namn}s kod i AdRaze under Inställningar › Familj.`,
    undefined, 'konto');   // föräldralarmet ligger i skyddade klassen konto, så det inte kan tystas genom att tömma drift
  return { kand: true, foralder: false };
});
// Barnet frågar om lov att gå in på en spärrad sida. Föräldern ser frågan i AdRaze Familj.
const fragaHost = (h) => String(h || '').trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '').slice(0, 200);
rutt('POST', '/barn/fraga', (req, res, b) => {
  const c = barnInloggad(req);
  const host = fragaHost(b.host);
  if (!host || !/^[a-z0-9.-]+$/.test(host)) throw fel(400, 'Ogiltig sida.');
  const text = String(b.text || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 200) || null;
  if (begransad(`barnfraga:${c.id}`, 20, 3_600_000)) throw fel(429, 'Du har frågat många gånger nu. Vänta en stund.');
  const vant = q('SELECT id FROM barn_fragor WHERE barn_id=? AND host=? AND svar IS NULL').get(c.id, host);
  let id;
  if (vant) { q('UPDATE barn_fragor SET text=?, skapad=? WHERE id=?').run(text, now(), vant.id); id = vant.id; }
  else id = Number(q('INSERT INTO barn_fragor(barn_id,host,text,skapad) VALUES(?,?,?,?)').run(c.id, host, text, now()).lastInsertRowid);
  q('DELETE FROM barn_fragor WHERE barn_id=? AND id NOT IN (SELECT id FROM barn_fragor WHERE barn_id=? ORDER BY skapad DESC LIMIT 50)').run(c.id, c.id);
  return { id };
});
rutt('POST', '/barn/historik', (req, res, b) => {
  const c = barnInloggad(req);
  if (begransad(`barnhist:${c.id}`, 600, 3_600_000)) return {};
  const url = String(b.url || '').slice(0, 500);
  if (!/^https?:/i.test(url)) return {};
  q('INSERT INTO barn_historik(barn_id,url,titel,ts) VALUES(?,?,?,?)').run(c.id, url, String(b.titel || '').slice(0, 200), now());
  q('DELETE FROM barn_historik WHERE barn_id=? AND rowid NOT IN (SELECT rowid FROM barn_historik WHERE barn_id=? ORDER BY ts DESC LIMIT 500)').run(c.id, c.id);
  return {};
});
rutt('POST', '/barn/logout', (req) => {
  const t = bearer(req);
  if (t) q('DELETE FROM barn_sessioner WHERE token=?').run(sha(t));
  return {};
});

// ── Översätt sidan (AdRaze-webbläsaren) ──
// Webbläsaren skickar sidans textbitar hit och vi frågar Googles översättning åt den, så att Google ser vår server och
// inte användaren. Inget loggas och inget sparas på disk: bara en minnescache per (språk, text), så att samma meny och
// sidfot inte översätts om för varje sida. Ingen inloggning krävs. Tak per adress och för alla per dygn.
const OVS_SPRAK = /^[a-z]{2,3}(-[A-Za-z]{2,4})?$/;
const ovsCache = new Map(); const OVS_CACHE_MAX = 30_000;
let ovsDag = '', ovsAntal = 0;
async function ovsGoogle(texter, till) {
  const u = 'https://clients5.google.com/translate_a/t?client=dict-chrome-ex&sl=auto&tl=' + encodeURIComponent(till) + '&' + texter.map((t) => 'q=' + encodeURIComponent(t)).join('&');
  const r = await fetch(u, { headers: { 'User-Agent': 'Mozilla/5.0', Accept: '*/*' }, signal: AbortSignal.timeout(15_000) });
  if (r.status === 429 || r.status === 503) throw fel(503, 'Översättningen är överbelastad just nu. Försök igen om en stund.');
  if (!r.ok) throw fel(502, 'Översättningen svarade inte.');
  const j = await r.json();
  if (!Array.isArray(j) || j.length !== texter.length) throw fel(502, 'Översättningen gav ett oväntat svar.');
  return j.map((x) => (Array.isArray(x) ? { text: String(x[0] ?? ''), fran: String(x[1] || '') } : { text: String(x ?? ''), fran: '' }));
}
rutt('POST', '/oversatt', async (req, res, b) => {
  const till = String(b.till || '');
  if (!OVS_SPRAK.test(till)) throw fel(400, 'Okänt språk.');
  const texter = Array.isArray(b.texter) ? b.texter : null;
  if (!texter || !texter.length || texter.length > 40 || texter.some((t) => typeof t !== 'string' || !t.trim() || t.length > 2000)) throw fel(400, 'Fel på texterna.');
  if (texter.reduce((n, t) => n + t.length, 0) > 4000) throw fel(413, 'För mycket text på en gång.');
  if (begransad(`ovs:${ipAv(req)}`, 900, 600_000)) throw fel(429, 'För många översättningar på kort tid. Vänta en stund.');
  const dag = new Date().toISOString().slice(0, 10);
  if (dag !== ovsDag) { ovsDag = dag; ovsAntal = 0; }
  const ut = new Array(texter.length); const saknas = [];
  texter.forEach((t, i) => { const c = ovsCache.get(till + '\n' + t); if (c) ut[i] = c; else saknas.push(i); });
  // Googles adress tar frågan i webbadressen: dela upp så att varje anrop håller sig kort
  for (let a = 0; a < saknas.length;) {
    const bit = []; let langd = 0;
    while (a < saknas.length && (!bit.length || langd + encodeURIComponent(texter[saknas[a]]).length < 5200)) { langd += encodeURIComponent(texter[saknas[a]]).length + 3; bit.push(saknas[a++]); }
    if (++ovsAntal > Number(process.env.OVS_DAG_TAK || 150_000)) throw fel(503, 'Översättningen har nått dagens tak. Försök igen i morgon.');
    const svar = await ovsGoogle(bit.map((i) => texter[i]), till);
    bit.forEach((i, n) => { ut[i] = svar[n]; if (ovsCache.size >= OVS_CACHE_MAX) ovsCache.delete(ovsCache.keys().next().value); ovsCache.set(till + '\n' + texter[i], svar[n]); });
  }
  return { texter: ut.map((x) => x.text), fran: ut.map((x) => x.fran) };
});

// ── Barnlås ──
// Föräldern (inloggad) låser den här webbläsaren till ett av sina barn: barnet loggas in direkt, utan barnkod och mejlad kod,
// eftersom det är föräldern själv som sitter vid datorn. Svaret bär också låsets märkning.
rutt('POST', '/familj/las', (req, res, b) => {
  const u = kravInloggad(req);
  const barn = ettBarn(u, b.barn_id);
  if (begransad(`las:${u.id}`, 20, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const t = crypto.randomBytes(32).toString('base64url'), las = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO barn_sessioner(token,barn_id,ip,skapad,senast,expires) VALUES(?,?,?,?,?,?)').run(sha(t), barn.id, ipAv(req), now(), now(), now() + BARN_DAGAR * 86_400_000);
  q('DELETE FROM barn_sessioner WHERE barn_id=? AND token NOT IN (SELECT token FROM barn_sessioner WHERE barn_id=? ORDER BY skapad DESC LIMIT ?)').run(barn.id, barn.id, BARN_SESSIONER);
  q('INSERT INTO barn_las(token,barn_id,skapad) VALUES(?,?,?)').run(sha(las), barn.id, now());
  q('DELETE FROM barn_las WHERE barn_id=? AND token NOT IN (SELECT token FROM barn_las WHERE barn_id=? ORDER BY skapad DESC LIMIT 20)').run(barn.id, barn.id);
  q('UPDATE barn SET senast=? WHERE id=?').run(now(), barn.id);
  return { token: t, las, barn: { id: barn.id, namn: barn.namn, alder: barn.alder } };
});
const lasRad = (las) => {
  const r = typeof las === 'string' && las.length >= 20 && q('SELECT l.*, b.namn, b.foralder_id FROM barn_las l JOIN barn b ON b.id=l.barn_id WHERE l.token=?').get(sha(las));
  if (!r) throw fel(404, 'Låset finns inte längre. Logga in som förälder för att ta bort det.');
  return r;
};
const lasMejl = (namn, kod) => ({
  amne: `${kod} – nytt lösenord till barnlåset i AdRaze`,
  html: mejlLayout('Nytt lösenord till barnlåset', mejlText(`Någon vill välja ett nytt lösenord till barnlåset på <b style="color:#17171a">${esc(namn)}</b>s AdRaze-webbläsare. Skriv koden i webbläsaren om det är du.`) +
    mejlKod(kod) + mejlText('Koden gäller i 15 minuter och fungerar bara en gång.') +
    mejlRuta(`<b>Var det inte du?</b> Då försöker någon låsa upp webbläsaren. Ge inte koden till ${esc(namn)}. Låset sitter kvar så länge ingen skriver in koden.`)),
  text: `Någon vill välja ett nytt lösenord till barnlåset på ${namn}s AdRaze-webbläsare.\n\nKod: ${kod}\n\nSkriv koden i webbläsaren om det är du. Koden gäller i 15 minuter.\nVar det inte du? Ge inte koden till ${namn}. Låset sitter kvar.`,
});
// Glömt lösenordet till låset, steg 1: en kod mejlas till föräldern
rutt('POST', '/barn/las-kod', async (req, res, b) => {
  if (begransad(`laskod:${ipAv(req)}`, 15, 900_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const l = lasRad(b.las);
  if (l.kod_sent && now() - l.kod_sent < 45_000) return { skickad: true };
  if (begransadDb(`barnmejl:${l.foralder_id}`, 5, 86_400_000)) throw fel(429, 'Det har skickats många koder i dag. Försök igen i morgon.');
  const foralder = q('SELECT email FROM users WHERE id=?').get(l.foralder_id);
  const kod = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const m = lasMejl(l.namn, kod);
  if (!(await skickaMejl(foralder.email, m.amne, m.html, m.text, undefined, 'familj'))) throw fel(502, 'Vi kunde inte skicka koden just nu. Försök igen om en stund.');
  q('UPDATE barn_las SET kod_hash=?, kod_tries=0, kod_expires=?, kod_sent=? WHERE token=?').run(hmac(`las:${l.token}:${kod}`), now() + KOD_TTL, now(), l.token);
  return { skickad: true };
});
// Steg 2: koden stämmer → webbläsaren får välja ett nytt lösenord (det sparas bara där)
rutt('POST', '/barn/las-verifiera', (req, res, b) => {
  if (begransad(`lasverif:${ipAv(req)}`, 30, 900_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const l = lasRad(b.las);
  if (!l.kod_hash || l.kod_expires < now()) throw fel(410, 'Koden har gått ut. Be om en ny.');
  if (l.kod_tries >= 6) throw fel(429, 'För många fel försök. Be om en ny kod.');
  if (typeof b.kod !== 'string' || !eq(hmac(`las:${l.token}:${b.kod.replace(/\s/g, '')}`), l.kod_hash)) {
    q('UPDATE barn_las SET kod_tries=kod_tries+1 WHERE token=?').run(l.token);
    throw fel(400, 'Fel kod. Kontrollera mejlet och försök igen.');
  }
  q('UPDATE barn_las SET kod_hash=NULL, kod_tries=0, kod_expires=0 WHERE token=?').run(l.token);
  return { godkand: true };
});
// Låset är upplåst: märkningen tas bort
rutt('POST', '/barn/las-bort', (req, res, b) => {
  if (typeof b.las === 'string') q('DELETE FROM barn_las WHERE token=?').run(sha(b.las));
  return {};
});

// Föräldern
rutt('POST', '/familj/barn', (req, res, b) => {
  const u = kravInloggad(req);
  if (q('SELECT COUNT(*) AS n FROM barn WHERE foralder_id=?').get(u.id).n >= BARN_MAX) throw fel(429, `Högst ${BARN_MAX} barn per konto.`);
  const namn = rensaNamn(b.namn), alder = parseInt(b.alder, 10);
  if (!namn || !(alder >= 1 && alder <= 20)) throw fel(400, 'Fyll i namn och ålder (1–20).');
  const id = 'b' + crypto.randomBytes(12).toString('hex'), kod = nyBarnKod(namn);
  q('INSERT INTO barn(id,foralder_id,namn,alder,kod,skapad) VALUES(?,?,?,?,?,?)').run(id, u.id, namn, alder, kod, now());
  return { barn: { id, namn, alder }, kod };
});
rutt('POST', '/familj/lista', (req) => {
  const u = kravInloggad(req);
  const antal = q('SELECT COUNT(*) AS n FROM barn_sessioner WHERE barn_id=? AND expires>?');
  return { barn: q('SELECT * FROM barn WHERE foralder_id=? ORDER BY skapad').all(u.id).map((c) => ({
    id: c.id, namn: c.namn, alder: c.alder, kod: c.kod, blocklista: lasLista(c.blocklista), tillat: aktivaTillat(c.tillat),
    senast: c.senast || 0, inloggningar: antal.get(c.id, now()).n, sparrljud: ljudUt(c),
    fragor: q('SELECT id, host, text, skapad FROM barn_fragor WHERE barn_id=? AND svar IS NULL AND skapad>? ORDER BY skapad DESC LIMIT 20').all(c.id, now() - 7 * 86_400_000) })) };
});
// Föräldern svarar på barnets fråga: ja (i X minuter, eller 0 = alltid) eller nej
rutt('POST', '/familj/svara', (req, res, b) => {
  const u = kravInloggad(req);
  const f = q('SELECT f.*, b.foralder_id, b.tillat, b.blocklista FROM barn_fragor f JOIN barn b ON b.id=f.barn_id WHERE f.id=?').get(parseInt(b.fraga_id, 10) || 0);
  if (!f || f.foralder_id !== u.id) throw fel(404, 'Frågan finns inte.');
  const ja = b.svar === 'ja', min = parseInt(b.minuter, 10);
  if (ja && !(min >= 0 && min <= 100_000)) throw fel(400, 'Ogiltig tid.');
  if (ja && min > 0) {
    const lista = aktivaTillat(f.tillat).filter((a) => a.host !== f.host).concat({ host: f.host, until: now() + min * 60_000 });
    q('UPDATE barn SET tillat=? WHERE id=?').run(JSON.stringify(lista), f.barn_id);
  } else if (ja) {
    const bort = (h) => h === f.host || f.host.endsWith('.' + h) || h.endsWith('.' + f.host);
    q('UPDATE barn SET blocklista=? WHERE id=?').run(JSON.stringify(lasLista(f.blocklista).filter((h) => !bort(fragaHost(h)))), f.barn_id);
  }
  q('UPDATE barn_fragor SET svar=?, minuter=?, svarad=? WHERE id=?').run(ja ? 'ja' : 'nej', ja ? min : null, now(), f.id);
  return { svar: ja ? 'ja' : 'nej' };
});
rutt('POST', '/familj/blocklista', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  const lista = Array.isArray(b.blocklista) ? b.blocklista.slice(0, 500).map((x) => String(x).slice(0, 120)) : [];
  q('UPDATE barn SET blocklista=? WHERE id=?').run(JSON.stringify(lista), c.id);
  return {};
});
rutt('POST', '/familj/sparrljud', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  const id = String(b.ljud || '');
  if (!SPARRLJUD.includes(id)) throw fel(400, 'Okänt ljud.');
  const vol = parseInt(b.volym, 10);
  q('UPDATE barn SET sparrljud=?, sparrljud_vol=? WHERE id=?').run(id, Math.min(80, Math.max(10, Number.isFinite(vol) ? vol : 60)), c.id);
  return { sparrljud: ljudUt(q('SELECT * FROM barn WHERE id=?').get(c.id)) };
});
rutt('POST', '/familj/tillat', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  const host = String(b.host || '').trim().toLowerCase().replace(/^www\./, '').slice(0, 200);
  const min = parseInt(b.minuter, 10);
  if (!host || !(min >= 1 && min <= 100_000)) throw fel(400, 'Ogiltig sida eller tid.');
  const until = now() + min * 60_000;
  const lista = aktivaTillat(c.tillat).filter((a) => a.host !== host).concat({ host, until });
  q('UPDATE barn SET tillat=? WHERE id=?').run(JSON.stringify(lista), c.id);
  return { until };
});
rutt('POST', '/familj/historik', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  return { historik: q('SELECT url, titel, ts FROM barn_historik WHERE barn_id=? ORDER BY ts DESC LIMIT 150').all(c.id) };
});
rutt('POST', '/familj/logga-ut', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  return { avslutade: Number(q('DELETE FROM barn_sessioner WHERE barn_id=?').run(c.id).changes) };
});
rutt('POST', '/familj/byt-kod', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  const kod = nyBarnKod(c.namn);
  q('UPDATE barn SET kod=? WHERE id=?').run(kod, c.id);
  q('DELETE FROM barn_godkann WHERE barn_id=?').run(c.id);
  return { kod, avslutade: Number(q('DELETE FROM barn_sessioner WHERE barn_id=?').run(c.id).changes) };
});
rutt('POST', '/familj/inloggningar', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  return { namn: c.namn, inloggningar: q('SELECT token, ip, skapad, senast FROM barn_sessioner WHERE barn_id=? AND expires>? ORDER BY skapad DESC').all(c.id, now())
    .map((s) => ({ sid: s.token.slice(0, 16), ip: s.ip || null, skapad: s.skapad, senast: s.senast || s.skapad })) };
});
rutt('POST', '/familj/logga-ut-inloggning', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  const sid = String(b.sid || '').replace(/[^a-f0-9]/g, '').slice(0, 64);
  if (sid.length < 8) throw fel(400, 'Okänd inloggning.');
  return { avslutade: Number(q('DELETE FROM barn_sessioner WHERE barn_id=? AND substr(token,1,?)=?').run(c.id, sid.length, sid).changes) };
});
rutt('POST', '/familj/ta-bort', (req, res, b) => {
  const c = ettBarn(kravInloggad(req), b.barn_id);
  q('DELETE FROM barn WHERE id=?').run(c.id);
  return {};
});

// ---------- Stöd oss: Stripes inbäddade kassa (valfritt belopp, engångsbetalning) ----------
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PK = process.env.STRIPE_PUBLISHABLE_KEY || '';
const STOD_PRODUKT = process.env.STOD_PRODUKT || 'prod_VU2VXsEklH4G9R';
const STOD_MIN_ORE = 300;
const STOD_MAX_ORE = 99_999_999;
const SPRAK = new Set(['sv', 'en', 'nb', 'da', 'fi', 'is', 'de', 'nl', 'fr', 'es', 'pt', 'it', 'pl', 'cs', 'sk', 'hu', 'ro', 'bg', 'el', 'hr', 'sl', 'et', 'lv', 'lt', 'uk', 'tr']);

async function stripe(metod, sokvag, falt) {
  const r = await fetch(`https://api.stripe.com/v1/${sokvag}`, {
    method: metod,
    headers: { authorization: `Bearer ${STRIPE_KEY}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: falt ? new URLSearchParams(falt).toString() : undefined,
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { console.error('Stripe', r.status, d.error?.message); throw fel(400, 'Betalningen kunde inte startas. Försök igen.'); }
  return d;
}

rutt('POST', '/stod/kassa', async (req, res, b) => {
  // Donationerna är borttagna (2026-11-08): man stöttar AdRaze genom att köpa Pro i webbläsaren
  throw fel(410, 'Donationer finns inte längre. Stötta AdRaze genom att skaffa Pro i webbläsaren.');
  if (!STRIPE_KEY || !STRIPE_PK) throw fel(400, 'Betalning är inte igång just nu.');
  if (begransad(`stod:${ipAv(req)}`, 20, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  // Belopp i kronor med upp till två decimaler. Gränserna är Stripes: minst 3 kr, högst 8 siffror i ören
  const ore = Math.round(Number(b.belopp) * 100);
  if (!Number.isFinite(ore) || ore < STOD_MIN_ORE || ore > STOD_MAX_ORE) throw fel(400, 'Välj ett belopp mellan 3 och 999 999,99 kr.');
  const sprak = SPRAK.has(b.sprak) ? b.sprak : 'sv';
  const sida = `${SAJT}${sprak === 'sv' ? '' : '/' + sprak}/stod`;
  const s = await stripe('POST', 'checkout/sessions', {
    ui_mode: 'embedded_page',
    mode: 'payment',
    submit_type: 'donate',
    locale: 'auto',
    'line_items[0][price_data][currency]': 'sek',
    'line_items[0][price_data][product]': STOD_PRODUKT,
    'line_items[0][price_data][unit_amount]': String(ore),
    'line_items[0][quantity]': '1',
    'metadata[app]': 'adraze',
    return_url: `${sida}?klar={CHECKOUT_SESSION_ID}`,
  });
  return { clientSecret: s.client_secret, publishableKey: STRIPE_PK };
});

rutt('GET', '/stod/status', async (req) => {
  const id = new URL(req.url, 'http://x').searchParams.get('id') || '';
  if (!/^cs_(live|test)_[A-Za-z0-9]{10,200}$/.test(id)) throw fel(400, 'Okänd betalning.');
  if (begransad(`stodstatus:${ipAv(req)}`, 60, 3_600_000)) throw fel(429, 'För ofta.');
  const s = await stripe('GET', `checkout/sessions/${id}`);
  if (s.metadata?.app !== 'adraze') throw fel(400, 'Okänd betalning.');
  return { status: s.status, belopp: (s.amount_total || 0) / 100 };
});

// Chatten (portad från Säkerkoll-communityn): vänner, grupper, E2E-meddelanden, bilder, stickers m.m. – se CHATT-API.md
require('./chatt.js')({ rutt, q, db, fel, kravInloggad, barnInloggad, nyttKonto, begransad, now, sha, ipAv, crypto, skickaMejl, mejlLayout, mejlText, esc, SAJT });
// Temagalleriet: delade teman med topplista – se galleri.js (efter chatten: skaparens namn är användarnamnet där)
require('./galleri.js')({ rutt, q, db, fel, inloggad, kravInloggad, barnInloggad, begransad, now, sha, ipAv, crypto });

// AdRaze Pro (Stripe-prenumeration) och Falk, AI-assistenten i webbläsaren – se pro.js
const pro = require('./pro.js')({ rutt, q, db, fel, kravInloggad, begransad, now, ipAv });
// Supportärenden (support.adraze.app) – se support.js
require('./support.js')({ rutt, q, db, fel, inloggad, kravInloggad, begransad, now, sha, ipAv, crypto, skickaMejl, mejlLayout, mejlText, esc, normEmail, EMAIL_RE });
require('./synk.js')({ rutt, q, db, fel, kravInloggad, begransad, now });

// Startvärde för id_hogvatten: det högsta id som finns eller som någon tabell fortfarande pekar på (rader som
// blev kvar efter konton som raderades innan högvattnet fanns)
{
  const finnsTabell = (t) => !!q("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
  const pekare = [['users', 'id'], ['synk', 'user_id'], ['support_arenden', 'user_id'], ['chatt_grupper', 'owner_id'], ['chatt_gruppmedlemmar', 'wrapped_by'], ['chatt_rapporter', 'target_id']];
  const hog = Math.max(0, ...pekare.filter(([t]) => finnsTabell(t)).map(([t, k]) => Number(q(`SELECT MAX(${k}) AS m FROM ${t}`).get().m) || 0));
  q("INSERT OR REPLACE INTO id_hogvatten(tabell,max_id) VALUES('users', MAX(?, COALESCE((SELECT max_id FROM id_hogvatten WHERE tabell='users'), 0)))").run(hog);
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  if (origin && ORIGINS.has(origin)) {
    res.setHeader('access-control-allow-origin', origin);
    res.setHeader('access-control-allow-credentials', 'true');
    res.setHeader('vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    if (!origin || !ORIGINS.has(origin)) { res.writeHead(403); return res.end(); }
    res.writeHead(204, { 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type', 'access-control-max-age': '600' });
    return res.end();
  }
  // Inloggning med kakor tas bara emot från vår egen sajt (skydd mot CSRF)
  if (req.method === 'POST' && origin && !ORIGINS.has(origin) && !String(origin).startsWith('chrome-extension://')) return skicka(res, 403, { ok: false, error: 'Fel ursprung.' });
  // En adress som inte går att tolka (t.ex. "//") ska ge 400, inte ett kastat fel utanför try nedan
  let sokvag;
  try { sokvag = new URL(req.url, 'http://x').pathname; } catch { return skicka(res, 400, { ok: false, error: 'Ogiltig adress.' }); }
  // Länkkollen är en egen tjänst (kolla/kolla.js, kör en webbläsare); hit kommer bara de anropen och skickas vidare
  if (sokvag === '/kolla' || sokvag.startsWith('/kolla/')) {
    const ut = http.request({ host: '127.0.0.1', port: KOLLA_PORT, method: req.method, path: req.url,
      headers: { 'content-type': req.headers['content-type'] || '', 'content-length': req.headers['content-length'] || 0, 'cf-connecting-ip': ipAv(req) } }, (svar) => {
      res.writeHead(svar.statusCode, svar.headers);
      svar.pipe(res);
    });
    ut.on('error', () => skicka(res, 503, { ok: false, fel: 'nere' }));
    return req.pipe(ut);
  }
  const fn = rutter[`${req.method} ${sokvag}`];
  if (!fn) return skicka(res, 404, { ok: false, error: 'Finns inte.' });
  try {
    const max = kroppMax[sokvag];
    // Stora kroppar (rutter med höjt tak) läses bara för inloggade konton: annars kan vem som helst ladda upp
    // megabytes och låsa API:ts enda tråd innan rutten ens hinner kontrollera inloggningen.
    if (req.method === 'POST' && max && max > 16_384) {
      // Höjt tak kräver ett inloggat konto (vuxen ELLER barn) innan kroppen läses. barnInloggad kastar, så barnsessionen slås upp utan sidoeffekt här.
      const bt = bearer(req);
      const barnOk = !!(bt && q('SELECT 1 FROM barn_sessioner WHERE token=? AND expires>?').get(sha(bt), now()));
      if (!inloggad(req) && !barnOk) { req.resume(); return skicka(res, 401, { ok: false, error: 'Du är inte inloggad.' }); }
    }
    const b = req.method === 'POST' ? await json(req, max) : {};
    skicka(res, 200, { ok: true, ...(await fn(req, res, b)) });
  } catch (e) {
    if (!e.expose) console.error(req.method, sokvag, e);
    skicka(res, e.status || 500, e.kropp || { ok: false, error: e.expose ? e.message : 'Något gick fel. Försök igen.' });   // e.kropp: rutten bestämmer själv felets form (chatten)
  }
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`adraze-api på 127.0.0.1:${PORT}`);
  // Ett löfte som ingen fångar ska bara loggas, inte döda processen (det nollar alla gränser i minnet).
  // Läggs in först efter listen, så att fel vid start fortfarande stoppar tjänsten och systemd startar om den.
  process.on('unhandledRejection', (e) => console.error('Ohanterat avvisat löfte:', e));
});
server.on('error', (e) => { console.error('Servern kunde inte starta:', e); process.exit(1); });
