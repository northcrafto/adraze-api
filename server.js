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
const SAJT = (process.env.SITE_URL || 'https://adraze.app').replace(/\/$/, '');
const ORIGINS = new Set((process.env.ORIGINS || 'https://adraze.app').split(',').map((s) => s.trim()));
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

// ---------- hjälpare ----------
const now = () => Date.now();
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
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

// ---------- mejl ----------
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Citatförslag från kontosidan går hit
const FORSLAG_TILL = process.env.FORSLAG_TILL || 'cetoari9@gmail.com';
const MAIL_PER_DAG = Number(process.env.MAIL_PER_DAG || 150);
let mejlIdag = { dag: '', n: 0 };
async function skickaMejl(till, amne, html, text, svaraTill) {
  const dag = new Date().toISOString().slice(0, 10);
  if (mejlIdag.dag !== dag) mejlIdag = { dag, n: 0 };
  if (++mejlIdag.n > MAIL_PER_DAG) { console.error('Mejltaket nått för i dag'); return false; }
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
};

async function skickaKod(email, syfte) {
  const rad = q('SELECT sent_at FROM codes WHERE email=? AND purpose=?').get(email, syfte);
  if (rad && now() - rad.sent_at < 45_000) return 'vanta';
  const kod = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  q('INSERT OR REPLACE INTO codes(email,purpose,hash,tries,expires,sent_at) VALUES(?,?,?,0,?,?)').run(email, syfte, sha(`${syfte}:${kod}`), now() + KOD_TTL, now());
  const m = KODMEJL[syfte](kod);
  return (await skickaMejl(email, m.amne, m.html, m.text)) ? 'skickad' : 'fel';
}
function anvandKod(email, syfte, kod) {
  const rad = q('SELECT * FROM codes WHERE email=? AND purpose=?').get(email, syfte);
  if (!rad || rad.expires < now()) return 'utgangen';
  if (rad.tries >= 6) return 'last';
  if (typeof kod !== 'string' || !eq(sha(`${syfte}:${kod.replace(/\s/g, '')}`), rad.hash)) {
    q('UPDATE codes SET tries=tries+1 WHERE email=? AND purpose=?').run(email, syfte);
    return 'fel';
  }
  q('DELETE FROM codes WHERE email=? AND purpose=?').run(email, syfte);
  return 'ok';
}
const KODSVAR = { utgangen: [410, 'Koden har gått ut. Be om en ny.'], last: [429, 'För många fel försök. Be om en ny kod.'], fel: [400, 'Fel kod. Kolla mejlet och försök igen.'] };
function krav(svar) { if (svar !== 'ok') throw fel(...KODSVAR[svar]); }
function kodSkickad(svar) {
  if (svar === 'fel') throw fel(502, 'Vi kunde inte skicka mejlet just nu. Försök igen om en stund.');
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
function nySession(res, userId) {
  const t = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(t), userId, now() + SESSION_DAGAR * 86_400_000);
  laggTillKaka(res, kaka(COOKIE, t, SESSION_DAGAR));
}
function litaPa(res, userId) {
  const t = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO trusted(token,user_id,expires) VALUES(?,?,?)').run(sha(t), userId, now() + ENHET_DAGAR * 86_400_000);
  laggTillKaka(res, kaka(ENHET, t, ENHET_DAGAR));
}
const betrodd = (req, userId) => { const t = kakor(req)[ENHET]; return !!t && !!q('SELECT 1 FROM trusted WHERE token=? AND user_id=? AND expires>?').get(sha(t), userId, now()); };
function inloggad(req) {
  const t = kakor(req)[COOKIE];
  return t ? q('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?').get(sha(t), now()) || null : null;
}
function kravInloggad(req) { const u = inloggad(req); if (!u) throw fel(401, 'Du är inte inloggad.'); return u; }
setInterval(() => {
  q('DELETE FROM sessions WHERE expires<?').run(now());
  q('DELETE FROM trusted WHERE expires<?').run(now());
  q('DELETE FROM codes WHERE expires<?').run(now() - 86_400_000);
  // Konton som aldrig bekräftades frigör sin adress efter ett dygn
  q('DELETE FROM users WHERE verified=0 AND created_at<?').run(now() - 86_400_000);
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
// Bara bokstäver, mellanslag, bindestreck och apostrof; högst 40 tecken
const rensaNamn = (n) => String(n || '').normalize('NFC').replace(/[^\p{L}\p{M} '’-]/gu, '').replace(/\s+/g, ' ').trim().slice(0, 40);
const mig = (u) => ({ email: u.email, namn: u.namn || '', google: !!u.google_sub, losenord: !!u.pass, skapad: u.created_at });

rutt('GET', '/health', () => ({}));
rutt('GET', '/auth/config', () => ({ googleClientId: GOOGLE_CLIENT_ID || null }));

rutt('POST', '/auth/signup', async (req, res, b) => {
  const email = normEmail(b.email);
  if (!EMAIL_RE.test(email)) throw fel(400, 'Skriv en giltig mejladress.');
  const pf = passFel(b.password); if (pf) throw fel(400, pf);
  if (begransad(`signup:${ipAv(req)}`, 8, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const finns = q('SELECT * FROM users WHERE email=?').get(email);
  if (finns?.verified) throw fel(409, 'Det finns redan ett konto med den mejladressen. Logga in i stället.');
  if (finns) q('UPDATE users SET pass=? WHERE id=?').run(hashPass(b.password), finns.id);
  else q('INSERT INTO users(email,pass,verified,created_at) VALUES(?,?,0,?)').run(email, hashPass(b.password), now());
  kodSkickad(await skickaKod(email, 'verify'));
  return { steg: 'kod', syfte: 'verify', email };
});

rutt('POST', '/auth/verify', async (req, res, b) => {
  const email = normEmail(b.email);
  if (begransad(`kod:${email}`, 20, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const u = q('SELECT * FROM users WHERE email=?').get(email);
  if (!u) throw fel(400, 'Fel kod. Kolla mejlet och försök igen.');
  const syfte = u.verified ? 'login' : 'verify';
  krav(anvandKod(email, syfte, b.code));
  if (!u.verified) q('UPDATE users SET verified=1 WHERE id=?').run(u.id);
  nySession(res, u.id);
  litaPa(res, u.id);
  return { me: mig(q('SELECT * FROM users WHERE id=?').get(u.id)) };
});

rutt('POST', '/auth/resend', async (req, res, b) => {
  const email = normEmail(b.email);
  const u = q('SELECT * FROM users WHERE email=?').get(email);
  if (begransad(`resend:${ipAv(req)}`, 10, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  // Bara om det finns en väntande kod, så att man inte kan skicka koder till vem som helst
  const syfte = b.syfte === 'reset' ? 'reset' : u?.verified ? 'login' : 'verify';
  if (!u || !q('SELECT 1 FROM codes WHERE email=? AND purpose=?').get(email, syfte)) return {};
  const svar = await skickaKod(email, syfte);
  if (svar === 'vanta') throw fel(429, 'Vänta en halv minut innan du ber om en ny kod.');
  kodSkickad(svar);
  return {};
});

rutt('POST', '/auth/login', async (req, res, b) => {
  const email = normEmail(b.email);
  if (begransad(`login:${ipAv(req)}`, 20, 900_000) || begransad(`login:${email}`, 10, 900_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const u = q('SELECT * FROM users WHERE email=?').get(email);
  const pass = typeof b.password === 'string' ? b.password : '';
  if (!checkPass(pass, u?.pass) || !u) throw fel(401, 'Fel mejladress eller lösenord.');
  if (!u.verified) { kodSkickad(await skickaKod(email, 'verify')); return { steg: 'kod', syfte: 'verify', email }; }
  if (betrodd(req, u.id)) { nySession(res, u.id); return { me: mig(u) }; }
  const svar = await skickaKod(email, 'login');
  kodSkickad(svar);
  return { steg: 'kod', syfte: 'login', email };
});

rutt('POST', '/auth/google', async (req, res, b) => {
  if (begransad(`google:${ipAv(req)}`, 20, 900_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const g = await verifieraGoogle(b.credential);
  let u = q('SELECT * FROM users WHERE google_sub=?').get(g.sub) || q('SELECT * FROM users WHERE email=?').get(g.email);
  if (u && !u.verified) q('UPDATE users SET pass=NULL WHERE id=?').run(u.id);
  if (u) q('UPDATE users SET google_sub=?, verified=1 WHERE id=?').run(g.sub, u.id);
  else q('INSERT INTO users(email,google_sub,verified,created_at) VALUES(?,?,1,?)').run(g.email, g.sub, now());
  if (g.namn) q("UPDATE users SET namn=? WHERE google_sub=? AND COALESCE(namn,'')=''").run(g.namn, g.sub);
  u = q('SELECT * FROM users WHERE google_sub=?').get(g.sub);
  nySession(res, u.id);
  litaPa(res, u.id);
  return { me: mig(u) };
});

rutt('POST', '/auth/forgot', async (req, res, b) => {
  const email = normEmail(b.email);
  if (!EMAIL_RE.test(email)) throw fel(400, 'Skriv en giltig mejladress.');
  if (begransad(`forgot:${ipAv(req)}`, 6, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  // Samma svar oavsett om kontot finns
  if (q('SELECT 1 FROM users WHERE email=? AND verified=1').get(email)) {
    const svar = await skickaKod(email, 'reset');
    if (svar === 'fel') kodSkickad(svar);
  }
  return { steg: 'kod', syfte: 'reset', email };
});

rutt('POST', '/auth/reset', async (req, res, b) => {
  const email = normEmail(b.email);
  const pf = passFel(b.password); if (pf) throw fel(400, pf);
  if (begransad(`kod:${email}`, 20, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
  const u = q('SELECT * FROM users WHERE email=? AND verified=1').get(email);
  if (!u) throw fel(400, 'Fel kod. Kolla mejlet och försök igen.');
  krav(anvandKod(email, 'reset', b.code));
  q('UPDATE users SET pass=? WHERE id=?').run(hashPass(b.password), u.id);
  // Nytt lösenord: logga ut överallt och glöm betrodda webbläsare
  q('DELETE FROM sessions WHERE user_id=?').run(u.id);
  q('DELETE FROM trusted WHERE user_id=?').run(u.id);
  nySession(res, u.id);
  litaPa(res, u.id);
  return { me: mig(u) };
});

rutt('POST', '/auth/logout', (req, res) => {
  const t = kakor(req)[COOKIE];
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
rutt('GET', '/me', (req) => { const u = kravInloggad(req); return { me: mig(u), ...statistik(u.id) }; });

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

rutt('POST', '/me/delete', async (req, res, b) => {
  const u = kravInloggad(req);
  if (u.pass && !checkPass(typeof b.password === 'string' ? b.password : '', u.pass)) throw fel(401, 'Fel lösenord.');
  q('DELETE FROM users WHERE id=?').run(u.id);
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

http.createServer(async (req, res) => {
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
  const sokvag = new URL(req.url, 'http://x').pathname;
  const fn = rutter[`${req.method} ${sokvag}`];
  if (!fn) return skicka(res, 404, { ok: false, error: 'Finns inte.' });
  try {
    const b = req.method === 'POST' ? await json(req) : {};
    skicka(res, 200, { ok: true, ...(await fn(req, res, b)) });
  } catch (e) {
    if (!e.expose) console.error(req.method, sokvag, e);
    skicka(res, e.status || 500, { ok: false, error: e.expose ? e.message : 'Något gick fel. Försök igen.' });
  }
}).listen(PORT, '127.0.0.1', () => console.log(`adraze-api på 127.0.0.1:${PORT}`));
