// AdRaze-chatten: Säkerkoll-communityns chatt-backend portad till AdRaze-kontona.
// Kopplas in i server.js med require('./chatt.js')({ ... }) före http.createServer.
//
// Samma modell som Säkerkoll (zero-knowledge, E2E):
// - Klienten väljer ett användarnamn och en hemlig kod. Ur namn+kod härleder den en login_hash
//   (bevis på koden) och en wrap-nyckel som krypterar den privata ECDH-nyckeln (enc_priv).
//   Servern sparar bara login_hash, publik nyckel och den KRYPTERADE privata nyckeln.
// - Meddelanden, bilagor, stickers, gruppnamn och gruppbilder är chiffertext; servern läser inget.
// - Inloggningen sköts av AdRaze-kontot (Bearer/kaka via kravInloggad). Chattprofilen hör till users.id.
//
// Varje Säkerkoll-route X finns här som /chatt + X med samma in- och utdata. Path-parametrar
// (:id, :gid) ligger i POST-kroppen resp. query-strängen. Fel svarar som Säkerkoll:
// { ok:false, error:'kod', message:'svensk text', ... } med samma statuskod. Se CHATT-API.md.
'use strict';
const nodeCrypto = require('node:crypto');
const _dns = require('node:dns');
const _net = require('node:net');
const _http = require('node:http');
const _https = require('node:https');

module.exports = function registreraChatt({ rutt, q, db, fel, kravInloggad, begransad, now, sha, ipAv, crypto = nodeCrypto }) {
  // ---------- gränser (samma som Säkerkoll) ----------
  const MESSAGE_MAX_BYTES = 16 * 1024;     // krypterat meddelande (base64-tecken)
  const PUBKEY_MAX = 2000;
  const ENCPRIV_MAX = 4000;
  const HASH_MAX = 200;
  const GROUP_NAME_ENC_MAX = 4000;
  const GROUP_AVATAR_ENC_MAX = 200000;
  const KEY_ENVELOPE_MAX = 1000;
  const ATTACHMENT_MAX_B64 = 2200000;      // ~1,6 MB bild
  const ATTACHMENT_ORPHAN_TTL_MS = 6 * 3600 * 1000;
  const TYPING_TTL_MS = 6000;
  const MAX_GROUP_MEMBERS = 50;
  const BIO_MAX = 300;
  const STICKER_MAX_B64 = 900000;
  const STICKER_MAX_COUNT = 120;
  const REC_SALT_MAX = 64, REC_BLOB_MAX = 600;
  const RENAME_MAX_PER_WEEK = 3;
  const MAX_PROFILES_PER_IP = 60;          // per IP och rullande dygn
  const AVATAR_MAX = 120_000;              // samma som /me/avatar i server.js
  const KVART = 15 * 60 * 1000;

  // Större kroppar än routerns standard (16 kB) bara där det behövs
  const MAX = {
    '/chatt/messages/attachment': ATTACHMENT_MAX_B64 + 100_000,
    '/chatt/stickers': STICKER_MAX_B64 + 50_000,
    '/chatt/reports': 800_000,              // ev. bevisbild ≤700k tecken + utdrag
    '/chatt/groups/avatar': GROUP_AVATAR_ENC_MAX + 10_000,
    '/chatt/groups/create': MAX_GROUP_MEMBERS * (KEY_ENVELOPE_MAX + 200) + GROUP_NAME_ENC_MAX + 2_000,
    '/chatt/users/avatar': AVATAR_MAX + 1_000,
    '/chatt/messages/send': MESSAGE_MAX_BYTES + 2_000,
    '/chatt/groups/messages': MESSAGE_MAX_BYTES + 2_000,
    '/chatt/messages/edit': MESSAGE_MAX_BYTES + 2_000,
    '/chatt/groups/messages/edit': MESSAGE_MAX_BYTES + 2_000,
    '/chatt/groups/members': KEY_ENVELOPE_MAX + 2_000,
    '/chatt/groups/rename': GROUP_NAME_ENC_MAX + 2_000,
    '/chatt/registrera': PUBKEY_MAX + ENCPRIV_MAX + HASH_MAX * 3 + REC_BLOB_MAX + 2_000,
    '/chatt/users/rename': ENCPRIV_MAX + HASH_MAX * 2 + 2_000,
  };
  if (typeof rutt.max === 'function') for (const [p, n] of Object.entries(MAX)) rutt.max(p, n);

  // ---------- tabeller ----------
  db.exec(`
  CREATE TABLE IF NOT EXISTS chatt_profiler(
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    username TEXT NOT NULL, username_lower TEXT NOT NULL UNIQUE,
    login_hash TEXT NOT NULL, public_key TEXT NOT NULL, enc_priv TEXT NOT NULL,
    bio TEXT, bubble TEXT, privacy TEXT,
    rec_salt TEXT, rec_auth TEXT, rec_blob TEXT,
    suspended_until INTEGER NOT NULL DEFAULT 0,
    ip_created TEXT, created_at INTEGER NOT NULL, last_seen INTEGER);
  CREATE INDEX IF NOT EXISTS chatt_profiler_ip ON chatt_profiler(ip_created, created_at);
  CREATE TABLE IF NOT EXISTS chatt_kontakter(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    addressee_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL,
    UNIQUE(requester_id, addressee_id));
  CREATE INDEX IF NOT EXISTS chatt_kontakter_addr ON chatt_kontakter(addressee_id, status);
  CREATE INDEX IF NOT EXISTS chatt_kontakter_req ON chatt_kontakter(requester_id, status);
  CREATE TABLE IF NOT EXISTS chatt_blockeringar(
    blocker_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL, PRIMARY KEY(blocker_id, blocked_id));
  CREATE INDEX IF NOT EXISTS chatt_blockeringar_blocked ON chatt_blockeringar(blocked_id);
  CREATE TABLE IF NOT EXISTS chatt_meddelanden(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL, created_at INTEGER NOT NULL, read_at INTEGER,
    deleted_at INTEGER, edited_at INTEGER, attachment_id TEXT);
  CREATE INDEX IF NOT EXISTS chatt_meddelanden_par ON chatt_meddelanden(recipient_id, sender_id, created_at);
  CREATE INDEX IF NOT EXISTS chatt_meddelanden_avs ON chatt_meddelanden(sender_id, recipient_id, created_at);
  CREATE TABLE IF NOT EXISTS chatt_grupper(
    id TEXT PRIMARY KEY, name_enc TEXT NOT NULL, owner_id INTEGER NOT NULL,
    avatar_enc TEXT, created_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS chatt_gruppmedlemmar(
    group_id TEXT NOT NULL REFERENCES chatt_grupper(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    key_envelope TEXT NOT NULL, wrapped_by INTEGER NOT NULL, joined_at INTEGER NOT NULL,
    last_read_at INTEGER NOT NULL DEFAULT 0, is_admin INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(group_id, user_id));
  CREATE INDEX IF NOT EXISTS chatt_gruppmedlemmar_user ON chatt_gruppmedlemmar(user_id);
  CREATE TABLE IF NOT EXISTS chatt_gruppmeddelanden(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT NOT NULL REFERENCES chatt_grupper(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL, created_at INTEGER NOT NULL,
    deleted_at INTEGER, edited_at INTEGER, attachment_id TEXT);
  CREATE INDEX IF NOT EXISTS chatt_gruppmeddelanden_g ON chatt_gruppmeddelanden(group_id, created_at);
  CREATE TABLE IF NOT EXISTS chatt_dolda(
    user_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    kind TEXT NOT NULL, message_id INTEGER NOT NULL, PRIMARY KEY(user_id, kind, message_id));
  CREATE TABLE IF NOT EXISTS chatt_bilagor(
    id TEXT PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    recipient_id INTEGER REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    group_id TEXT REFERENCES chatt_grupper(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL, bytes INTEGER NOT NULL, created_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
  CREATE INDEX IF NOT EXISTS chatt_bilagor_avs ON chatt_bilagor(sender_id, created_at);
  CREATE TABLE IF NOT EXISTS chatt_namnbyten(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    old_username TEXT NOT NULL, new_username TEXT NOT NULL, created_at INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS chatt_namnbyten_user ON chatt_namnbyten(user_id, created_at);
  CREATE TABLE IF NOT EXISTS chatt_stickers(
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL, bytes INTEGER NOT NULL, created_at INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS chatt_stickers_user ON chatt_stickers(user_id, created_at);
  CREATE TABLE IF NOT EXISTS chatt_rapporter(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL REFERENCES chatt_profiler(user_id) ON DELETE CASCADE,
    target_id INTEGER NOT NULL, reason TEXT NOT NULL, details TEXT,
    message_id TEXT, message_kind TEXT, group_id TEXT, excerpt TEXT, evidence_img TEXT,
    status TEXT NOT NULL DEFAULT 'open', action TEXT, admin_note TEXT,
    created_at INTEGER NOT NULL, resolved_at INTEGER);
  CREATE INDEX IF NOT EXISTS chatt_rapporter_status ON chatt_rapporter(status, created_at);
  CREATE INDEX IF NOT EXISTS chatt_rapporter_target ON chatt_rapporter(target_id);
  CREATE TABLE IF NOT EXISTS chatt_hemligt(nyckel TEXT PRIMARY KEY, varde TEXT NOT NULL);`);

  // Hemlighet för låtsas-salt i recovery/params (stabil över omstarter, så att saltet inte avslöjar vilka namn som finns)
  let HEMLIG = q("SELECT varde FROM chatt_hemligt WHERE nyckel='rec'").get()?.varde;
  if (!HEMLIG) { HEMLIG = crypto.randomBytes(32).toString('hex'); q("INSERT INTO chatt_hemligt(nyckel,varde) VALUES('rec',?)").run(HEMLIG); }

  // ---------- hjälpare ----------
  // Fel i Säkerkolls form ({ error:'kod', message }) med routerns { ok:false }; routern skickar e.kropp som den är
  function E(res, status, error, message, extra) {
    const kropp = { ok: false, error, ...(message ? { message } : {}), ...(extra || {}) };
    return Object.assign(new Error(message || error), { status, expose: true, kropp });
  }
  function grans(req, res, namn, max, ms, msg, perAnvandare) {
    if (begransad(`chatt:${namn}:${perAnvandare ?? ipAv(req)}`, max, ms))
      throw E(res, 429, 'rate_limited', msg || 'För många förfrågningar. Vänta en stund och försök igen.', { retry_after_seconds: Math.ceil(ms / 1000) });
  }
  function tx(fn) {
    db.exec('BEGIN IMMEDIATE');
    try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { try { db.exec('ROLLBACK'); } catch {} throw e; }
  }
  const query = (req) => new URL(req.url, 'http://x').searchParams;
  const idUt = (n) => (n == null ? null : String(n));
  // Användar-id in: "12" eller 12 → 12, annars null
  const idIn = (x) => ((typeof x === 'string' && /^\d{1,15}$/.test(x)) || (Number.isSafeInteger(x) && x > 0) ? Number(x) : null);
  const msgId = (x) => { const n = parseInt(x, 10); return Number.isSafeInteger(n) ? n : 0; };
  const gidIn = (x) => (typeof x === 'string' && x.length <= 64 ? x : null);
  const validUsername = (u) => typeof u === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(u);
  const isSaneB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/=_-]+$/.test(s);
  function timingSafeStrEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const ab = Buffer.from(a), bb = Buffer.from(b);
    return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
  }
  function suspendedBody(until) {
    const perm = until > now() + 50 * 365 * 86400000;
    return { suspended_until: until, message: perm ? 'Ditt konto är avstängt efter en granskad rapport.'
      : 'Ditt konto är avstängt till ' + new Date(until).toLocaleDateString('sv-SE') + ' efter en granskad rapport.' };
  }
  // Alla chatt-rutter: flödesskydd per IP (Säkerkolls communityLimiter: 12 000 / 15 min)
  function bas(req, res) { grans(req, res, 'alla', 12000, KVART, 'För många förfrågningar. Vänta en stund och försök igen.'); }
  // Inloggad med AdRaze-kontot OCH har valt användarnamn
  function profil(req, res) {
    bas(req, res);
    const u = kravInloggad(req);
    const p = q('SELECT * FROM chatt_profiler WHERE user_id=?').get(u.id);
    if (!p) throw E(res, 403, 'no_profile', 'Välj ett användarnamn för chatten först.');
    if (p.suspended_until && p.suspended_until > now()) { const s = suspendedBody(p.suspended_until); throw E(res, 403, 'suspended', s.message, { suspended_until: s.suspended_until }); }
    if (!p.last_seen || now() - p.last_seen > 60_000) q('UPDATE chatt_profiler SET last_seen=? WHERE user_id=?').run(now(), u.id);
    p.id = p.user_id; p.konto = u;
    return p;
  }
  const profilPaNamn = (lower) => q('SELECT user_id AS id, username FROM chatt_profiler WHERE username_lower=?').get(lower);
  const finnsProfil = (id) => !!q('SELECT 1 FROM chatt_profiler WHERE user_id=?').get(id);

  // ---------- brute force-lås (5 fel → 5 min per IP+namn, 60 fel → hela IP:n) ----------
  const loginFails = new Map();
  const failKeys = (ip, who) => (who ? [ip, ip + '|' + String(who).toLowerCase()] : [ip]);
  function loginLockStatus(ip, who) {
    for (const k of failKeys(ip, who)) { const e = loginFails.get(k); if (e && e.lockedUntil > now()) return { locked: true, retryAfter: Math.ceil((e.lockedUntil - now()) / 1000) }; }
    return { locked: false };
  }
  function registerLoginFail(ip, who) {
    let result = { locked: false, remaining: 5 };
    for (const k of failKeys(ip, who)) {
      const per = k.includes('|'), max = per ? 5 : 60;
      const e = loginFails.get(k) || { fails: [], lockedUntil: 0 };
      e.fails = e.fails.filter((t) => t > now() - 300_000); e.fails.push(now());
      if (e.fails.length >= max) { e.lockedUntil = now() + 300_000; e.fails = []; result = { locked: true, retryAfter: 300 }; }
      else if (per) result.remaining = Math.min(result.remaining, max - e.fails.length);
      loginFails.set(k, e);
    }
    return result;
  }
  const clearLoginFails = (ip, who) => loginFails.delete(ip + '|' + String(who).toLowerCase());
  setInterval(() => { for (const [k, e] of loginFails) if (e.lockedUntil < now() && (!e.fails.length || e.fails[e.fails.length - 1] < now() - 300_000)) loginFails.delete(k); }, 300_000).unref();
  function kollaLas(res, ip, who) {
    const l = loginLockStatus(ip, who);
    if (l.locked) { res.setHeader('Retry-After', String(l.retryAfter)); throw E(res, 429, 'locked', `För många felaktiga försök. Vänta ${Math.ceil(l.retryAfter / 60)} min.`); }
  }

  // ---------- integritet, bubbla ----------
  function getPrivacy(uid) {
    let o = {};
    try { const r = q('SELECT privacy FROM chatt_profiler WHERE user_id=?').get(uid); o = r && r.privacy ? JSON.parse(r.privacy) : {}; } catch {}
    return { read_receipts: o.read_receipts !== false, typing: o.typing !== false, requests: o.requests === 'none' ? 'none' : 'all', show_pro: o.show_pro !== false };
  }
  const BUBBLE_FRAMES = new Set(['alg', 'groda', 'katt', 'haj', 'bjorn', 'drake']);
  function parseBubble(s) { if (!s) return null; try { const o = JSON.parse(s); return { color: o.color || null, frame: o.frame || null }; } catch { return null; } }

  // ---------- relationer ----------
  const isBlockedEither = (a, b) => !!q('SELECT 1 FROM chatt_blockeringar WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)').get(a, b, b, a);
  function areContacts(a, b) {
    if (a == null || b == null || isBlockedEither(a, b)) return false;
    return !!q("SELECT 1 FROM chatt_kontakter WHERE status='accepted' AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))").get(a, b, b, a);
  }
  const dropContactRows = (a, b) => q('DELETE FROM chatt_kontakter WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)').run(a, b, b, a);
  const isMember = (gid, uid) => !!(gid && q('SELECT 1 FROM chatt_gruppmedlemmar WHERE group_id=? AND user_id=?').get(gid, uid));
  const isAdmin = (gid, uid) => q('SELECT is_admin FROM chatt_gruppmedlemmar WHERE group_id=? AND user_id=?').get(gid, uid)?.is_admin === 1;
  const genId = () => crypto.randomBytes(12).toString('base64url');
  function tomGruppBort(gid) {
    if (q('SELECT COUNT(*) c FROM chatt_gruppmedlemmar WHERE group_id=?').get(gid).c === 0) q('DELETE FROM chatt_grupper WHERE id=?').run(gid); // meddelanden och bilagor följer med (CASCADE)
    else if (!q('SELECT 1 FROM chatt_gruppmedlemmar WHERE group_id=? AND is_admin=1').get(gid))
      q('UPDATE chatt_gruppmedlemmar SET is_admin=1 WHERE group_id=? AND user_id=(SELECT user_id FROM chatt_gruppmedlemmar WHERE group_id=? ORDER BY joined_at ASC LIMIT 1)').run(gid, gid);
  }

  // ---------- "skriver…" (bara i minnet) ----------
  const typingMap = new Map();
  const typingKey = (kind, a, b) => kind + ':' + a + ':' + b;
  const isTyping = (kind, a, b) => { const t = typingMap.get(typingKey(kind, a, b)); return !!t && t > now() - TYPING_TTL_MS; };
  setInterval(() => { const f = now() - TYPING_TTL_MS; for (const [k, t] of typingMap) if (t < f) typingMap.delete(k); }, 30000).unref();

  // ---------- kodräddning (scrypt av klientens rec_auth) ----------
  const REC_FAKE_KEY = crypto.createHash('sha256').update('rec-fake-salt:' + HEMLIG).digest();
  const recFakeSalt = (lower) => crypto.createHmac('sha256', REC_FAKE_KEY).update(lower).digest().subarray(0, 16).toString('base64');
  const recScrypt = (val, salt) => new Promise((ok, no) => crypto.scrypt(String(val), salt, 32, (e, dk) => (e ? no(e) : ok(dk))));
  async function recHash(auth) { const salt = crypto.randomBytes(16); return salt.toString('hex') + ':' + (await recScrypt(auth, salt)).toString('hex'); }
  async function recVerify(auth, stored) {
    try { const [s, h] = String(stored).split(':'); const want = Buffer.from(h, 'hex'); const dk = await recScrypt(auth, Buffer.from(s, 'hex')); return dk.length === want.length && crypto.timingSafeEqual(dk, want); } catch { return false; }
  }
  const REC_DUMMY = '00000000000000000000000000000000:' + '0'.repeat(64);
  const recNameFails = new Map();
  function recNameLocked(lower) {
    const f = recNameFails.get(lower); if (!f) return 0;
    if (now() - f.first > 3600e3) { recNameFails.delete(lower); return 0; }
    return f.count >= 10 ? Math.ceil((f.first + 3600e3 - now()) / 1000) : 0;
  }
  function recNameFail(lower) {
    const f = recNameFails.get(lower);
    if (!f || now() - f.first > 3600e3) recNameFails.set(lower, { count: 1, first: now() }); else f.count++;
    if (recNameFails.size > 5000) { const cut = now() - 3600e3; for (const [k, v] of recNameFails) if (v.first < cut) recNameFails.delete(k); }
  }
  const recLimit = (req, res) => grans(req, res, 'rec', 60, KVART, 'För många försök. Vänta en stund och försök igen.');

  const avatarAv = (id) => q('SELECT avatar FROM users WHERE id=?').get(id)?.avatar || null;
  function migSjalv(p) {
    return { id: idUt(p.user_id), username: p.username, bubble: parseBubble(p.bubble), has_account: false, account_last4: null,
      has_recovery: !!p.rec_auth, avatar: avatarAv(p.user_id), public_key: p.public_key };
  }

  // ======================================================================
  // Profil: välj användarnamn (ersätter Säkerkolls /users/register + /users/login)
  // ======================================================================
  rutt('GET', '/chatt/jag', (req, res) => {
    bas(req, res);
    const u = kravInloggad(req);
    const p = q('SELECT * FROM chatt_profiler WHERE user_id=?').get(u.id);
    if (!p) {
      // Förslag på användarnamn ur kontots namn (eller mejlen), ledigt just nu
      const a = q('SELECT namn, email FROM users WHERE id=?').get(u.id) || {};
      let bas0 = String(a.namn || String(a.email || '').split('@')[0] || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^A-Za-z0-9_]/g, '').slice(0, 16);
      if (bas0.length < 3) bas0 = (bas0 + 'user').slice(0, 16);
      let forslag = bas0;
      for (let i = 0; i < 30 && q('SELECT 1 FROM chatt_profiler WHERE username_lower=?').get(forslag.toLowerCase()); i++) forslag = bas0 + (Math.floor(Math.random() * 9000) + 100);
      return { profil: null, forslag };
    }
    if (p.suspended_until && p.suspended_until > now()) { const s = suspendedBody(p.suspended_until); throw E(res, 403, 'suspended', s.message, { suspended_until: s.suspended_until }); }
    let auto = false; try { const sec = lasHemlighet(u.id); auto = !!sec && timingSafeStrEqual(p.login_hash, autoHash(sec)); } catch {}
    return { profil: true, ...migSjalv(p), auto };
  });

  rutt('POST', '/chatt/registrera', async (req, res, b) => {
    bas(req, res);
    grans(req, res, 'login', 200, KVART, 'För många försök. Försök igen om en stund.');
    const u = kravInloggad(req);
    if (q('SELECT 1 FROM chatt_profiler WHERE user_id=?').get(u.id)) throw E(res, 409, 'already_registered', 'Du har redan ett användarnamn i chatten.');
    const username = b.username;
    if (!validUsername(username)) throw E(res, 400, 'invalid_username', 'Användarnamn: 3–20 tecken, bara bokstäver, siffror och _.');
    if (!isSaneB64(b.login_hash, HASH_MAX)) throw E(res, 400, 'invalid_login_hash');
    if (!isSaneB64(b.public_key, PUBKEY_MAX)) throw E(res, 400, 'invalid_public_key');
    if (!isSaneB64(b.enc_priv, ENCPRIV_MAX)) throw E(res, 400, 'invalid_enc_priv');
    // Valfritt: lösenordsräddning direkt vid registreringen (samma fält som /users/recovery/set)
    const medRec = b.rec_auth != null || b.rec_blob != null || b.salt != null;
    if (medRec && (!isSaneB64(b.salt, REC_SALT_MAX) || !isSaneB64(b.rec_auth, HASH_MAX) || !isSaneB64(b.rec_blob, REC_BLOB_MAX))) throw E(res, 400, 'invalid_input');
    const lower = username.toLowerCase();
    if (q('SELECT 1 FROM chatt_profiler WHERE username_lower=?').get(lower)) throw E(res, 409, 'username_taken', 'Användarnamnet är upptaget. Välj ett annat.');
    const ip = ipAv(req);
    if (q('SELECT COUNT(*) c FROM chatt_profiler WHERE ip_created=? AND created_at>?').get(ip, now() - 86_400_000).c >= MAX_PROFILES_PER_IP)
      throw E(res, 429, 'too_many_users_per_ip', 'För många konton har skapats från din IP. Försök senare.');
    const rec = medRec ? await recHash(b.rec_auth) : null;
    try {
      q('INSERT INTO chatt_profiler(user_id,username,username_lower,login_hash,public_key,enc_priv,rec_salt,rec_auth,rec_blob,ip_created,created_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(u.id, username, lower, b.login_hash, b.public_key, b.enc_priv, medRec ? b.salt : null, rec, medRec ? b.rec_blob : null, ip, now(), now());
    } catch (e) {
      if (/UNIQUE|PRIMARY/i.test(String(e.message))) throw E(res, 409, 'username_taken', 'Användarnamnet är upptaget. Välj ett annat.');
      throw e;
    }
    return { id: idUt(u.id), username, has_recovery: medRec };
  });

  // Ny enhet: lås upp nycklarna. Motsvarar Säkerkolls /users/login (namn + login_hash → enc_priv),
  // men AdRaze-sessionen krävs och bara den egna profilen kan låsas upp. Ingen token i svaret.
  rutt('POST', '/chatt/users/login', (req, res, b) => {
    grans(req, res, 'login', 200, KVART, 'För många inloggningsförsök. Försök igen om en stund.');
    const p = profil(req, res);
    const ip = ipAv(req);
    const l = loginLockStatus(ip, 'li:' + p.user_id);
    if (l.locked) { res.setHeader('Retry-After', String(l.retryAfter)); throw E(res, 429, 'login_locked', `För många felaktiga försök. Vänta ${Math.ceil(l.retryAfter / 60)} min och försök igen.`, { retry_after_seconds: l.retryAfter }); }
    if (b.username != null && (!validUsername(b.username) || b.username.toLowerCase() !== p.username_lower)) throw E(res, 401, 'invalid_login', 'Fel användarnamn eller kod.');
    if (!isSaneB64(b.login_hash, HASH_MAX)) throw E(res, 400, 'invalid_input');
    if (!timingSafeStrEqual(p.login_hash, b.login_hash)) {
      const f = registerLoginFail(ip, 'li:' + p.user_id);
      if (f.locked) { res.setHeader('Retry-After', String(f.retryAfter)); throw E(res, 429, 'login_locked', 'För många felaktiga försök. Vänta 5 min och försök igen.', { retry_after_seconds: f.retryAfter }); }
      throw E(res, 401, 'invalid_login', 'Fel användarnamn eller kod.', { attempts_left: f.remaining });
    }
    clearLoginFails(ip, 'li:' + p.user_id);
    return { id: idUt(p.user_id), username: p.username, public_key: p.public_key, enc_priv: p.enc_priv, account: null, avatar: avatarAv(p.user_id) };
  });

  // ======================================================================
  // Kontonyckel: chatten låses upp av AdRaze-inloggningen, ingen kod att spara.
  // Varje konto får en slumpad hemlighet (32 byte). Klienten härleder ur den nyckeln som krypterar den
  // privata ECDH-nyckeln (enc_priv) och login_hash = sha256("adraze-chatt-auto-v1:" + hemlighet).
  // Hemligheten sparas krypterad (AES-256-GCM) med CHATT_NYCKEL från .env – den finns aldrig i databasen,
  // så en databasläcka räcker inte för att läsa någons meddelanden.
  // ======================================================================
  db.exec(`CREATE TABLE IF NOT EXISTS chatt_nycklar(
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc TEXT NOT NULL, created_at INTEGER NOT NULL);`);
  const MASTER = /^[0-9a-f]{64}$/i.test(process.env.CHATT_NYCKEL || '') ? Buffer.from(process.env.CHATT_NYCKEL, 'hex') : null;
  if (!MASTER) console.error('chatt: CHATT_NYCKEL saknas i .env – automatisk upplåsning av chatten är avstängd');
  function lasHemlighet(uid) {
    const r = q('SELECT secret_enc FROM chatt_nycklar WHERE user_id=?').get(uid);
    if (!r || !MASTER) return null;
    const b = Buffer.from(r.secret_enc, 'base64');
    const d = nodeCrypto.createDecipheriv('aes-256-gcm', MASTER, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28)); d.setAAD(Buffer.from('chatt:' + uid));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('base64');
  }
  function kontoHemlighet(uid) {
    const har = lasHemlighet(uid); if (har) return har;
    if (!MASTER) return null;
    const sec = nodeCrypto.randomBytes(32), iv = nodeCrypto.randomBytes(12);
    const c = nodeCrypto.createCipheriv('aes-256-gcm', MASTER, iv); c.setAAD(Buffer.from('chatt:' + uid));
    const ct = Buffer.concat([c.update(sec), c.final()]);
    q('INSERT OR IGNORE INTO chatt_nycklar(user_id, secret_enc, created_at) VALUES(?,?,?)').run(uid, Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64'), now());
    return lasHemlighet(uid);   // läs tillbaka (två samtidiga anrop får samma hemlighet)
  }
  const autoHash = (secB64) => nodeCrypto.createHash('sha256').update('adraze-chatt-auto-v1:' + secB64).digest('base64');

  rutt('GET', '/chatt/nyckel', (req, res) => {
    bas(req, res);
    grans(req, res, 'nyckel', 60, KVART, 'För många försök. Vänta en stund och försök igen.');
    const u = kravInloggad(req);
    const secret = kontoHemlighet(u.id);
    if (!secret) throw E(res, 503, 'unavailable', 'Chatten kan inte låsas upp just nu. Försök igen senare.');
    res.setHeader('Cache-Control', 'no-store');
    return { secret };
  });

  // Byt till kontonyckeln (profiler från tiden med hemlig kod). Nya nycklar ⇒ gamla meddelanden går inte att läsa.
  rutt('POST', '/chatt/users/ny-nyckel', (req, res, b) => {
    grans(req, res, 'nynyckel', 10, 3600_000, 'För många försök. Vänta en stund och försök igen.');
    const p = profil(req, res);
    const secret = kontoHemlighet(p.user_id);
    if (!secret) throw E(res, 503, 'unavailable', 'Chatten kan inte låsas upp just nu. Försök igen senare.');
    if (!isSaneB64(b.public_key, PUBKEY_MAX) || !isSaneB64(b.enc_priv, ENCPRIV_MAX) || !isSaneB64(b.login_hash, HASH_MAX)) throw E(res, 400, 'invalid_input');
    if (!timingSafeStrEqual(autoHash(secret), b.login_hash)) throw E(res, 403, 'wrong_code', 'Fel nyckel.');
    q('UPDATE chatt_profiler SET public_key=?, enc_priv=?, login_hash=?, rec_salt=NULL, rec_auth=NULL, rec_blob=NULL WHERE user_id=?').run(b.public_key, b.enc_priv, b.login_hash, p.user_id);
    return { public_key: b.public_key };
  });

  rutt('GET', '/chatt/users/me', (req, res) => {
    const p = profil(req, res);
    const m = migSjalv(p);
    return { id: m.id, username: m.username, bubble: m.bubble, has_account: false, account_last4: null, has_recovery: m.has_recovery, avatar: m.avatar };
  });

  rutt('GET', '/chatt/users/privacy', (req, res) => ({ privacy: getPrivacy(profil(req, res).id) }));
  rutt('POST', '/chatt/users/privacy', (req, res, b) => {
    const me = profil(req, res).id, cur = getPrivacy(me);
    for (const k of ['read_receipts', 'typing', 'show_pro']) if (typeof b[k] === 'boolean') cur[k] = b[k];
    if (b.requests === 'all' || b.requests === 'none') cur.requests = b.requests;
    q('UPDATE chatt_profiler SET privacy=? WHERE user_id=?').run(JSON.stringify(cur), me);
    if (!cur.typing) for (const k of typingMap.keys()) if (k.startsWith('dm:' + me + ':') || k.endsWith(':' + me)) typingMap.delete(k);
    return { privacy: cur };
  });

  rutt('POST', '/chatt/users/bubble', (req, res, b) => {
    const me = profil(req, res).id;
    const color = typeof b.color === 'string' && /^#[0-9a-f]{6}$/i.test(b.color) ? b.color.toLowerCase() : null;
    const frame = typeof b.frame === 'string' && BUBBLE_FRAMES.has(b.frame) ? b.frame : null;
    if ((b.color && !color) || (b.frame && !frame)) throw E(res, 400, 'invalid_bubble');
    const val = color || frame ? JSON.stringify({ color, frame }) : null;
    q('UPDATE chatt_profiler SET bubble=? WHERE user_id=?').run(val, me);
    return { bubble: parseBubble(val) };
  });

  // Profilbilden är AdRaze-kontots (users.avatar). Samma kontroll som /me/avatar i server.js.
  rutt('POST', '/chatt/users/avatar', (req, res, b) => {
    const p = profil(req, res);
    grans(req, res, 'avatar', 20, 3_600_000, 'För många byten. Vänta en stund.', p.id);
    if (b.avatar === null || b.avatar === '') { q('UPDATE users SET avatar=NULL WHERE id=?').run(p.id); return { avatar: null }; }
    const m = typeof b.avatar === 'string' && b.avatar.length <= AVATAR_MAX && /^data:image\/jpeg;base64,([A-Za-z0-9+/]+=*)$/.exec(b.avatar);
    const bytes = m && Buffer.from(m[1], 'base64');
    if (!bytes || bytes.length < 200 || bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes[2] !== 0xff) throw E(res, 400, 'invalid_avatar', 'Bilden är för stor eller i fel format.');
    q('UPDATE users SET avatar=? WHERE id=?').run(b.avatar, p.id);
    return { avatar: b.avatar };
  });

  // ---------- kod, räddning, namnbyte, radering ----------
  rutt('POST', '/chatt/users/verify-code', (req, res, b) => {
    const p = profil(req, res); recLimit(req, res);
    const ip = ipAv(req), who = 'vc:' + p.user_id;
    kollaLas(res, ip, who);
    if (!isSaneB64(b.login_hash, HASH_MAX) || !timingSafeStrEqual(p.login_hash, b.login_hash)) { registerLoginFail(ip, who); throw E(res, 403, 'wrong_code', 'Fel kod.'); }
    clearLoginFails(ip, who);
    return { enc_priv: p.enc_priv };
  });

  rutt('POST', '/chatt/users/recovery/params', (req, res, b) => {
    bas(req, res); recLimit(req, res);
    if (!validUsername(b.username)) throw E(res, 400, 'invalid_input');
    const lower = b.username.toLowerCase();
    const r = q('SELECT rec_salt FROM chatt_profiler WHERE username_lower=?').get(lower);
    return { salt: (r && r.rec_salt) || recFakeSalt(lower) };
  });

  rutt('POST', '/chatt/users/recovery/set', async (req, res, b) => {
    const p = profil(req, res); recLimit(req, res);
    if (!isSaneB64(b.login_hash, HASH_MAX) || !isSaneB64(b.salt, REC_SALT_MAX) || !isSaneB64(b.rec_auth, HASH_MAX) || !isSaneB64(b.rec_blob, REC_BLOB_MAX)) throw E(res, 400, 'invalid_input');
    const ip = ipAv(req), who = 'rs:' + p.user_id;
    kollaLas(res, ip, who);
    if (!timingSafeStrEqual(p.login_hash, b.login_hash)) { registerLoginFail(ip, who); throw E(res, 403, 'wrong_code', 'Fel kod.'); }
    clearLoginFails(ip, who);
    q('UPDATE chatt_profiler SET rec_salt=?, rec_auth=?, rec_blob=? WHERE user_id=?').run(b.salt, await recHash(b.rec_auth), b.rec_blob, p.id);
    return { has_recovery: true };
  });

  // Visa koden. Hos Säkerkoll öppen utan inloggning; här krävs AdRaze-kontot och namnet måste vara ens eget.
  rutt('POST', '/chatt/users/recovery/reveal', async (req, res, b) => {
    bas(req, res); recLimit(req, res);
    const u = kravInloggad(req);
    if (!validUsername(b.username) || !isSaneB64(b.rec_auth, HASH_MAX)) throw E(res, 400, 'invalid_input');
    // Namnlåset gäller den som frågar (kontot), inte namnet: rutten lyckas bara för ens eget namn, så en
    // främling ska inte kunna låsa någon annans "Visa koden" genom att gissa fel på deras namn
    const ip = ipAv(req), lower = b.username.toLowerCase(), who = 'rec:' + lower, lasNyckel = 'id:' + u.id;
    const lock = loginLockStatus(ip, who), nameLock = recNameLocked(lasNyckel);
    if (lock.locked || nameLock) {
      const wait = Math.max(lock.locked ? lock.retryAfter : 0, nameLock);
      res.setHeader('Retry-After', String(wait));
      throw E(res, 429, 'locked', `För många felaktiga försök. Vänta ${Math.ceil(wait / 60)} min och försök igen.`);
    }
    const p = q('SELECT user_id, username, rec_auth, rec_blob FROM chatt_profiler WHERE username_lower=?').get(lower);
    const ok = await recVerify(b.rec_auth, (p && p.rec_auth) || REC_DUMMY);
    if (!p || p.user_id !== u.id || !p.rec_auth || !p.rec_blob || !ok) {
      registerLoginFail(ip, who); recNameFail(lasNyckel);
      throw E(res, 403, 'invalid_recovery', 'Fel användarnamn eller lösenord — eller så har kontot inget lösenord sparat.');
    }
    clearLoginFails(ip, who);
    return { username: p.username, rec_blob: p.rec_blob };
  });

  rutt('POST', '/chatt/users/recovery/remove', async (req, res, b) => {
    const p = profil(req, res); recLimit(req, res);
    if (!isSaneB64(b.rec_auth, HASH_MAX)) throw E(res, 400, 'invalid_input');
    if (!p.rec_auth || !(await recVerify(b.rec_auth, p.rec_auth))) throw E(res, 403, 'invalid_recovery', 'Fel lösenord.');
    q('UPDATE chatt_profiler SET rec_salt=NULL, rec_auth=NULL, rec_blob=NULL WHERE user_id=?').run(p.id);
    return { has_recovery: false };
  });

  rutt('POST', '/chatt/users/rename', (req, res, b) => {
    const p = profil(req, res); recLimit(req, res);
    const nu = b.new_username;
    if (!validUsername(nu)) throw E(res, 400, 'invalid_username', 'Användarnamn: 3–20 tecken, bara bokstäver, siffror och _.');
    if (!isSaneB64(b.old_login_hash, HASH_MAX) || !isSaneB64(b.new_login_hash, HASH_MAX) || !isSaneB64(b.enc_priv, ENCPRIV_MAX)) throw E(res, 400, 'invalid_input');
    const ip = ipAv(req), who = 'rn:' + p.user_id;
    kollaLas(res, ip, who);
    if (!timingSafeStrEqual(p.login_hash, b.old_login_hash)) { registerLoginFail(ip, who); throw E(res, 403, 'wrong_code', 'Fel kod.'); }
    clearLoginFails(ip, who);
    const lower = nu.toLowerCase();
    if (nu === p.username) throw E(res, 400, 'same_username', 'Det är redan ditt användarnamn.');
    if (q('SELECT COUNT(*) c FROM chatt_namnbyten WHERE user_id=? AND created_at>?').get(p.id, now() - 7 * 86400e3).c >= RENAME_MAX_PER_WEEK)
      throw E(res, 429, 'too_many_renames', `Du kan byta användarnamn högst ${RENAME_MAX_PER_WEEK} gånger per vecka. Försök igen om några dagar.`);
    try {
      tx(() => {
        if (q('SELECT 1 FROM chatt_profiler WHERE username_lower=? AND user_id!=?').get(lower, p.id)) throw Object.assign(new Error('taken'), { taken: true });
        q('UPDATE chatt_profiler SET username=?, username_lower=?, login_hash=?, enc_priv=? WHERE user_id=?').run(nu, lower, b.new_login_hash, b.enc_priv, p.id);
        q('INSERT INTO chatt_namnbyten(user_id,old_username,new_username,created_at) VALUES(?,?,?,?)').run(p.id, p.username, nu, now());
      });
    } catch (e) {
      if (e.taken || /UNIQUE/i.test(String(e.message))) throw E(res, 409, 'username_taken', 'Användarnamnet är upptaget. Välj ett annat.');
      throw e;
    }
    return { username: nu };
  });

  // Radera chattprofilen (inte AdRaze-kontot). Kräver koden. Allt kopplat följer med (CASCADE).
  rutt('POST', '/chatt/users/delete', (req, res, b) => {
    const p = profil(req, res); recLimit(req, res);
    const ip = ipAv(req), who = 'del:' + p.user_id;
    kollaLas(res, ip, who);
    if (!isSaneB64(b.login_hash, HASH_MAX) || !timingSafeStrEqual(p.login_hash, b.login_hash)) { registerLoginFail(ip, who); throw E(res, 403, 'wrong_code', 'Fel kod.'); }
    clearLoginFails(ip, who);
    const me = p.id;
    tx(() => {
      const gids = q('SELECT group_id FROM chatt_gruppmedlemmar WHERE user_id=?').all(me).map((r) => r.group_id);
      q('DELETE FROM chatt_profiler WHERE user_id=?').run(me);
      for (const gid of gids) tomGruppBort(gid);
    });
    for (const k of typingMap.keys()) if (k.includes(':' + me)) typingMap.delete(k);
    return {};
  });

  // ---------- rapporter (sparas; granskning i ägarpanel finns inte än) ----------
  const REPORT_REASONS = { spam: 'Spam eller reklam', scam: 'Bedrägeri eller bluff', harassment: 'Trakasserier eller mobbning', threat: 'Hot eller våld',
    hate: 'Hatiskt innehåll', sexual: 'Sexuellt innehåll', impersonation: 'Utger sig för att vara någon annan', doxxing: 'Sprider privata uppgifter',
    child: 'Ett barn kan vara i fara', other: 'Annat' };
  rutt('POST', '/chatt/reports', (req, res, b) => {
    grans(req, res, 'rapport', 15, 3_600_000, 'Du har rapporterat många gånger på kort tid. Vänta en stund.');
    const me = profil(req, res).id;
    const reason = String(b.reason || '');
    if (!REPORT_REASONS[reason]) throw E(res, 400, 'invalid_reason', 'Välj en anledning.');
    const uname = String(b.username || '').toLowerCase();
    if (!validUsername(uname)) throw E(res, 400, 'invalid_username');
    const target = profilPaNamn(uname);
    if (!target) throw E(res, 404, 'user_not_found', 'Användaren finns inte längre.');
    if (target.id === me) throw E(res, 400, 'cant_report_self', 'Du kan inte rapportera dig själv.');
    const details = typeof b.details === 'string' ? b.details.trim().slice(0, 1000) : '';
    if (reason === 'other' && details.length < 3) throw E(res, 400, 'details_required', 'Beskriv kort vad det gäller.');
    const messageId = b.message_id != null ? String(b.message_id).replace(/[^0-9a-z]/gi, '').slice(0, 40) : null;
    const kind = b.message_kind === 'group' ? 'group' : b.message_kind === 'dm' ? 'dm' : null;
    const groupId = kind === 'group' && typeof b.group_id === 'string' ? b.group_id.slice(0, 64) : null;
    if (!areContacts(me, target.id) && !(groupId && isMember(groupId, me) && isMember(groupId, target.id))
      && !q('SELECT 1 FROM chatt_kontakter WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)').get(me, target.id, target.id, me)
      && !q('SELECT 1 FROM chatt_blockeringar WHERE blocker_id=? AND blocked_id=?').get(me, target.id))
      throw E(res, 403, 'no_relation', 'Du kan bara rapportera personer du har haft kontakt med.');
    const excerpt = typeof b.excerpt === 'string' ? b.excerpt.slice(0, 2000) : null;
    let img = typeof b.evidence_img === 'string' ? b.evidence_img : null;
    if (img && (img.length > 700000 || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(img))) img = null;
    if (messageId && q("SELECT 1 FROM chatt_rapporter WHERE reporter_id=? AND message_id=? AND status='open'").get(me, messageId)) return { duplicate: true };
    q('INSERT INTO chatt_rapporter(reporter_id,target_id,reason,details,message_id,message_kind,group_id,excerpt,evidence_img,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .run(me, target.id, reason, details || null, messageId, kind, groupId, excerpt, img, now());
    return {};
  });

  // ======================================================================
  // Länkkoll: hotlistor (URLhaus, OpenPhish, Phishing.Database) laddas i minnet varje timme
  // ======================================================================
  const threat = { urls: new Set(), hosts: new Map(), phishDomains: new Set(), updatedAt: 0, counts: {} };
  function normUrl(u) {
    try { const x = new URL(u); x.hash = ''; return x.protocol + '//' + x.hostname.toLowerCase() + (x.port ? ':' + x.port : '') + x.pathname.replace(/\/+$/, '') + x.search; } catch { return null; }
  }
  async function fetchText(url) {
    const r = await fetch(url, { signal: AbortSignal.timeout(60000), headers: { 'User-Agent': 'AdRaze-linkcheck/1.0' }, redirect: 'follow' });
    if (!r.ok) throw new Error(url + ' ' + r.status);
    return r.text();
  }
  async function refreshThreatLists() {
    const next = { urls: new Set(), hosts: new Map(), phishDomains: new Set(), counts: {} };
    const addUrlList = (txt, src) => {
      let n = 0;
      for (const line of txt.split('\n')) {
        const l = line.trim(); if (!l || l[0] === '#') continue;
        const u = normUrl(l); if (!u) continue;
        next.urls.add(u);
        try { const h = new URL(l).hostname.toLowerCase(); if (!next.hosts.has(h)) next.hosts.set(h, src); } catch {}
        n++;
      }
      next.counts[src] = n;
    };
    const res = await Promise.allSettled([
      fetchText('https://urlhaus.abuse.ch/downloads/text_online/').then((t) => addUrlList(t, 'urlhaus')),
      fetchText('https://openphish.com/feed.txt').then((t) => addUrlList(t, 'openphish')),
      fetchText('https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt').then((t) => {
        let n = 0; for (const line of t.split('\n')) { const d = line.trim().toLowerCase(); if (d && d[0] !== '#') { next.phishDomains.add(d); n++; } } next.counts.phishdb = n;
      }),
    ]);
    res.forEach((r) => { if (r.status === 'rejected') console.error('[chatt länkkoll] lista misslyckades:', r.reason && r.reason.message); });
    if (!next.counts.phishdb && threat.phishDomains.size) { next.phishDomains = threat.phishDomains; next.counts.phishdb = threat.counts.phishdb; }
    if (!next.urls.size && threat.urls.size) { next.urls = threat.urls; next.hosts = threat.hosts; Object.assign(next.counts, { urlhaus: threat.counts.urlhaus, openphish: threat.counts.openphish }); }
    Object.assign(threat, next, { updatedAt: now() });
    console.log('[chatt länkkoll] listor laddade', JSON.stringify(threat.counts));
  }
  if (process.env.CHATT_HOTLISTOR !== '0') {
    setTimeout(() => refreshThreatLists().catch(() => {}), 5000).unref();
    setInterval(() => refreshThreatLists().catch(() => {}), 3_600_000).unref();
  }
  const LIST_NAMES = { urlhaus: 'URLhaus (skadlig kod)', openphish: 'OpenPhish (nätfiske)', phishdb: 'Phishing.Database (nätfiske)' };
  const SHARED_HOSTS = /(^|\.)(github\.com|githubusercontent\.com|github\.io|gitlab\.com|google\.com|googleusercontent\.com|googleapis\.com|dropbox\.com|dropboxusercontent\.com|discord\.com|discordapp\.com|discordapp\.net|onedrive\.live\.com|1drv\.ms|sharepoint\.com|amazonaws\.com|cloudfront\.net|azureedge\.net|blob\.core\.windows\.net|mediafire\.com|mega\.nz|we\.tl|wetransfer\.com|bitbucket\.org|sourceforge\.net|pastebin\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|vercel\.app|netlify\.app|pages\.dev|web\.app|firebaseapp\.com|000webhostapp\.com|weebly\.com|wixsite\.com|blogspot\.com|wordpress\.com|telegram\.org|t\.me)$/i;

  rutt('POST', '/chatt/links/check', (req, res, b) => {
    grans(req, res, 'lankkoll', 120, KVART, 'För många länkkollar. Vänta en stund.');
    profil(req, res);
    const raw = String(b.url || '').slice(0, 2048);
    let u; try { u = new URL(raw); } catch { throw E(res, 400, 'invalid_url'); }
    if (!/^https?:$/.test(u.protocol)) return { verdict: 'danger', hits: [{ why: 'Inte en vanlig webblänk.' }] };
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    const hits = [];
    const nu = normUrl(u.href);
    if (nu && threat.urls.has(nu)) hits.push({ why: 'Exakt den här länken finns i en lista över farliga länkar.', list: LIST_NAMES[threat.hosts.get(host)] || 'hotlista' });
    const parts = host.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const d = parts.slice(i).join('.');
      if (threat.phishDomains.has(d)) { hits.push({ why: 'Domänen ' + d + ' är känd för nätfiske.', list: LIST_NAMES.phishdb }); break; }
    }
    if (!hits.length && threat.hosts.has(host) && !SHARED_HOSTS.test(host)) hits.push({ why: 'Den här sajten har spridit skadliga länkar nyligen.', list: LIST_NAMES[threat.hosts.get(host)], soft: true });
    const verdict = hits.some((h) => !h.soft) ? 'danger' : hits.length ? 'warn' : 'clean';
    return { verdict, hits, lists_updated_at: threat.updatedAt, lists_ready: threat.updatedAt > 0 };
  });

  // ---------- länkförhandsvisning: servern hämtar åt avsändaren, SSRF-skyddat ----------
  // Samma kontroll som Falks sidläsning (webb.js): IPv6 bara global unicast, inga inbäddade/interna former
  const isPublicIp = require('./webb.js').isPublicIp;
  function safeLookup(host, opts, cb) {
    _dns.lookup(host, { all: true }, (err, addrs) => {
      if (err) return cb(err);
      const ok = (addrs || []).filter((a) => isPublicIp(a.address));
      if (!ok.length || ok.length !== addrs.length) return cb(new Error('blocked_address'));
      if (opts && opts.all) return cb(null, ok);
      cb(null, ok[0].address, ok[0].family);
    });
  }
  function safeGet(urlStr, maxBytes, accept, hops = 0) {
    return new Promise((resolve, reject) => {
      let u; try { u = new URL(urlStr); } catch { return reject(new Error('bad_url')); }
      if (!/^https?:$/.test(u.protocol)) return reject(new Error('bad_proto'));
      if (u.port && !['80', '443'].includes(u.port)) return reject(new Error('bad_port'));
      if (u.username || u.password) return reject(new Error('bad_url'));
      const bare = u.hostname.replace(/^\[|\]$/g, '');
      if (_net.isIP(bare) && !isPublicIp(bare)) return reject(new Error('blocked_address'));
      const mod = u.protocol === 'https:' ? _https : _http;
      const r = mod.request(u, { method: 'GET', lookup: safeLookup, timeout: 6000, agent: false, headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; AdRazePreview/1.0; +https://adraze.app)', Accept: accept, 'Accept-Language': 'sv,en;q=0.8' } }, (svar) => {
        if ([301, 302, 303, 307, 308].includes(svar.statusCode) && svar.headers.location) {
          svar.resume();
          if (hops >= 3) return reject(new Error('too_many_redirects'));
          let nx; try { nx = new URL(svar.headers.location, u).href; } catch { return reject(new Error('bad_redirect')); }
          return safeGet(nx, maxBytes, accept, hops + 1).then(resolve, reject);
        }
        if (svar.statusCode !== 200) { svar.resume(); return reject(new Error('status_' + svar.statusCode)); }
        const chunks = []; let n = 0;
        svar.on('data', (c) => { n += c.length; if (n > maxBytes) { chunks.push(c.subarray(0, Math.max(0, c.length - (n - maxBytes)))); svar.destroy(); } else chunks.push(c); });
        svar.on('close', () => resolve({ url: u.href, type: String(svar.headers['content-type'] || '').toLowerCase(), body: Buffer.concat(chunks) }));
        svar.on('error', reject);
      });
      r.on('timeout', () => r.destroy(new Error('timeout')));
      r.on('error', reject);
      r.end();
    });
  }
  function decodeEntities(t) {
    return String(t).replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi, (m, e) => {
      const l = e.toLowerCase();
      if (l[0] === '#') { const cp = l[1] === 'x' ? parseInt(l.slice(2), 16) : parseInt(l.slice(1), 10); try { return String.fromCodePoint(cp); } catch { return ''; } }
      return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }[l];
    });
  }
  const cleanText = (t, max) => decodeEntities(t || '').replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
  function metaContent(html, attr, name) {
    const tag = (html.match(new RegExp('<meta[^>]+' + attr + '\\s*=\\s*["\']' + name + '["\'][^>]*>', 'i')) || [])[0]; if (!tag) return '';
    return ((tag.match(/content\s*=\s*"([^"]*)"/i) || tag.match(/content\s*=\s*'([^']*)'/i) || [])[1]) || '';
  }
  function sniffImage(b) {
    if (b.length < 4) return null;
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'image/png';
    if (b[0] === 0xff && b[1] === 0xd8) return 'image/jpeg';
    if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return 'image/gif';
    if (b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00) return 'image/x-icon';
    if (b.length > 12 && b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') return 'image/webp';
    return null; // SVG och allt annat avvisas
  }
  // ClamAV (clamd) om den finns; svarar den inte visas förhandsvisningen ändå, som i Säkerkoll
  const CLAMD_HOST = process.env.CLAMD_HOST || '127.0.0.1', CLAMD_PORT = +(process.env.CLAMD_PORT || 3310);
  function clamScan(buf) {
    return new Promise((resolve) => {
      const sock = _net.connect(CLAMD_PORT, CLAMD_HOST);
      let out = '', done = false;
      const fin = (r) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve(r); } };
      sock.setTimeout(25000, () => fin({ error: 'timeout' }));
      sock.on('error', (e) => fin({ error: e.code || e.message }));
      sock.on('data', (d) => { out += d.toString(); if (out.includes('\0') || /\n$/.test(out)) sock.end(); });
      sock.on('close', () => {
        const r = out.replace(/\0/g, '').trim();
        if (/FOUND$/.test(r)) fin({ found: r.replace(/^stream:\s*/, '').replace(/\s*FOUND$/, '') });
        else if (/OK$/.test(r)) fin({ ok: true }); else fin({ error: r || 'no_reply' });
      });
      sock.on('connect', () => {
        sock.write('zINSTREAM\0');
        for (let i = 0; i < buf.length; i += 65536) { const c = buf.subarray(i, i + 65536), h = Buffer.alloc(4); h.writeUInt32BE(c.length); sock.write(h); sock.write(c); }
        sock.write(Buffer.alloc(4));
      });
    });
  }
  const previewCache = new Map();
  rutt('POST', '/chatt/links/preview', async (req, res, b) => {
    grans(req, res, 'forhand', 60, KVART, 'För många förhandsvisningar. Vänta en stund.');
    profil(req, res);
    const raw = String(b.url || '').slice(0, 2048);
    let u; try { u = new URL(raw); } catch { throw E(res, 400, 'invalid_url'); }
    if (!/^https?:$/.test(u.protocol)) throw E(res, 400, 'invalid_url');
    u.hash = '';
    const key = u.href;
    const hit = previewCache.get(key);
    if (hit && hit.at > now() - 6 * 3600000) return hit.data;
    const host = u.hostname.toLowerCase(), nu = normUrl(u.href), parts = host.split('.');
    const listed = (nu && threat.urls.has(nu)) || parts.some((_, i) => i < parts.length - 1 && threat.phishDomains.has(parts.slice(i).join('.')));
    if (listed) return { blocked: true };
    const data = { url: u.href, title: '', desc: '', site: '', icon: null };
    try {
      const page = await safeGet(u.href, 300000, 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1');
      const av = await clamScan(page.body);
      if (av.found) { const d2 = { blocked: true, reason: 'clamav' }; previewCache.set(key, { at: now(), data: d2 }); return d2; }
      if (/text\/html|xhtml/.test(page.type)) {
        const head = page.body.toString('utf8').slice(0, 200000);
        data.title = cleanText(metaContent(head, 'property', 'og:title') || metaContent(head, 'name', 'twitter:title') || ((head.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]) || '', 120);
        data.desc = cleanText(metaContent(head, 'property', 'og:description') || metaContent(head, 'name', 'description') || metaContent(head, 'name', 'twitter:description'), 240);
        data.site = cleanText(metaContent(head, 'property', 'og:site_name'), 60);
        const cands = [];
        for (const l of head.match(/<link[^>]+>/gi) || []) {
          const rel = ((l.match(/rel\s*=\s*["']([^"']+)["']/i) || [])[1] || '').toLowerCase();
          if (!/(^|\s)(icon|shortcut icon|apple-touch-icon)(\s|$)/.test(rel) && rel !== 'shortcut icon') continue;
          const href = (l.match(/href\s*=\s*["']([^"']+)["']/i) || [])[1]; if (!href) continue;
          if (/\.svg(\?|$)/i.test(href) || /image\/svg/i.test(l)) continue;
          try { cands.push({ href: new URL(decodeEntities(href), page.url).href, apple: rel.includes('apple') }); } catch {}
        }
        cands.sort((a, c) => a.apple - c.apple);
        cands.push({ href: new URL('/favicon.ico', page.url).href });
        for (const c of cands.slice(0, 3)) {
          try {
            const ic = await safeGet(c.href, 65536, 'image/png,image/x-icon,image/*;q=0.8');
            const mime = sniffImage(ic.body);
            if (mime && ic.body.length < 65536) { data.icon = 'data:' + mime + ';base64,' + ic.body.toString('base64'); break; }
          } catch {}
        }
      }
    } catch { data.error = 'unreachable'; }
    previewCache.set(key, { at: now(), data });
    if (previewCache.size > 800) previewCache.delete(previewCache.keys().next().value);
    return data;
  });

  // ======================================================================
  // Användare och kontakter
  // ======================================================================
  // Uppslag på namn (för vänförfrågan). Blockerade par ser varandra som om kontot inte fanns, och bild och
  // publik nyckel får bara man själv och kontakter (samma regel som /users/key och /users/profile).
  rutt('GET', '/chatt/users/lookup', (req, res) => {
    const me = profil(req, res).id;
    const uname = String(query(req).get('username') || '').toLowerCase();
    if (!validUsername(uname)) throw E(res, 400, 'invalid_username');
    const u = q('SELECT p.user_id, p.username, p.public_key, a.avatar FROM chatt_profiler p JOIN users a ON a.id=p.user_id WHERE p.username_lower=?').get(uname);
    if (!u || (u.user_id !== me && isBlockedEither(me, u.user_id))) return { exists: false };
    const nara = u.user_id === me || areContacts(me, u.user_id);
    return { exists: true, id: idUt(u.user_id), username: u.username, public_key: nara ? u.public_key : null, avatar: nara ? (u.avatar || null) : null };
  });

  rutt('GET', '/chatt/users/key', (req, res) => {
    const me = profil(req, res).id;
    const id = idIn(query(req).get('id'));
    const u = id && q('SELECT p.user_id, p.username, p.public_key, a.avatar FROM chatt_profiler p JOIN users a ON a.id=p.user_id WHERE p.user_id=?').get(id);
    if (!u) throw E(res, 404, 'not_found');
    if (u.user_id !== me && !areContacts(me, u.user_id)) throw E(res, 403, 'not_contacts');
    return { id: idUt(u.user_id), username: u.username, public_key: u.public_key, avatar: u.avatar || null };
  });

  rutt('GET', '/chatt/users/profile', (req, res) => {
    const me = profil(req, res).id;
    const id = idIn(query(req).get('id'));
    const u = id && q('SELECT p.user_id, p.username, p.bio, p.created_at, a.avatar FROM chatt_profiler p JOIN users a ON a.id=p.user_id WHERE p.user_id=?').get(id);
    if (!u) throw E(res, 404, 'not_found');
    const isSelf = u.user_id === me;
    if (!isSelf && !areContacts(me, u.user_id)) throw E(res, 403, 'not_contacts');
    const friends = q("SELECT COUNT(*) n FROM chatt_kontakter WHERE status='accepted' AND (requester_id=? OR addressee_id=?)").get(u.user_id, u.user_id).n;
    return { id: idUt(u.user_id), username: u.username, avatar: u.avatar || null, bio: u.bio || null, created_at: u.created_at, friends, pro: false, is_self: isSelf };
  });

  rutt('POST', '/chatt/users/bio', (req, res, b) => {
    const me = profil(req, res).id;
    let bio = b.bio;
    if (bio === null || bio === '') { q('UPDATE chatt_profiler SET bio=NULL WHERE user_id=?').run(me); return { bio: null }; }
    if (typeof bio !== 'string' || bio.length > BIO_MAX) throw E(res, 400, 'invalid_bio', 'Beskrivningen är för lång (max ' + BIO_MAX + ' tecken).');
    bio = bio.trim();
    q('UPDATE chatt_profiler SET bio=? WHERE user_id=?').run(bio, me);
    return { bio };
  });

  rutt('POST', '/chatt/contacts/request', (req, res, b) => {
    const me = profil(req, res).id;
    grans(req, res, 'forfragan', 200, 3_600_000, 'För många förfrågningar. Vänta en stund.', me); // mot massförfrågningar (nytt jämfört med Säkerkoll)
    const uname = String(b.username || '').toLowerCase();
    if (!validUsername(uname)) throw E(res, 400, 'invalid_username');
    const target = profilPaNamn(uname);
    if (!target) throw E(res, 404, 'user_not_found', 'Hittar ingen med det namnet.');
    if (target.id === me) throw E(res, 400, 'cant_add_self', 'Du kan inte lägga till dig själv.');
    const them = target.id;
    if (isBlockedEither(me, them)) throw E(res, 403, 'blocked', 'Det går inte att lägga till den här användaren.');
    if (areContacts(me, them)) return { status: 'accepted' };
    const reverse = q("SELECT id FROM chatt_kontakter WHERE requester_id=? AND addressee_id=? AND status='pending'").get(them, me);
    if (!reverse && getPrivacy(them).requests === 'none') throw E(res, 403, 'requests_closed', 'Den här användaren tar inte emot kontaktförfrågningar just nu.');
    if (reverse) { q("UPDATE chatt_kontakter SET status='accepted' WHERE id=?").run(reverse.id); return { status: 'accepted' }; }
    const mine = q('SELECT status FROM chatt_kontakter WHERE requester_id=? AND addressee_id=?').get(me, them);
    if (mine) return { status: mine.status };
    q("INSERT INTO chatt_kontakter(requester_id,addressee_id,status,created_at) VALUES(?,?,'pending',?)").run(me, them, now());
    return { status: 'pending' };
  });

  rutt('POST', '/chatt/contacts/accept', (req, res, b) => {
    const me = profil(req, res).id;
    const uname = String(b.username || '').toLowerCase();
    if (!validUsername(uname)) throw E(res, 400, 'invalid_username');
    const from = profilPaNamn(uname);
    if (!from) throw E(res, 404, 'user_not_found');
    if (isBlockedEither(me, from.id)) throw E(res, 403, 'blocked');
    const row = q("SELECT id FROM chatt_kontakter WHERE requester_id=? AND addressee_id=? AND status='pending'").get(from.id, me);
    if (!row) throw E(res, 404, 'no_pending_request');
    q("UPDATE chatt_kontakter SET status='accepted' WHERE id=?").run(row.id);
    return {};
  });

  rutt('POST', '/chatt/contacts/remove', (req, res, b) => {
    const me = profil(req, res).id;
    const uname = String(b.username || '').toLowerCase();
    if (!validUsername(uname)) throw E(res, 400, 'invalid_username');
    const them = profilPaNamn(uname);
    if (!them) throw E(res, 404, 'user_not_found');
    dropContactRows(me, them.id);
    return {};
  });

  rutt('POST', '/chatt/contacts/block', (req, res, b) => {
    const me = profil(req, res).id;
    const uname = String(b.username || '').toLowerCase();
    if (!validUsername(uname)) throw E(res, 400, 'invalid_username');
    const them = profilPaNamn(uname);
    if (!them) throw E(res, 404, 'user_not_found');
    if (them.id === me) throw E(res, 400, 'cant_block_self');
    tx(() => {
      q('INSERT OR IGNORE INTO chatt_blockeringar(blocker_id,blocked_id,created_at) VALUES(?,?,?)').run(me, them.id, now());
      dropContactRows(me, them.id);
    });
    typingMap.delete(typingKey('dm', them.id, me)); typingMap.delete(typingKey('dm', me, them.id));
    return {};
  });

  rutt('POST', '/chatt/contacts/unblock', (req, res, b) => {
    const me = profil(req, res).id;
    const uname = String(b.username || '').toLowerCase();
    if (!validUsername(uname)) throw E(res, 400, 'invalid_username');
    const them = profilPaNamn(uname);
    if (!them) throw E(res, 404, 'user_not_found');
    q('DELETE FROM chatt_blockeringar WHERE blocker_id=? AND blocked_id=?').run(me, them.id);
    return {};
  });

  rutt('GET', '/chatt/contacts', (req, res) => {
    const me = profil(req, res).id;
    const accepted = q(`SELECT CAST(p.user_id AS TEXT) AS id, p.username, a.avatar, p.bubble FROM chatt_kontakter c
      JOIN chatt_profiler p ON p.user_id = CASE WHEN c.requester_id=? THEN c.addressee_id ELSE c.requester_id END
      JOIN users a ON a.id=p.user_id
      WHERE c.status='accepted' AND (c.requester_id=? OR c.addressee_id=?) ORDER BY p.username COLLATE NOCASE`).all(me, me, me);
    const incoming = q(`SELECT CAST(p.user_id AS TEXT) AS id, p.username, a.avatar FROM chatt_kontakter c JOIN chatt_profiler p ON p.user_id=c.requester_id
      JOIN users a ON a.id=p.user_id WHERE c.addressee_id=? AND c.status='pending' ORDER BY c.created_at DESC`).all(me);
    const outgoing = q(`SELECT CAST(p.user_id AS TEXT) AS id, p.username, a.avatar FROM chatt_kontakter c JOIN chatt_profiler p ON p.user_id=c.addressee_id
      JOIN users a ON a.id=p.user_id WHERE c.requester_id=? AND c.status='pending' ORDER BY c.created_at DESC`).all(me);
    for (const c of accepted) c.bubble = parseBubble(c.bubble);
    const blocked = q('SELECT CAST(p.user_id AS TEXT) AS id, p.username FROM chatt_blockeringar b JOIN chatt_profiler p ON p.user_id=b.blocked_id WHERE b.blocker_id=? ORDER BY b.created_at DESC').all(me);
    return { contacts: accepted.map(utRad), incoming: incoming.map(utRad), outgoing: outgoing.map(utRad), blocked: blocked.map(utRad) };
  });
  // node:sqlite ger rader med null-prototyp; gör om till vanliga objekt
  const utRad = (r) => ({ ...r });

  // ======================================================================
  // Meddelanden
  // ======================================================================
  rutt('POST', '/chatt/messages/typing', (req, res, b) => {
    const me = profil(req, res).id;
    if (!getPrivacy(me).typing) return { off: true };
    if (b.to_id != null) {
      const to = idIn(b.to_id);
      if (!areContacts(me, to)) throw E(res, 403, 'not_contacts');
      typingMap.set(typingKey('dm', me, to), now());
    } else if (typeof b.group_id === 'string') {
      if (!isMember(b.group_id, me)) throw E(res, 403, 'not_member');
      typingMap.set(typingKey('grp', b.group_id, me), now());
    } else throw E(res, 400, 'invalid_input');
    return {};
  });

  // ---------- stickers (egen krypterad samling) ----------
  rutt('GET', '/chatt/stickers', (req, res) => {
    const me = profil(req, res).id;
    const id = query(req).get('id');
    if (id != null) { // GET /stickers/:id
      const r = q('SELECT ciphertext FROM chatt_stickers WHERE id=? AND user_id=?').get(String(id), me);
      if (!r) throw E(res, 404, 'not_found');
      return { ciphertext: r.ciphertext };
    }
    return { stickers: q('SELECT id, bytes, created_at FROM chatt_stickers WHERE user_id=? ORDER BY created_at DESC').all(me).map(utRad), max: STICKER_MAX_COUNT };
  });
  rutt('POST', '/chatt/stickers', (req, res, b) => {
    grans(req, res, 'bilaga', 400, KVART, 'För många bilder på kort tid. Vänta en stund och försök igen.');
    const me = profil(req, res).id;
    if (!isSaneB64(b.ciphertext, STICKER_MAX_B64)) throw E(res, 400, 'invalid_input', 'Stickern är för stor.');
    if (q('SELECT COUNT(*) c FROM chatt_stickers WHERE user_id=?').get(me).c >= STICKER_MAX_COUNT) throw E(res, 400, 'too_many', `Du har redan ${STICKER_MAX_COUNT} stickers. Ta bort några först.`);
    const id = crypto.randomBytes(16).toString('hex');
    q('INSERT INTO chatt_stickers(id,user_id,ciphertext,bytes,created_at) VALUES(?,?,?,?,?)').run(id, me, b.ciphertext, b.ciphertext.length, now());
    return { id };
  });
  rutt('POST', '/chatt/stickers/delete', (req, res, b) => {
    const me = profil(req, res).id;
    q('DELETE FROM chatt_stickers WHERE id=? AND user_id=?').run(String(b.id ?? ''), me);
    return {};
  });

  // ---------- bildbilagor ----------
  // Tak per konto (tecken chiffertext ≈ byte): totalt och per dygn, så att ingen ensam kan fylla disken.
  // Indexet låter SQLite summera utan att läsa själva bilderna.
  const BILAGA_KVOT = Number(process.env.CHATT_BILAGA_KVOT || 500_000_000);
  const BILAGA_PER_DYGN = Number(process.env.CHATT_BILAGA_PER_DYGN || 200_000_000);
  db.exec('CREATE INDEX IF NOT EXISTS chatt_bilagor_kvot ON chatt_bilagor(sender_id, created_at, bytes)');
  rutt('POST', '/chatt/messages/attachment', (req, res, b) => {
    grans(req, res, 'bilaga', 400, KVART, 'För många bilder på kort tid. Vänta en stund och försök igen.');
    const me = profil(req, res).id;
    grans(req, res, 'bilaga-anv', 400, KVART, 'För många bilder på kort tid. Vänta en stund och försök igen.', me);
    if (!isSaneB64(b.ciphertext, ATTACHMENT_MAX_B64)) throw E(res, 400, 'invalid_input', 'Bilden är för stor.');
    const anvant = q('SELECT COALESCE(SUM(bytes),0) AS s FROM chatt_bilagor WHERE sender_id=?').get(me).s;
    const idag = q('SELECT COALESCE(SUM(bytes),0) AS s FROM chatt_bilagor WHERE sender_id=? AND created_at>?').get(me, now() - 86_400_000).s;
    if (anvant + b.ciphertext.length > BILAGA_KVOT || idag + b.ciphertext.length > BILAGA_PER_DYGN)
      throw E(res, 413, 'quota_exceeded', 'Du har skickat väldigt många bilder. Ta bort gamla bilder du har skickat, eller vänta till i morgon.');
    let recipient = null, group = null;
    if (b.to_id != null) {
      recipient = idIn(b.to_id);
      if (!areContacts(me, recipient)) throw E(res, 403, 'not_contacts', 'Ni är inte kontakter.');
    } else if (typeof b.group_id === 'string') {
      if (!isMember(b.group_id, me)) throw E(res, 403, 'not_member');
      group = b.group_id;
    } else throw E(res, 400, 'invalid_input');
    const id = crypto.randomBytes(16).toString('hex');
    q('INSERT INTO chatt_bilagor(id,sender_id,recipient_id,group_id,ciphertext,bytes,created_at) VALUES(?,?,?,?,?,?,?)').run(id, me, recipient, group, b.ciphertext, b.ciphertext.length, now());
    return { id };
  });
  rutt('GET', '/chatt/messages/attachment', (req, res) => {
    const me = profil(req, res).id;
    const a = q('SELECT sender_id, recipient_id, group_id, ciphertext FROM chatt_bilagor WHERE id=?').get(String(query(req).get('id') || ''));
    if (!a) throw E(res, 404, 'not_found');
    if (!(a.sender_id === me || a.recipient_id === me || (a.group_id && isMember(a.group_id, me)))) throw E(res, 403, 'forbidden');
    return { ciphertext: a.ciphertext };
  });
  function claimAttachment(attId, me, { recipient = null, group = null }, tabell, messageId) {
    if (typeof attId !== 'string' || !/^[a-f0-9]{32}$/.test(attId)) return null;
    const a = q('SELECT id FROM chatt_bilagor WHERE id=? AND sender_id=? AND used=0 AND recipient_id IS ? AND group_id IS ?').get(attId, me, recipient, group);
    if (!a) return null;
    q('UPDATE chatt_bilagor SET used=1 WHERE id=?').run(attId);
    q(`UPDATE ${tabell} SET attachment_id=? WHERE id=?`).run(attId, messageId);
    return attId;
  }
  const dropAttachment = (attId) => { if (attId) q('DELETE FROM chatt_bilagor WHERE id=?').run(attId); };
  function sweep() {
    try {
      q('DELETE FROM chatt_bilagor WHERE used=0 AND created_at<?').run(now() - ATTACHMENT_ORPHAN_TTL_MS);
      q('DELETE FROM chatt_grupper WHERE id NOT IN (SELECT DISTINCT group_id FROM chatt_gruppmedlemmar)').run(); // grupper vars sista medlem raderat kontot
    } catch (e) { console.error('[chatt] städning:', e.message); }
  }
  setInterval(sweep, 3_600_000).unref();
  sweep();

  rutt('POST', '/chatt/messages/send', (req, res, b) => {
    const me = profil(req, res).id;
    const toId = b.to_id != null ? idIn(b.to_id) : null;
    if (!toId || !isSaneB64(b.ciphertext, MESSAGE_MAX_BYTES)) throw E(res, 400, 'invalid_input');
    if (!finnsProfil(toId)) throw E(res, 404, 'user_not_found');
    if (!areContacts(me, toId)) throw E(res, 403, 'not_contacts', 'Ni är inte kontakter.');
    const t = now();
    const info = q('INSERT INTO chatt_meddelanden(sender_id,recipient_id,ciphertext,created_at) VALUES(?,?,?,?)').run(me, toId, b.ciphertext, t);
    const id = Number(info.lastInsertRowid);
    if (b.attachment_id && !claimAttachment(b.attachment_id, me, { recipient: toId }, 'chatt_meddelanden', id)) {
      q('DELETE FROM chatt_meddelanden WHERE id=?').run(id);
      throw E(res, 400, 'bad_attachment', 'Bilden kunde inte bifogas. Försök igen.');
    }
    typingMap.delete(typingKey('dm', me, toId));
    return { id, created_at: t };
  });

  rutt('GET', '/chatt/messages', (req, res) => {
    const me = profil(req, res).id;
    const qs = query(req);
    const withRaw = qs.get('with') || '';
    if (!withRaw) throw E(res, 400, 'missing_with');
    const withId = idIn(withRaw);
    if (!areContacts(me, withId)) throw E(res, 403, 'not_contacts');
    const since = parseInt(qs.get('since'), 10) || 0;
    const rows = q(`SELECT id, sender_id, ciphertext, created_at, deleted_at, edited_at FROM chatt_meddelanden
      WHERE created_at > ? AND ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) ORDER BY created_at ASC LIMIT 500`).all(since, me, withId, withId, me);
    q('UPDATE chatt_meddelanden SET read_at=? WHERE recipient_id=? AND sender_id=? AND read_at IS NULL').run(now(), me, withId);
    const hidden = new Set(q("SELECT message_id FROM chatt_dolda WHERE user_id=? AND kind='dm'").all(me).map((r) => r.message_id));
    const messages = rows.filter((r) => !hidden.has(r.id)).map((r) => ({ id: r.id, mine: r.sender_id === me, ciphertext: r.deleted_at ? '' : r.ciphertext, created_at: r.created_at, deleted: !!r.deleted_at, edited: !!r.edited_at }));
    const receipts = getPrivacy(me).read_receipts && getPrivacy(withId).read_receipts;
    const seen = receipts ? q('SELECT MAX(created_at) AS until, MAX(read_at) AS at FROM chatt_meddelanden WHERE sender_id=? AND recipient_id=? AND read_at IS NOT NULL').get(me, withId) : null;
    const changedSince = parseInt(qs.get('changed_since'), 10) || 0;
    const changes = changedSince ? q(`SELECT id, ciphertext, deleted_at, edited_at FROM chatt_meddelanden
      WHERE ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) AND (deleted_at > ? OR edited_at > ?) LIMIT 200`)
      .all(me, withId, withId, me, changedSince, changedSince)
      .map((r) => ({ id: r.id, deleted: !!r.deleted_at, edited: !!r.edited_at, ciphertext: r.deleted_at ? '' : r.ciphertext })) : [];
    return { messages, server_time: now(), changes, peer_read_until: (seen && seen.until) || 0, peer_read_at: (seen && seen.at) || 0,
      typing: getPrivacy(withId).typing && isTyping('dm', withId, me) };
  });

  rutt('GET', '/chatt/messages/overview', (req, res) => {
    const me = profil(req, res).id;
    return { unread: q('SELECT CAST(sender_id AS TEXT) AS id, COUNT(*) AS n FROM chatt_meddelanden WHERE recipient_id=? AND read_at IS NULL GROUP BY sender_id').all(me).map(utRad) };
  });

  function egetDm(res, me, b) {
    const id = msgId(b.id);
    return { id, m: q('SELECT sender_id, recipient_id, deleted_at, attachment_id FROM chatt_meddelanden WHERE id=?').get(id) };
  }
  rutt('POST', '/chatt/messages/edit', (req, res, b) => {
    const me = profil(req, res).id;
    if (!isSaneB64(b.ciphertext, MESSAGE_MAX_BYTES)) throw E(res, 400, 'invalid_input');
    const { id, m } = egetDm(res, me, b);
    if (!m) throw E(res, 404, 'not_found');
    if (m.sender_id !== me) throw E(res, 403, 'not_sender', 'Du kan bara andra dina egna meddelanden.');
    if (m.deleted_at) throw E(res, 400, 'already_deleted');
    q('UPDATE chatt_meddelanden SET ciphertext=?, edited_at=? WHERE id=?').run(b.ciphertext, now(), id);
    return {};
  });
  rutt('POST', '/chatt/messages/delete', (req, res, b) => {
    const me = profil(req, res).id;
    const { id, m } = egetDm(res, me, b);
    if (!m) throw E(res, 404, 'not_found');
    if (m.sender_id !== me) throw E(res, 403, 'not_sender', 'Du kan bara ta bort dina egna meddelanden.');
    q("UPDATE chatt_meddelanden SET ciphertext='', deleted_at=? WHERE id=?").run(now(), id);
    dropAttachment(m.attachment_id);
    return {};
  });
  rutt('POST', '/chatt/messages/hide', (req, res, b) => {
    const me = profil(req, res).id;
    const { id, m } = egetDm(res, me, b);
    if (!m) throw E(res, 404, 'not_found');
    if (m.sender_id !== me && m.recipient_id !== me) throw E(res, 403, 'not_participant');
    q("INSERT OR IGNORE INTO chatt_dolda(user_id,kind,message_id) VALUES(?,'dm',?)").run(me, id);
    return {};
  });

  // ======================================================================
  // Grupper
  // ======================================================================
  rutt('POST', '/chatt/groups/create', (req, res, b) => {
    const me = profil(req, res).id;
    grans(req, res, 'grupp', 30, 3_600_000, 'För många nya grupper. Vänta en stund.', me);
    if (!isSaneB64(b.name_enc, GROUP_NAME_ENC_MAX)) throw E(res, 400, 'invalid_name');
    const members = b.members;
    if (!Array.isArray(members) || members.length < 1 || members.length > MAX_GROUP_MEMBERS) throw E(res, 400, 'invalid_members');
    const lista = [];
    for (const m of members) {
      const uid = m && idIn(m.user_id);
      if (!uid || !isSaneB64(m.key_envelope, KEY_ENVELOPE_MAX)) throw E(res, 400, 'invalid_member_entry');
      if (!finnsProfil(uid)) throw E(res, 404, 'member_not_found', 'En av medlemmarna finns inte.');
      if (uid !== me && !areContacts(me, uid)) throw E(res, 403, 'not_contacts', 'Du kan bara lägga till dina kontakter.');
      if (!lista.some((x) => x.uid === uid)) lista.push({ uid, env: m.key_envelope });
    }
    if (!lista.some((m) => m.uid === me)) throw E(res, 400, 'creator_missing', 'Skaparen måste ingå i gruppen.');
    const gid = genId(), t = now();
    tx(() => {
      q('INSERT INTO chatt_grupper(id,name_enc,owner_id,created_at) VALUES(?,?,?,?)').run(gid, b.name_enc, me, t);
      const ins = q('INSERT INTO chatt_gruppmedlemmar(group_id,user_id,key_envelope,wrapped_by,joined_at,last_read_at,is_admin) VALUES(?,?,?,?,?,?,?)');
      for (const m of lista) ins.run(gid, m.uid, m.env, me, t, m.uid === me ? t : 0, m.uid === me ? 1 : 0);
    });
    return { id: gid, created_at: t };
  });

  rutt('GET', '/chatt/groups', (req, res) => {
    const me = profil(req, res).id;
    const rows = q(`SELECT g.id, g.name_enc, g.owner_id, g.avatar_enc, gm.key_envelope, gm.wrapped_by, gm.joined_at, gm.last_read_at
      FROM chatt_gruppmedlemmar gm JOIN chatt_grupper g ON g.id=gm.group_id WHERE gm.user_id=? ORDER BY g.created_at DESC`).all(me);
    const antal = q('SELECT COUNT(*) c FROM chatt_gruppmedlemmar WHERE group_id=?');
    const sist = q('SELECT MAX(created_at) m FROM chatt_gruppmeddelanden WHERE group_id=?');
    const olast = q('SELECT COUNT(*) c FROM chatt_gruppmeddelanden WHERE group_id=? AND created_at > ? AND created_at >= ? AND sender_id != ?');
    return { groups: rows.map((r) => ({ id: r.id, name_enc: r.name_enc, owner_id: idUt(r.owner_id), avatar_enc: r.avatar_enc || null, key_envelope: r.key_envelope,
      wrapped_by: idUt(r.wrapped_by), member_count: antal.get(r.id).c, last_message_at: sist.get(r.id).m || 0, unread: olast.get(r.id, r.last_read_at, r.joined_at, me).c })) };
  });

  rutt('GET', '/chatt/groups/members', (req, res) => {
    const me = profil(req, res).id;
    const gid = gidIn(query(req).get('id'));
    if (!isMember(gid, me)) throw E(res, 403, 'not_member');
    const g = q('SELECT owner_id FROM chatt_grupper WHERE id=?').get(gid);
    const members = q(`SELECT CAST(p.user_id AS TEXT) AS id, p.username, a.avatar, gm.joined_at, gm.is_admin FROM chatt_gruppmedlemmar gm
      JOIN chatt_profiler p ON p.user_id=gm.user_id JOIN users a ON a.id=p.user_id WHERE gm.group_id=? ORDER BY p.username COLLATE NOCASE`).all(gid).map(utRad);
    return { owner_id: g ? idUt(g.owner_id) : null, members };
  });

  rutt('GET', '/chatt/groups/messages', (req, res) => {
    const me = profil(req, res).id;
    const qs = query(req);
    const gid = gidIn(qs.get('id'));
    const mem = gid && q('SELECT joined_at FROM chatt_gruppmedlemmar WHERE group_id=? AND user_id=?').get(gid, me);
    if (!mem) throw E(res, 403, 'not_member');
    const since = parseInt(qs.get('since'), 10) || 0;
    const rows = q(`SELECT m.id, m.sender_id, p.username AS sender_username, p.bubble AS sender_bubble, m.ciphertext, m.created_at, m.deleted_at, m.edited_at
      FROM chatt_gruppmeddelanden m JOIN chatt_profiler p ON p.user_id=m.sender_id
      WHERE m.group_id=? AND m.created_at > ? ORDER BY m.created_at ASC LIMIT 500`).all(gid, Math.max(since, mem.joined_at));
    q('UPDATE chatt_gruppmedlemmar SET last_read_at=? WHERE group_id=? AND user_id=?').run(now(), gid, me);
    const hidden = new Set(q("SELECT message_id FROM chatt_dolda WHERE user_id=? AND kind='group'").all(me).map((r) => r.message_id));
    const messages = rows.filter((r) => !hidden.has(r.id)).map((r) => ({ id: r.id, sender_id: idUt(r.sender_id), sender_username: r.sender_username, sender_bubble: parseBubble(r.sender_bubble),
      mine: r.sender_id === me, ciphertext: r.deleted_at ? '' : r.ciphertext, created_at: r.created_at, deleted: !!r.deleted_at, edited: !!r.edited_at }));
    const others = q('SELECT gm.user_id, gm.last_read_at, p.username FROM chatt_gruppmedlemmar gm JOIN chatt_profiler p ON p.user_id=gm.user_id WHERE gm.group_id=? AND gm.user_id!=?').all(gid, me);
    const reads = getPrivacy(me).read_receipts ? others.filter((o) => getPrivacy(o.user_id).read_receipts).map((o) => ({ id: idUt(o.user_id), username: o.username, read_at: o.last_read_at || 0 })) : [];
    const typing = others.filter((o) => isTyping('grp', gid, o.user_id)).map((o) => o.username);
    const changedSince = parseInt(qs.get('changed_since'), 10) || 0;
    const changes = changedSince ? q('SELECT id, ciphertext, deleted_at, edited_at FROM chatt_gruppmeddelanden WHERE group_id=? AND created_at >= ? AND (deleted_at > ? OR edited_at > ?) LIMIT 200')
      .all(gid, mem.joined_at || 0, changedSince, changedSince)
      .map((r) => ({ id: r.id, deleted: !!r.deleted_at, edited: !!r.edited_at, ciphertext: r.deleted_at ? '' : r.ciphertext })) : [];
    return { messages, server_time: now(), reads, typing, changes };
  });

  rutt('POST', '/chatt/groups/messages', (req, res, b) => {
    const me = profil(req, res).id;
    grans(req, res, 'gruppmsg-anv', 600, KVART, 'Du skickar väldigt många meddelanden. Vänta en stund och försök igen.', me);
    const gid = gidIn(b.id);
    if (!isMember(gid, me)) throw E(res, 403, 'not_member');
    if (!isSaneB64(b.ciphertext, MESSAGE_MAX_BYTES)) throw E(res, 400, 'invalid_input');
    const t = now();
    const id = Number(q('INSERT INTO chatt_gruppmeddelanden(group_id,sender_id,ciphertext,created_at) VALUES(?,?,?,?)').run(gid, me, b.ciphertext, t).lastInsertRowid);
    if (b.attachment_id && !claimAttachment(b.attachment_id, me, { group: gid }, 'chatt_gruppmeddelanden', id)) {
      q('DELETE FROM chatt_gruppmeddelanden WHERE id=?').run(id);
      throw E(res, 400, 'bad_attachment', 'Bilden kunde inte bifogas. Försök igen.');
    }
    q('UPDATE chatt_gruppmedlemmar SET last_read_at=? WHERE group_id=? AND user_id=?').run(t, gid, me);
    typingMap.delete(typingKey('grp', gid, me));
    return { id, created_at: t };
  });

  rutt('POST', '/chatt/groups/members', (req, res, b) => {
    const me = profil(req, res).id;
    const gid = gidIn(b.id);
    if (!isMember(gid, me)) throw E(res, 403, 'not_member');
    const uid = b.user_id != null ? idIn(b.user_id) : null;
    if (!uid || !isSaneB64(b.key_envelope, KEY_ENVELOPE_MAX)) throw E(res, 400, 'invalid_input');
    if (!finnsProfil(uid)) throw E(res, 404, 'user_not_found');
    if (isMember(gid, uid)) return { already_member: true };
    if (!areContacts(me, uid)) throw E(res, 403, 'not_contacts', 'Du kan bara lägga till dina kontakter.');
    if (q('SELECT COUNT(*) c FROM chatt_gruppmedlemmar WHERE group_id=?').get(gid).c >= MAX_GROUP_MEMBERS) throw E(res, 409, 'group_full', `Gruppen är full (max ${MAX_GROUP_MEMBERS}).`);
    q('INSERT INTO chatt_gruppmedlemmar(group_id,user_id,key_envelope,wrapped_by,joined_at,last_read_at) VALUES(?,?,?,?,?,0)').run(gid, uid, b.key_envelope, me, now());
    return {};
  });

  rutt('POST', '/chatt/groups/rename', (req, res, b) => {
    const me = profil(req, res).id;
    const gid = gidIn(b.id);
    if (!isMember(gid, me)) throw E(res, 403, 'not_member');
    if (!isAdmin(gid, me)) throw E(res, 403, 'not_admin', 'Bara admins kan byta gruppnamn.');
    if (!isSaneB64(b.name_enc, GROUP_NAME_ENC_MAX)) throw E(res, 400, 'invalid_name');
    q('UPDATE chatt_grupper SET name_enc=? WHERE id=?').run(b.name_enc, gid);
    return {};
  });

  rutt('POST', '/chatt/groups/avatar', (req, res, b) => {
    const me = profil(req, res).id;
    const gid = gidIn(b.id);
    if (!isAdmin(gid, me)) throw E(res, 403, 'not_admin', 'Bara admins kan byta gruppbild.');
    const av = b.avatar_enc;
    if (av === null || av === '') { q('UPDATE chatt_grupper SET avatar_enc=NULL WHERE id=?').run(gid); return {}; }
    if (!isSaneB64(av, GROUP_AVATAR_ENC_MAX)) throw E(res, 400, 'invalid_avatar');
    q('UPDATE chatt_grupper SET avatar_enc=? WHERE id=?').run(av, gid);
    return {};
  });

  rutt('POST', '/chatt/groups/leave', (req, res, b) => {
    const me = profil(req, res).id;
    const gid = gidIn(b.id);
    if (!isMember(gid, me)) throw E(res, 403, 'not_member');
    tx(() => {
      q('DELETE FROM chatt_gruppmedlemmar WHERE group_id=? AND user_id=?').run(gid, me);
      if (q('SELECT COUNT(*) c FROM chatt_gruppmedlemmar WHERE group_id=?').get(gid).c === 0) q('DELETE FROM chatt_grupper WHERE id=?').run(gid);
    });
    typingMap.delete(typingKey('grp', gid, me));
    return {};
  });

  // Alla medlemmar får ta bort andra (Cettos beslut i Säkerkoll), men aldrig ägaren
  rutt('POST', '/chatt/groups/kick', (req, res, b) => {
    const me = profil(req, res).id;
    const gid = gidIn(b.id);
    const g = gid && q('SELECT owner_id FROM chatt_grupper WHERE id=?').get(gid);
    if (!g) throw E(res, 404, 'group_not_found');
    if (!isMember(gid, me)) throw E(res, 403, 'not_member', 'Du är inte med i gruppen.');
    if (b.user_id == null) throw E(res, 400, 'invalid_input');
    const uid = idIn(b.user_id);
    if (uid === me) throw E(res, 400, 'cant_kick_self', 'Du kan inte ta bort dig själv – lämna gruppen i stället.');
    if (uid === g.owner_id) throw E(res, 403, 'cant_kick_owner', 'Gruppens ägare kan inte tas bort.');
    if (!uid || !isMember(gid, uid)) throw E(res, 404, 'not_member');
    q('DELETE FROM chatt_gruppmedlemmar WHERE group_id=? AND user_id=?').run(gid, uid);
    typingMap.delete(typingKey('grp', gid, uid));
    return {};
  });

  rutt('POST', '/chatt/groups/promote', (req, res, b) => {
    const me = profil(req, res).id;
    const gid = gidIn(b.id);
    if (!isAdmin(gid, me)) throw E(res, 403, 'not_admin');
    const uid = idIn(b.user_id);
    if (!uid || !isMember(gid, uid)) throw E(res, 404, 'not_member');
    q('UPDATE chatt_gruppmedlemmar SET is_admin=1 WHERE group_id=? AND user_id=?').run(gid, uid);
    return {};
  });

  rutt('POST', '/chatt/groups/demote', (req, res, b) => {
    const me = profil(req, res).id;
    const gid = gidIn(b.id);
    const g = gid && q('SELECT owner_id FROM chatt_grupper WHERE id=?').get(gid);
    if (!g) throw E(res, 404, 'group_not_found');
    if (!isAdmin(gid, me)) throw E(res, 403, 'not_admin');
    const uid = idIn(b.user_id);
    if (!uid || !isMember(gid, uid)) throw E(res, 404, 'not_member');
    if (uid === g.owner_id) throw E(res, 403, 'cant_demote_owner', 'Original-agaren ar alltid admin.');
    q('UPDATE chatt_gruppmedlemmar SET is_admin=0 WHERE group_id=? AND user_id=?').run(gid, uid);
    return {};
  });

  function gruppMsg(res, me, b) {
    const gid = gidIn(b.gid), id = msgId(b.id);
    if (!isMember(gid, me)) throw E(res, 403, 'not_member');
    return { gid, id, m: q('SELECT sender_id, deleted_at, attachment_id FROM chatt_gruppmeddelanden WHERE id=? AND group_id=?').get(id, gid) };
  }
  rutt('POST', '/chatt/groups/messages/edit', (req, res, b) => {
    const me = profil(req, res).id;
    const gid = gidIn(b.gid);
    if (!isMember(gid, me)) throw E(res, 403, 'not_member');
    if (!isSaneB64(b.ciphertext, MESSAGE_MAX_BYTES)) throw E(res, 400, 'invalid_input');
    const { id, m } = gruppMsg(res, me, b);
    if (!m) throw E(res, 404, 'not_found');
    if (m.sender_id !== me) throw E(res, 403, 'not_sender');
    if (m.deleted_at) throw E(res, 400, 'already_deleted');
    q('UPDATE chatt_gruppmeddelanden SET ciphertext=?, edited_at=? WHERE id=?').run(b.ciphertext, now(), id);
    return {};
  });
  rutt('POST', '/chatt/groups/messages/delete', (req, res, b) => {
    const me = profil(req, res).id;
    const { id, m } = gruppMsg(res, me, b);
    if (!m) throw E(res, 404, 'not_found');
    if (m.sender_id !== me) throw E(res, 403, 'not_sender');
    q("UPDATE chatt_gruppmeddelanden SET ciphertext='', deleted_at=? WHERE id=?").run(now(), id);
    dropAttachment(m.attachment_id);
    return {};
  });
  rutt('POST', '/chatt/groups/messages/hide', (req, res, b) => {
    const me = profil(req, res).id;
    const { id, m } = gruppMsg(res, me, b);
    if (!m) throw E(res, 404, 'not_found');
    q("INSERT OR IGNORE INTO chatt_dolda(user_id,kind,message_id) VALUES(?,'group',?)").run(me, id);
    return {};
  });

  return { refreshThreatLists, threat };
};
