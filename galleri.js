// Temagalleriet: AdRaze-användare delar sina teman och bläddrar bland andras, med en topplista per vecka.
// Kopplas in i server.js med require('./galleri.js')({ ... }) EFTER chatt.js: skaparens namn är användarnamnet
// i chatten. Har man inget, eller väljer att publicera anonymt, visas skaparen som "Anonym" (null här).
//
// Ett tema är en ADRZ1-kod (samma format som AdRazes delningskod) som BARA får innehålla tema.*-nycklar.
// Värdena får vara hex-färger, sant/falskt eller ett av de kända valen i TEMA_VAL. Allt annat avvisas
// (bilder, adresser, CSS, fritext, tal, andra områden), så ett delat tema kan aldrig bära något annat än utseende.
//
// Rutter (svarar som resten av API:t: { ok:true, ... } eller { ok:false, error:'svensk text' }):
//   GET  /galleri/schema                     vad ett tema får innehålla (klienten filtrerar sitt tema innan publicering)
//   GET  /galleri/lista?sort=&sida=&barn=1   populara | nya | vecka (topplistan), 24 per sida. Inloggning valfri.
//   GET  /galleri/tema?id=                   ett tema med sin kod
//   GET  /galleri/mina                       mina publicerade teman (vuxet konto)
//   POST /galleri/publicera { namn, beskrivning, kod, anonym }   vuxet konto, högst 5 per dygn
//   POST /galleri/rosta     { id, rost: 1 | -1 | 0 }   gilla, ogilla, ta bort rösten. En röst per konto.
//   POST /galleri/nedladdad { id }   någon behöll temat. Räknas en gång per konto (eller adress utan konto).
//   POST /galleri/anmal     { id, orsak }   tre anmälningar döljer temat. Barn ser inga anmälda teman alls.
//   POST /galleri/ta-bort   { id }   ägaren tar bort sitt tema
'use strict';

module.exports = function registreraGalleri({ rutt, q, db, fel, inloggad, kravInloggad, barnInloggad, begransad, now, sha, ipAv, crypto }) {
  const PER_SIDA = 24;
  const MAX_SIDA = 200;              // så långt bak går det att bläddra
  const NAMN_MAX = 40, BESK_MAX = 140;
  const PUBL_PER_DYGN = 5;           // per konto, borttagna räknas också
  const AKTIVA_MAX = 50;             // synliga teman per konto
  const ANMAL_GRANS = 3;             // så många olika konton som anmäler → temat döljs
  const KOD_MAX = 8000;
  const NYCKLAR_MAX = 40;
  const VECKA = 7 * 86_400_000;
  const ORSAKER = ['olampligt', 'spam', 'annat'];

  // Nycklar: tema.<namn>, en nivå, bara bokstäver och siffror. Färger godtas för alla sådana nycklar.
  const NYCKEL_RE = /^tema\.[a-z][a-zA-Z0-9]{0,39}$/;
  const HEX_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;
  // Kända val (enum) per nyckel. Lägg till här när tema-området i webbläsaren får nya val.
  const TEMA_VAL = {
    'tema.lage': ['ljus', 'ljust', 'mork', 'morkt', 'system', 'light', 'dark', 'auto'],
    'tema.rundning': ['ingen', 'skarp', 'liten', 'mjuk', 'mellan', 'rund', 'stor'],
    'tema.densitet': ['kompakt', 'normal', 'luftig'],
    'tema.typsnitt': ['system', 'sans', 'rundad', 'serif', 'mono'],
    'tema.kontrast': ['normal', 'hog'],
    'tema.flikform': ['rund', 'fyrkantig', 'flik', 'linje'],
    'tema.ikoner': ['linje', 'fylld'],
    'tema.skuggor': ['inga', 'mjuka', 'tydliga'],
  };

  // ---------- tabeller ----------
  db.exec(`
  CREATE TABLE IF NOT EXISTS galleri_teman(
    id TEXT PRIMARY KEY,
    agare INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    namn TEXT, beskrivning TEXT,
    varden TEXT,                                 -- validerad JSON { "tema.x": värde }; NULL när temat tagits bort
    hash TEXT,                                   -- av varden (stoppar dubbletter)
    visa_namn INTEGER NOT NULL DEFAULT 1,        -- 0 = Anonym
    status TEXT NOT NULL DEFAULT 'synlig',       -- synlig | dold (anmält) | borttagen (raden finns kvar ett dygn för dygnsgränsen)
    gillar INTEGER NOT NULL DEFAULT 0, ogillar INTEGER NOT NULL DEFAULT 0,
    nedladdningar INTEGER NOT NULL DEFAULT 0, anmalningar INTEGER NOT NULL DEFAULT 0,
    skapad INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS galleri_teman_status ON galleri_teman(status, skapad);
  CREATE INDEX IF NOT EXISTS galleri_teman_agare ON galleri_teman(agare, skapad);
  CREATE INDEX IF NOT EXISTS galleri_teman_hash ON galleri_teman(hash);
  -- vem: 'u:<users.id>' (vuxet konto), 'b:<barn.id>' (barnkonto) eller 'ip:<hash>' (nedladdning utan konto)
  CREATE TABLE IF NOT EXISTS galleri_roster(tema_id TEXT NOT NULL REFERENCES galleri_teman(id) ON DELETE CASCADE,
    vem TEXT NOT NULL, rost INTEGER NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(tema_id, vem));
  CREATE INDEX IF NOT EXISTS galleri_roster_ts ON galleri_roster(ts);
  CREATE INDEX IF NOT EXISTS galleri_roster_vem ON galleri_roster(vem);
  CREATE TABLE IF NOT EXISTS galleri_nedladdningar(tema_id TEXT NOT NULL REFERENCES galleri_teman(id) ON DELETE CASCADE,
    vem TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(tema_id, vem));
  CREATE INDEX IF NOT EXISTS galleri_nedladdningar_ts ON galleri_nedladdningar(ts);
  CREATE INDEX IF NOT EXISTS galleri_nedladdningar_vem ON galleri_nedladdningar(vem);
  CREATE TABLE IF NOT EXISTS galleri_anmalningar(tema_id TEXT NOT NULL REFERENCES galleri_teman(id) ON DELETE CASCADE,
    vem TEXT NOT NULL, orsak TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(tema_id, vem));
  CREATE INDEX IF NOT EXISTS galleri_anmalningar_vem ON galleri_anmalningar(vem);
  CREATE TABLE IF NOT EXISTS galleri_inst(nyckel TEXT PRIMARY KEY, varde TEXT NOT NULL);

  -- Räknarna på temat räknas om från raderna vid varje ändring (även när ett konto raderas)
  CREATE TRIGGER IF NOT EXISTS galleri_roster_ny AFTER INSERT ON galleri_roster BEGIN
    UPDATE galleri_teman SET gillar=(SELECT COUNT(*) FROM galleri_roster WHERE tema_id=NEW.tema_id AND rost=1),
      ogillar=(SELECT COUNT(*) FROM galleri_roster WHERE tema_id=NEW.tema_id AND rost=-1) WHERE id=NEW.tema_id; END;
  CREATE TRIGGER IF NOT EXISTS galleri_roster_andrad AFTER UPDATE ON galleri_roster BEGIN
    UPDATE galleri_teman SET gillar=(SELECT COUNT(*) FROM galleri_roster WHERE tema_id=NEW.tema_id AND rost=1),
      ogillar=(SELECT COUNT(*) FROM galleri_roster WHERE tema_id=NEW.tema_id AND rost=-1) WHERE id=NEW.tema_id; END;
  CREATE TRIGGER IF NOT EXISTS galleri_roster_bort AFTER DELETE ON galleri_roster BEGIN
    UPDATE galleri_teman SET gillar=(SELECT COUNT(*) FROM galleri_roster WHERE tema_id=OLD.tema_id AND rost=1),
      ogillar=(SELECT COUNT(*) FROM galleri_roster WHERE tema_id=OLD.tema_id AND rost=-1) WHERE id=OLD.tema_id; END;
  CREATE TRIGGER IF NOT EXISTS galleri_ned_ny AFTER INSERT ON galleri_nedladdningar BEGIN
    UPDATE galleri_teman SET nedladdningar=(SELECT COUNT(*) FROM galleri_nedladdningar WHERE tema_id=NEW.tema_id) WHERE id=NEW.tema_id; END;
  CREATE TRIGGER IF NOT EXISTS galleri_ned_bort AFTER DELETE ON galleri_nedladdningar BEGIN
    UPDATE galleri_teman SET nedladdningar=(SELECT COUNT(*) FROM galleri_nedladdningar WHERE tema_id=OLD.tema_id) WHERE id=OLD.tema_id; END;
  CREATE TRIGGER IF NOT EXISTS galleri_anm_ny AFTER INSERT ON galleri_anmalningar BEGIN
    UPDATE galleri_teman SET anmalningar=(SELECT COUNT(*) FROM galleri_anmalningar WHERE tema_id=NEW.tema_id) WHERE id=NEW.tema_id; END;
  CREATE TRIGGER IF NOT EXISTS galleri_anm_bort AFTER DELETE ON galleri_anmalningar BEGIN
    UPDATE galleri_teman SET anmalningar=(SELECT COUNT(*) FROM galleri_anmalningar WHERE tema_id=OLD.tema_id) WHERE id=OLD.tema_id; END;

  -- Raderat konto: dess teman försvinner (ON DELETE CASCADE) och dess röster, nedladdningar och anmälningar här
  CREATE TRIGGER IF NOT EXISTS galleri_konto_raderat AFTER DELETE ON users BEGIN
    DELETE FROM galleri_roster WHERE vem='u:' || OLD.id;
    DELETE FROM galleri_nedladdningar WHERE vem='u:' || OLD.id;
    DELETE FROM galleri_anmalningar WHERE vem='u:' || OLD.id;
  END;
  CREATE TRIGGER IF NOT EXISTS galleri_barn_raderat AFTER DELETE ON barn BEGIN
    DELETE FROM galleri_roster WHERE vem='b:' || OLD.id;
    DELETE FROM galleri_nedladdningar WHERE vem='b:' || OLD.id;
    DELETE FROM galleri_anmalningar WHERE vem='b:' || OLD.id;
  END;`);

  // Nedladdningar utan konto räknas per adress, men adressen sparas bara som en saltad hash
  q("INSERT OR IGNORE INTO galleri_inst(nyckel, varde) VALUES('salt', ?)").run(crypto.randomBytes(16).toString('hex'));
  const SALT = q("SELECT varde FROM galleri_inst WHERE nyckel='salt'").get().varde;
  const ipNyckel = (req) => 'ip:' + sha(`${SALT}:${ipAv(req)}`).slice(0, 32);

  setInterval(() => {
    // Borttagna rader behövs bara för dygnsgränsen
    q("DELETE FROM galleri_teman WHERE status='borttagen' AND skapad<?").run(now() - 2 * 86_400_000);
  }, 3_600_000).unref();

  // ---------- validering ----------
  const normHex = (h) => { h = h.toLowerCase(); return h.length === 4 ? `#${h[1]}${h[1]}${h[2]}${h[2]}${h[3]}${h[3]}` : h; };
  function giltigtVarde(k, v) {
    if (typeof k !== 'string' || !NYCKEL_RE.test(k)) return undefined;
    if (typeof v === 'string' && HEX_RE.test(v)) return normHex(v);
    if (typeof v === 'boolean') return v;
    if (typeof v === 'string' && Object.hasOwn(TEMA_VAL, k) && TEMA_VAL[k].includes(v)) return v;
    return undefined;
  }
  // ADRZ1-kod → validerade värden (sorterade). Allt som inte är ett tema avvisar HELA koden.
  function lasTemaKod(kod) {
    if (typeof kod !== 'string' || kod.length > KOD_MAX) throw fel(400, 'Temakoden är ogiltig eller för stor.');
    const m = /^ADRZ1\.([A-Za-z0-9_-]+)$/.exec(kod.trim());
    if (!m) throw fel(400, 'Temakoden är ogiltig.');
    let o;
    try { o = JSON.parse(Buffer.from(m[1], 'base64url').toString('utf8')); } catch { throw fel(400, 'Temakoden är ogiltig.'); }
    if (!o || typeof o !== 'object' || Array.isArray(o)) throw fel(400, 'Temakoden är ogiltig.');
    const nycklar = Object.keys(o);
    if (!nycklar.length) throw fel(400, 'Temat är tomt. Ändra något under Tema först.');
    if (nycklar.length > NYCKLAR_MAX) throw fel(400, 'Temat har för många inställningar.');
    const ut = {};
    for (const k of nycklar.sort()) {
      const v = giltigtVarde(k, o[k]);
      if (v === undefined) throw fel(400, NYCKEL_RE.test(k) ? `Inställningen ${k} kan inte delas i galleriet.` : 'Ett tema får bara innehålla temainställningar.');
      ut[k] = v;
    }
    return ut;
  }
  const kodAv = (varden) => 'ADRZ1.' + Buffer.from(JSON.stringify(varden)).toString('base64url');

  // Namn och beskrivning: ren text på en rad. Inga taggar, adresser, domäner, mejladresser eller osynliga tecken.
  const OSYNLIGA = /[\u0000-\u001f\u007f-\u009f­͏؜ᅟᅠ឴឵᠋-᠎​‌‎‏‪-‮⁠-⁯ㅤ﻿ﾠ￰-￻]/g;
  const DOMAN = /(?<![\p{L}\p{N}_-])[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)*\.(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})(?![\p{L}\p{N}_-])(?:[/:?#]\S*)?/giu;
  function rensaText(s) {
    return String(s ?? '').normalize('NFKC')
      .replace(OSYNLIGA, ' ')
      .replace(/[。．｡]/g, '.')                       // punkter som webbläsare läser som "." i adresser
      .replace(/<[^>]*>/g, ' ').replace(/[<>]/g, ' ')               // HTML
      .replace(/\b[a-z][a-z0-9+.-]{0,20}:\/\/\S*/gi, ' ')          // https://… ftp://…
      .replace(/\b(?:javascript|data|vbscript|mailto|file|tel|sms|blob):\S*/gi, ' ')
      .replace(/\bwww\d{0,3}\.\S*/gi, ' ')
      .replace(/[^\s@]+@[^\s@]+/g, ' ')                             // mejladresser
      .replace(DOMAN, ' ')                                          // exempel.se, discord.gg/abc
      .replace(/\s+/g, ' ').trim();
  }
  const langd = (s) => [...s].length;

  // ---------- vem frågar ----------
  // Vuxet konto (vanlig session) eller barnkonto (barnsession). Barn kan bläddra, gilla och anmäla, men inte publicera.
  function vemAr(req) {
    const u = inloggad(req);
    if (u) return { typ: 'vuxen', id: u.id, nyckel: 'u:' + u.id };
    if (!/^Bearer /.test(String(req.headers.authorization || ''))) return null;
    try { const c = barnInloggad(req); return { typ: 'barn', id: c.id, nyckel: 'b:' + c.id }; } catch { return null; }
  }
  function kravKonto(req, text) { const v = vemAr(req); if (!v) throw fel(401, text); return v; }
  const egen = (t, vem) => !!(vem && vem.typ === 'vuxen' && vem.id === t.agare);
  const giltigtId = (id) => { if (typeof id !== 'string' || !/^t[0-9a-f]{20}$/.test(id)) throw fel(404, 'Temat finns inte längre.'); return id; };
  const parametrar = (req) => new URL(req.url, 'http://x').searchParams;

  // Skaparens användarnamn kommer från chattprofilen (finns tabellen inte visas alla som Anonym)
  let harChatt = null;
  const skapare = () => {
    if (harChatt === null) harChatt = !!q("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chatt_profiler'").get();
    return harChatt ? 'CASE WHEN t.visa_namn=1 THEN (SELECT p.username FROM chatt_profiler p WHERE p.user_id=t.agare) END' : 'NULL';
  };
  const VAL = () => `t.id, t.agare, t.namn, t.beskrivning, t.varden, t.gillar, t.nedladdningar, t.anmalningar, t.skapad, t.status,
    ${skapare()} AS skapare, COALESCE((SELECT r.rost FROM galleri_roster r WHERE r.tema_id=t.id AND r.vem=?), 0) AS min_rost`;

  function utTema(t, vem, extra) {
    let varden = {}; try { varden = JSON.parse(t.varden || '{}'); } catch {}
    return { id: t.id, namn: t.namn || '', beskrivning: t.beskrivning || '', skapare: t.skapare || null, varden,
      gillar: t.gillar || 0, nedladdningar: t.nedladdningar || 0, skapad: t.skapad, min_rost: t.min_rost || 0, egen: egen(t, vem), ...extra };
  }
  // Ett tema som frågaren får se: synligt (ägaren ser även sina dolda), och för barn aldrig ett anmält
  function synligtTema(id, vem, barnfilter) {
    const t = q(`SELECT ${VAL()} FROM galleri_teman t WHERE t.id=?`).get(vem ? vem.nyckel : '', id);
    const barn = barnfilter || (vem && vem.typ === 'barn');
    if (!t || t.status === 'borttagen' || (t.status === 'dold' && !egen(t, vem)) || (barn && t.anmalningar > 0 && !egen(t, vem))) throw fel(404, 'Temat finns inte längre.');
    return t;
  }

  // ---------- rutter ----------
  rutt('GET', '/galleri/schema', () => ({ nyckel: NYCKEL_RE.source, val: TEMA_VAL, maxNycklar: NYCKLAR_MAX, namnMax: NAMN_MAX, beskMax: BESK_MAX, perDygn: PUBL_PER_DYGN }));

  rutt('GET', '/galleri/lista', (req) => {
    if (begransad(`gallerilista:${ipAv(req)}`, 900, 3_600_000)) throw fel(429, 'För många förfrågningar. Vänta en stund.');
    const p = parametrar(req), vem = vemAr(req);
    const sort = ['populara', 'nya', 'vecka'].includes(p.get('sort')) ? p.get('sort') : 'populara';
    const sida = Math.max(0, Math.min(MAX_SIDA, parseInt(p.get('sida'), 10) || 0));
    const barn = p.get('barn') === '1' || (vem && vem.typ === 'barn');
    const barnVillkor = barn ? ' AND t.anmalningar=0' : '';
    // Den som har anmält ett tema ser det inte längre
    const minaAnm = ' AND NOT EXISTS (SELECT 1 FROM galleri_anmalningar a WHERE a.tema_id=t.id AND a.vem=?)';
    const nyckel = vem ? vem.nyckel : '';
    let rader;
    if (sort === 'vecka') {
      // Topplistan: poäng från röster och nedladdningar de senaste sju dagarna
      const fran = now() - VECKA;
      rader = q(`SELECT ${VAL()}, v.poang AS veckopoang FROM galleri_teman t JOIN (
          SELECT tema_id, SUM(p) AS poang FROM (
            SELECT tema_id, CASE rost WHEN 1 THEN 2 WHEN -1 THEN -2 ELSE 0 END AS p FROM galleri_roster WHERE ts>?
            UNION ALL SELECT tema_id, 1 AS p FROM galleri_nedladdningar WHERE ts>?) GROUP BY tema_id) v ON v.tema_id=t.id
        WHERE t.status='synlig' AND v.poang>0${barnVillkor}${minaAnm}
        ORDER BY v.poang DESC, t.gillar DESC, t.skapad DESC, t.rowid DESC LIMIT ? OFFSET ?`).all(nyckel, fran, fran, nyckel, PER_SIDA + 1, sida * PER_SIDA);
    } else {
      const ordning = sort === 'nya' ? 't.skapad DESC, t.rowid DESC' : '(t.gillar * 2 + t.nedladdningar - t.ogillar * 2) DESC, t.gillar DESC, t.skapad DESC, t.rowid DESC';
      rader = q(`SELECT ${VAL()} FROM galleri_teman t WHERE t.status='synlig'${barnVillkor}${minaAnm} ORDER BY ${ordning} LIMIT ? OFFSET ?`)
        .all(nyckel, nyckel, PER_SIDA + 1, sida * PER_SIDA);
    }
    const mer = rader.length > PER_SIDA;
    return { sort, sida, mer, teman: rader.slice(0, PER_SIDA).map((t, i) => utTema(t, vem, sort === 'vecka' ? { plats: sida * PER_SIDA + i + 1 } : undefined)) };
  });

  rutt('GET', '/galleri/tema', (req) => {
    if (begransad(`galleritema:${ipAv(req)}`, 900, 3_600_000)) throw fel(429, 'För många förfrågningar. Vänta en stund.');
    const p = parametrar(req), vem = vemAr(req);
    const t = synligtTema(giltigtId(p.get('id')), vem, p.get('barn') === '1');
    const ut = utTema(t, vem);
    return { tema: { ...ut, kod: kodAv(ut.varden) } };
  });

  rutt('GET', '/galleri/mina', (req) => {
    const u = kravInloggad(req), vem = { typ: 'vuxen', id: u.id, nyckel: 'u:' + u.id };
    const rader = q(`SELECT ${VAL()} FROM galleri_teman t WHERE t.agare=? AND t.status IN ('synlig','dold') ORDER BY t.skapad DESC, t.rowid DESC LIMIT ?`).all(vem.nyckel, u.id, AKTIVA_MAX);
    const idag = q('SELECT COUNT(*) AS n FROM galleri_teman WHERE agare=? AND skapad>?').get(u.id, now() - 86_400_000).n;
    return { teman: rader.map((t) => utTema(t, vem, { dold: t.status === 'dold' })), kvarIdag: Math.max(0, PUBL_PER_DYGN - idag) };
  });

  rutt('POST', '/galleri/publicera', (req, res, b) => {
    const u = kravInloggad(req);   // bara vuxna konton: barnkonton har ingen vanlig session
    if (begransad(`galleripub:${ipAv(req)}`, 30, 86_400_000)) throw fel(429, 'För många försök i dag. Försök igen i morgon.');
    const namnRa = typeof b.namn === 'string' ? b.namn.trim() : '';
    const beskRa = typeof b.beskrivning === 'string' ? b.beskrivning.trim() : '';
    if (langd(namnRa) > NAMN_MAX) throw fel(400, `Namnet får vara högst ${NAMN_MAX} tecken.`);
    if (langd(beskRa) > BESK_MAX) throw fel(400, `Beskrivningen får vara högst ${BESK_MAX} tecken.`);
    const namn = rensaText(namnRa), beskrivning = rensaText(beskRa);
    if (langd(namn) < 2) throw fel(400, 'Ge temat ett namn med minst två tecken (inga länkar).');
    const varden = lasTemaKod(b.kod);
    const idag = q('SELECT COUNT(*) AS n FROM galleri_teman WHERE agare=? AND skapad>?').get(u.id, now() - 86_400_000).n;
    if (idag >= PUBL_PER_DYGN) throw fel(429, `Du kan publicera ${PUBL_PER_DYGN} teman per dygn. Försök igen i morgon.`);
    if (q("SELECT COUNT(*) AS n FROM galleri_teman WHERE agare=? AND status IN ('synlig','dold')").get(u.id).n >= AKTIVA_MAX)
      throw fel(400, `Du har redan ${AKTIVA_MAX} teman i galleriet. Ta bort något först.`);
    const json = JSON.stringify(varden), hash = sha('galleri:' + json);
    const lika = q("SELECT namn FROM galleri_teman WHERE hash=? AND status='synlig'").get(hash);
    if (lika) throw fel(409, `Ett likadant tema finns redan i galleriet: ${lika.namn}.`);
    const id = 't' + crypto.randomBytes(10).toString('hex');
    q('INSERT INTO galleri_teman(id,agare,namn,beskrivning,varden,hash,visa_namn,skapad) VALUES(?,?,?,?,?,?,?,?)')
      .run(id, u.id, namn, beskrivning || null, json, hash, b.anonym === true ? 0 : 1, now());
    const vem = { typ: 'vuxen', id: u.id, nyckel: 'u:' + u.id };
    return { tema: utTema(q(`SELECT ${VAL()} FROM galleri_teman t WHERE t.id=?`).get(vem.nyckel, id), vem), kvarIdag: Math.max(0, PUBL_PER_DYGN - idag - 1) };
  });

  rutt('POST', '/galleri/rosta', (req, res, b) => {
    const vem = kravKonto(req, 'Logga in för att gilla teman.');
    const id = giltigtId(b.id);
    if (![1, -1, 0].includes(b.rost)) throw fel(400, 'Ogiltig röst.');
    if (begransad(`gallerirost:${vem.nyckel}`, 300, 3_600_000)) throw fel(429, 'Du har röstat många gånger nu. Vänta en stund.');
    const t = synligtTema(id, vem);
    if (egen(t, vem)) throw fel(403, 'Du kan inte rösta på ditt eget tema.');
    if (b.rost === 0) q('DELETE FROM galleri_roster WHERE tema_id=? AND vem=?').run(id, vem.nyckel);
    else q('INSERT INTO galleri_roster(tema_id,vem,rost,ts) VALUES(?,?,?,?) ON CONFLICT(tema_id,vem) DO UPDATE SET rost=excluded.rost, ts=excluded.ts WHERE rost<>excluded.rost')
      .run(id, vem.nyckel, b.rost, now());
    return { gillar: q('SELECT gillar FROM galleri_teman WHERE id=?').get(id).gillar, min_rost: b.rost };
  });

  rutt('POST', '/galleri/nedladdad', (req, res, b) => {
    if (begransad(`gallerined:${ipAv(req)}`, 120, 3_600_000)) throw fel(429, 'För ofta. Vänta en stund.');
    const vem = vemAr(req);
    const id = giltigtId(b.id);
    const t = synligtTema(id, vem);
    if (!egen(t, vem)) q('INSERT OR IGNORE INTO galleri_nedladdningar(tema_id,vem,ts) VALUES(?,?,?)').run(id, vem ? vem.nyckel : ipNyckel(req), now());
    return { nedladdningar: q('SELECT nedladdningar FROM galleri_teman WHERE id=?').get(id).nedladdningar };
  });

  rutt('POST', '/galleri/anmal', (req, res, b) => {
    const vem = kravKonto(req, 'Logga in för att anmäla ett tema.');
    const id = giltigtId(b.id);
    if (begransad(`gallerianm:${vem.nyckel}`, 20, 86_400_000)) throw fel(429, 'Du har anmält många teman i dag. Försök igen i morgon.');
    const t = q("SELECT id, agare, status FROM galleri_teman WHERE id=? AND status IN ('synlig','dold')").get(id);
    if (!t) throw fel(404, 'Temat finns inte längre.');
    if (egen(t, vem)) throw fel(400, 'Det är ditt eget tema. Du kan ta bort det i stället.');
    q('INSERT OR IGNORE INTO galleri_anmalningar(tema_id,vem,orsak,ts) VALUES(?,?,?,?)').run(id, vem.nyckel, ORSAKER.includes(b.orsak) ? b.orsak : 'annat', now());
    const n = q('SELECT anmalningar FROM galleri_teman WHERE id=?').get(id).anmalningar;
    if (n >= ANMAL_GRANS && t.status === 'synlig') {
      q("UPDATE galleri_teman SET status='dold' WHERE id=?").run(id);
      console.log(`[galleri] tema ${id} doldes efter ${n} anmälningar`);
    }
    return {};
  });

  rutt('POST', '/galleri/ta-bort', (req, res, b) => {
    const u = kravInloggad(req);
    const id = giltigtId(b.id);
    if (begransad(`galleribort:${u.id}`, 60, 3_600_000)) throw fel(429, 'För ofta. Vänta en stund.');
    if (!q("SELECT 1 FROM galleri_teman WHERE id=? AND agare=? AND status IN ('synlig','dold')").get(id, u.id)) throw fel(404, 'Temat finns inte.');
    // Raden blir kvar utan innehåll ett tag (dygnsgränsen räknar den), röster m.m. försvinner direkt
    db.exec('BEGIN IMMEDIATE');
    try {
      q("UPDATE galleri_teman SET status='borttagen', namn=NULL, beskrivning=NULL, varden=NULL, hash=NULL WHERE id=?").run(id);
      q('DELETE FROM galleri_roster WHERE tema_id=?').run(id);
      q('DELETE FROM galleri_nedladdningar WHERE tema_id=?').run(id);
      q('DELETE FROM galleri_anmalningar WHERE tema_id=?').run(id);
      db.exec('COMMIT');
    } catch (e) { try { db.exec('ROLLBACK'); } catch {} throw e; }
    return {};
  });

  return { lasTemaKod, rensaText };
};
