// AdRaze Synk: bokmärken och kortkommandon mellan enheter. Per konto, krypterat vilande? Nej —
// lagras som JSON per användare. Sammanfogning sker med union (nyaste vinner per nyckel), och
// borttagningar sprids via gravstenar (url + tidpunkt). Enkelt och robust, ingen realtid behövs.
module.exports = ({ rutt, q, db, fel, kravInloggad, begransad, now }) => {
  db.exec(`CREATE TABLE IF NOT EXISTS synk(
    user_id INTEGER NOT NULL,
    sorts   TEXT NOT NULL,       -- 'bokmarken' | 'kortkommandon'
    data    TEXT NOT NULL,       -- JSON: { poster: {nyckel: {..., _t}}, borttagna: {nyckel: _t} }
    rev     INTEGER NOT NULL DEFAULT 1,
    updated INTEGER NOT NULL,
    PRIMARY KEY(user_id, sorts)
  );
  -- Raderas kontot raderas dess bokmärken och kortkommandon (även när obekräftade konton rensas)
  CREATE TRIGGER IF NOT EXISTS synk_konto_raderat AFTER DELETE ON users BEGIN
    DELETE FROM synk WHERE user_id = OLD.id;
  END;`);

  const SORTER = { bokmarken: 'url', kortkommandon: 'id' };
  const MAX = 5000;             // tak per sort så en trasig klient inte sväller valvet

  // En rad som är äldre än kontot blev kvar efter ett raderat konto med samma id och räknas som tom
  function las(u, sorts) {
    const rad = q('SELECT data, rev, updated FROM synk WHERE user_id=? AND sorts=?').get(u.id, sorts);
    if (!rad || rad.updated < u.created_at) return { poster: {}, borttagna: {}, rev: 0 };
    let d; try { d = JSON.parse(rad.data); } catch { d = {}; }
    return { poster: d.poster || {}, borttagna: d.borttagna || {}, rev: rad.rev };
  }

  function skriv(userId, sorts, state) {
    const rev = state.rev + 1;
    q(`INSERT INTO synk(user_id, sorts, data, rev, updated) VALUES(?,?,?,?,?)
       ON CONFLICT(user_id, sorts) DO UPDATE SET data=excluded.data, rev=excluded.rev, updated=excluded.updated`)
      .run(userId, sorts, JSON.stringify({ poster: state.poster, borttagna: state.borttagna }), rev, now());
    return rev;
  }

  // Lista ut posterna som faktiskt gäller (inte borttagna) för klienten
  function utatt(state) {
    return Object.values(state.poster).map((p) => { const { _t, ...rest } = p; return rest; });
  }

  // Hämta allt (vid inloggning på en ny enhet)
  rutt('POST', '/synk/get', async (req, res, b) => {
    const u = kravInloggad(req);
    const sorts = String((b && b.sorts) || '');
    if (!SORTER[sorts]) throw fel(400, 'Okänd sort.');
    const state = las(u, sorts);
    return { rev: state.rev, poster: utatt(state) };
  });

  // Skicka upp lokala ändringar och få tillbaka den sammanfogade listan
  rutt.max('/synk/push', 2_000_000);
  rutt('POST', '/synk/push', async (req, res, b) => {
    const u = kravInloggad(req);
    const sorts = String((b && b.sorts) || '');
    const nyckel = SORTER[sorts];
    if (!nyckel) throw fel(400, 'Okänd sort.');
    if (begransad(`synk:${u.id}`, 120, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');

    const state = las(u, sorts);
    const nu = now();
    const poster = Array.isArray(b.poster) ? b.poster : [];
    const borttagna = Array.isArray(b.borttagna) ? b.borttagna : [];

    // Gravstenar först: markera borttaget om borttagningen är nyare än posten
    for (const g of borttagna) {
      const k = g && g[nyckel]; if (!k) continue;
      const t = Number(g._t) || nu;
      if (!state.borttagna[k] || t > state.borttagna[k]) state.borttagna[k] = t;
      if (state.poster[k] && (state.poster[k]._t || 0) <= t) delete state.poster[k];
    }
    // Poster: lägg till/uppdatera om den inte tagits bort senare
    for (const p of poster) {
      const k = p && p[nyckel]; if (!k || typeof k !== 'string') continue;
      const t = Number(p._t) || nu;
      if (state.borttagna[k] && state.borttagna[k] >= t) continue;      // borttagen senare → hoppa
      if (state.borttagna[k]) delete state.borttagna[k];                 // återuppstånden
      const nuvarande = state.poster[k];
      if (!nuvarande || (nuvarande._t || 0) <= t) state.poster[k] = { ...p, _t: t };
    }
    // Håll valvet inom rimlig storlek
    const antal = Object.keys(state.poster).length;
    if (antal > MAX) {
      const sorterade = Object.entries(state.poster).sort((a, c) => (c[1]._t || 0) - (a[1]._t || 0)).slice(0, MAX);
      state.poster = Object.fromEntries(sorterade);
    }
    // Städa gamla gravstenar (äldre än 90 dygn)
    for (const k of Object.keys(state.borttagna)) if (state.borttagna[k] < nu - 90 * 86_400_000) delete state.borttagna[k];

    const rev = skriv(u.id, sorts, state);
    return { rev, poster: utatt(state) };
  });

  return {};
};
