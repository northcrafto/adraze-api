// Support (support.adraze.app): ärenden med meddelanden fram och tillbaka mellan kunden och teamet.
// Kunden får en hemlig länk (support.adraze.app/arende#<nyckel>) och mejl när teamet svarar.
// Teamet = inloggade AdRaze-konton vars mejl står i SUPPORT_TEAM; nya ärenden mejlas till SUPPORT_TILL.
module.exports = ({ rutt, q, db, fel, inloggad, kravInloggad, begransad, now, sha, ipAv, crypto, skickaMejl, mejlLayout, mejlText, esc, normEmail, EMAIL_RE }) => {
  const SAJT = (process.env.SUPPORT_URL || 'https://support.adraze.app').replace(/\/$/, '');
  const TEAM = new Set((process.env.SUPPORT_TEAM || 'cetoari9@gmail.com').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
  const TILL = process.env.SUPPORT_TILL || 'cetoari9@gmail.com';
  const KATEGORIER = ['tillagg', 'webblasare', 'konto', 'betalning', 'annat'];
  const STATUS = ['oppen', 'besvarad', 'stangd'];
  const MAX_TEXT = 5000, MAX_AMNE = 140, MAX_MEDDELANDEN = 100;
  // Kundens nyckel räknas fram ur ärendenumret med en hemlighet: samma länk i varje mejl, inget i klartext i databasen
  const HEMLIG = process.env.SUPPORT_SECRET || '';
  if (HEMLIG.length < 32) console.error('SUPPORT_SECRET saknas eller är för kort: supporten är avstängd');
  const nyckelFor = (nr) => { if (HEMLIG.length < 32) throw fel(503, 'Supporten är inte påslagen just nu.'); return crypto.createHmac('sha256', HEMLIG).update(`support:${nr}`).digest('base64url'); };

  db.exec(`CREATE TABLE IF NOT EXISTS support_arenden (
    id INTEGER PRIMARY KEY, nr TEXT NOT NULL UNIQUE, nyckel TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL, namn TEXT NOT NULL DEFAULT '', user_id INTEGER, kategori TEXT NOT NULL, amne TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'oppen', sprak TEXT NOT NULL DEFAULT 'sv', ip TEXT,
    skapad INTEGER NOT NULL, uppdaterad INTEGER NOT NULL, last_kund INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS support_meddelanden (
    id INTEGER PRIMARY KEY, arende_id INTEGER NOT NULL REFERENCES support_arenden(id) ON DELETE CASCADE,
    fran TEXT NOT NULL, namn TEXT NOT NULL DEFAULT '', text TEXT NOT NULL, skapad INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS support_med_arende ON support_meddelanden(arende_id, skapad);
  CREATE INDEX IF NOT EXISTS support_ar_user ON support_arenden(user_id);
  CREATE INDEX IF NOT EXISTS support_ar_upd ON support_arenden(uppdaterad);`);

  const rensa = (s, max) => String(s ?? '').replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max);
  // Ärendenummer som går att läsa upp i telefon: 6 tecken utan 0/O/1/I
  const nyttNr = () => {
    const tecken = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    for (;;) {
      const nr = Array.from(crypto.randomBytes(6), (b) => tecken[b % tecken.length]).join('');
      if (!q('SELECT 1 FROM support_arenden WHERE nr=?').get(nr)) return nr;
    }
  };
  const SPRAK = new Set('sv en nb da fi is de nl fr es pt it pl cs sk hu ro bg el hr sl et lv lt uk tr'.split(' '));
  const lank = (nyckel, sprak) => `${SAJT}${sprak === 'sv' ? '' : '/' + sprak}/arende#${nyckel}`;
  const engelska = (sprak) => !['sv', 'nb', 'da'].includes(sprak);
  const medd = (id) => q('SELECT fran, namn, text, skapad FROM support_meddelanden WHERE arende_id=? ORDER BY skapad, id').all(id);
  const ut = (a) => ({ nr: a.nr, amne: a.amne, kategori: a.kategori, status: a.status, skapad: a.skapad, uppdaterad: a.uppdaterad, meddelanden: medd(a.id) });
  const arendeAv = (nyckel) => {
    if (typeof nyckel !== 'string' || !/^[A-Za-z0-9_-]{32,64}$/.test(nyckel)) throw fel(404, 'Ärendet finns inte.');
    const a = q('SELECT * FROM support_arenden WHERE nyckel=?').get(sha(nyckel));
    if (!a) throw fel(404, 'Ärendet finns inte.');
    return a;
  };
  const kravTeam = (req) => {
    const u = kravInloggad(req);
    if (!TEAM.has(String(u.email).toLowerCase())) throw fel(403, 'Bara AdRaze-teamet kommer åt det här.');
    return u;
  };
  const stycken = (t) => esc(t).replace(/\n/g, '<br>');

  // ---------- mejl ----------
  function mejlKund(a, typ, nyckel, svar) {
    const en = engelska(a.sprak);
    const knapp = `<tr><td align="center" style="padding-top:26px"><a href="${lank(nyckel, a.sprak)}" style="display:inline-block;background:#17171a;color:#ffffff;text-decoration:none;font-weight:600;font-size:15px;padding:14px 26px;border-radius:999px">${en ? 'Open your case' : 'Öppna ärendet'}</a></td></tr>`;
    if (typ === 'mottaget') {
      const rubrik = en ? `We got your message (#${a.nr})` : `Vi har fått ditt meddelande (#${a.nr})`;
      const t = en ? 'Thanks for writing to AdRaze. We reply as fast as we can, and you will get an email when we do. Keep this email: the button takes you back to your case.' : 'Tack för att du hörde av dig till AdRaze. Vi svarar så snabbt vi kan, och du får ett mejl när vi har gjort det. Spara mejlet: knappen tar dig tillbaka till ärendet.';
      return skickaMejl(a.email, rubrik, mejlLayout(rubrik, mejlText(esc(t)) + mejlText(`<b>${esc(a.amne)}</b>`) + knapp), `${t}\n\n${lank(nyckel, a.sprak)}`, undefined, 'drift');
    }
    const rubrik = en ? `New reply on your case #${a.nr}` : `Nytt svar i ditt ärende #${a.nr}`;
    const citat = `<tr><td style="padding-top:22px"><div style="border-radius:12px;background:#f6f6f3;padding:16px 18px;font-size:15px;line-height:1.65;color:#17171a">${stycken(svar)}</div></td></tr>`;
    // Teamets svar räknas mot kontobudgeten, så att en flod av nya ärenden inte kan stoppa svaren
    return skickaMejl(a.email, rubrik, mejlLayout(rubrik, citat + knapp), `${svar}\n\n${en ? 'Reply here' : 'Svara här'}: ${lank(nyckel, a.sprak)}`, undefined, 'konto');
  }
  function mejlTeam(a, text, nytt) {
    const rubrik = `${nytt ? 'Nytt supportärende' : 'Nytt svar från kunden'} #${a.nr}: ${a.amne}`.slice(0, 160);
    const html = mejlLayout(rubrik, mejlText(`${esc(a.namn || a.email)} &lt;${esc(a.email)}&gt;<br>Kategori: ${esc(a.kategori)}`)
      + `<tr><td style="padding-top:22px"><div style="border-radius:12px;background:#f6f6f3;padding:16px 18px;font-size:15px;line-height:1.65;color:#17171a">${stycken(text)}</div></td></tr>`
      + `<tr><td align="center" style="padding-top:26px"><a href="${SAJT}/team#${a.nr}" style="display:inline-block;background:#ff4b1f;color:#17171a;text-decoration:none;font-weight:600;font-size:15px;padding:14px 26px;border-radius:999px">Svara i teampanelen</a></td></tr>`);
    return skickaMejl(TILL, rubrik, html, `${a.namn || ''} <${a.email}>\n${a.kategori}\n\n${text}\n\n${SAJT}/team#${a.nr}`, a.email, 'drift');
  }

  // ---------- kunden ----------
  rutt('POST', '/support/nytt', async (req, res, b) => {
    // Honungsfälla: fältet är osynligt för människor
    if (b.webbplats) return { nr: 'OK' };
    const ip = ipAv(req);
    const u = inloggad(req);
    const email = u ? u.email : normEmail(b.email);
    if (!EMAIL_RE.test(email)) throw fel(400, 'Skriv en giltig mejladress.');
    const amne = rensa(b.amne, MAX_AMNE), text = rensa(b.text, MAX_TEXT), namn = rensa(b.namn, 60);
    if (amne.length < 3) throw fel(400, 'Skriv vad det gäller.');
    if (text.length < 10) throw fel(400, 'Berätta lite mer, minst några ord.');
    const kategori = KATEGORIER.includes(b.kategori) ? b.kategori : 'annat';
    const sprak = SPRAK.has(b.sprak) ? b.sprak : 'sv';
    if (begransad(`support:ip:${ip}`, 6, 3_600_000) || begransad(`support:mejl:${email}`, 8, 86_400_000) || begransad('support:alla', 300, 86_400_000))
      throw fel(429, 'Du har skickat många meddelanden på kort tid. Vänta en stund och försök igen.');
    const nr = nyttNr(), nyckel = nyckelFor(nr);
    const t = now();
    const r = q('INSERT INTO support_arenden(nr,nyckel,email,namn,user_id,kategori,amne,sprak,ip,skapad,uppdaterad,last_kund) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(nr, sha(nyckel), email, namn || (u?.namn || ''), u ? u.id : null, kategori, amne, sprak, ip, t, t, t);
    q('INSERT INTO support_meddelanden(arende_id,fran,namn,text,skapad) VALUES(?,?,?,?,?)').run(r.lastInsertRowid, 'kund', namn, text, t);
    const a = q('SELECT * FROM support_arenden WHERE id=?').get(r.lastInsertRowid);
    await Promise.all([mejlKund(a, 'mottaget', nyckel), mejlTeam(a, text, true)]);
    return { nr: a.nr, nyckel };
  });

  // Nyckeln skickas i kroppen (inte i adressen) så att den aldrig hamnar i loggar
  rutt('POST', '/support/arende', async (req, res, b) => {
    if (begransad(`support:las:${ipAv(req)}`, 120, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
    return { arende: ut(arendeAv(b.nyckel)) };
  });

  rutt('POST', '/support/svara', async (req, res, b) => {
    const a = arendeAv(b.nyckel);
    const text = rensa(b.text, MAX_TEXT);
    if (text.length < 2) throw fel(400, 'Skriv ett meddelande.');
    if (begransad(`support:svar:${a.id}`, 20, 3_600_000) || begransad(`support:ip:${ipAv(req)}:svar`, 30, 3_600_000)) throw fel(429, 'Du har skickat många meddelanden. Vänta en stund.');
    if (q('SELECT COUNT(*) n FROM support_meddelanden WHERE arende_id=?').get(a.id).n >= MAX_MEDDELANDEN) throw fel(400, 'Ärendet är fullt. Skapa ett nytt ärende.');
    const t = now();
    q('INSERT INTO support_meddelanden(arende_id,fran,namn,text,skapad) VALUES(?,?,?,?,?)').run(a.id, 'kund', a.namn, text, t);
    q("UPDATE support_arenden SET status='oppen', uppdaterad=?, last_kund=? WHERE id=?").run(t, t, a.id);
    await mejlTeam(a, text, false);
    return { arende: ut(q('SELECT * FROM support_arenden WHERE id=?').get(a.id)) };
  });

  // Inloggade ser ärenden de skapat inloggade. Att mejladressen stämmer räcker inte: vem som helst kan skicka ett
  // ärende i någon annans namn. Ärenden äldre än kontot hör till ett tidigare konto med samma id.
  const egetArende = (nr, u) => q('SELECT * FROM support_arenden WHERE nr=? AND user_id=? AND skapad>=?').get(String(nr || ''), u.id, u.created_at);
  rutt('GET', '/support/mina', async (req) => {
    const u = kravInloggad(req);
    const rader = q(`SELECT a.nr, a.amne, a.status, a.uppdaterad, (SELECT fran FROM support_meddelanden m WHERE m.arende_id=a.id ORDER BY skapad DESC, id DESC LIMIT 1) AS senast
      FROM support_arenden a WHERE a.user_id=? AND a.skapad>=? ORDER BY a.uppdaterad DESC LIMIT 50`).all(u.id, u.created_at);
    return { arenden: rader, team: TEAM.has(String(u.email).toLowerCase()) };
  });
  // Ett eget ärende öppnas via kontot i stället för nyckeln
  rutt('POST', '/support/mitt', async (req, res, b) => {
    const u = kravInloggad(req);
    const a = egetArende(b.nr, u);
    if (!a) throw fel(404, 'Ärendet finns inte.');
    return { arende: ut(a) };
  });
  rutt('POST', '/support/mitt/svara', async (req, res, b) => {
    const u = kravInloggad(req);
    const a = egetArende(b.nr, u);
    if (!a) throw fel(404, 'Ärendet finns inte.');
    const text = rensa(b.text, MAX_TEXT);
    if (text.length < 2) throw fel(400, 'Skriv ett meddelande.');
    if (begransad(`support:svar:${a.id}`, 20, 3_600_000)) throw fel(429, 'Du har skickat många meddelanden. Vänta en stund.');
    if (q('SELECT COUNT(*) n FROM support_meddelanden WHERE arende_id=?').get(a.id).n >= MAX_MEDDELANDEN) throw fel(400, 'Ärendet är fullt. Skapa ett nytt ärende.');
    const t = now();
    q('INSERT INTO support_meddelanden(arende_id,fran,namn,text,skapad) VALUES(?,?,?,?,?)').run(a.id, 'kund', a.namn, text, t);
    q("UPDATE support_arenden SET status='oppen', uppdaterad=?, last_kund=? WHERE id=?").run(t, t, a.id);
    await mejlTeam(a, text, false);
    return { arende: ut(q('SELECT * FROM support_arenden WHERE id=?').get(a.id)) };
  });

  // ---------- teamet ----------
  rutt('GET', '/support/team/lista', async (req) => {
    kravTeam(req);
    const rader = q(`SELECT a.nr, a.email, a.namn, a.kategori, a.amne, a.status, a.sprak, a.skapad, a.uppdaterad,
      (SELECT text FROM support_meddelanden m WHERE m.arende_id=a.id ORDER BY skapad DESC, id DESC LIMIT 1) AS senast_text,
      (SELECT fran FROM support_meddelanden m WHERE m.arende_id=a.id ORDER BY skapad DESC, id DESC LIMIT 1) AS senast_fran,
      (SELECT COUNT(*) FROM support_meddelanden m WHERE m.arende_id=a.id) AS antal
      FROM support_arenden a ORDER BY (a.status='stangd'), a.uppdaterad DESC LIMIT 300`).all();
    for (const r of rader) r.senast_text = String(r.senast_text || '').slice(0, 160);
    return { arenden: rader };
  });
  const teamArende = (nr) => {
    const a = q('SELECT * FROM support_arenden WHERE nr=?').get(String(nr || ''));
    if (!a) throw fel(404, 'Ärendet finns inte.');
    return a;
  };
  const teamUt = (a) => ({ ...ut(a), email: a.email, namn: a.namn, sprak: a.sprak, konto: !!a.user_id });
  rutt('POST', '/support/team/arende', async (req, res, b) => { kravTeam(req); return { arende: teamUt(teamArende(b.nr)) }; });
  rutt('POST', '/support/team/svara', async (req, res, b) => {
    const u = kravTeam(req);
    const a = teamArende(b.nr);
    const text = rensa(b.text, MAX_TEXT);
    if (text.length < 2) throw fel(400, 'Skriv ett svar.');
    const t = now();
    q('INSERT INTO support_meddelanden(arende_id,fran,namn,text,skapad) VALUES(?,?,?,?,?)').run(a.id, 'team', rensa(u.namn, 40) || 'AdRaze', text, t);
    q("UPDATE support_arenden SET status='besvarad', uppdaterad=? WHERE id=?").run(t, a.id);
    const skickat = await mejlKund(a, 'svar', nyckelFor(a.nr), text);
    return { arende: teamUt(q('SELECT * FROM support_arenden WHERE id=?').get(a.id)), mejlat: !!skickat };
  });
  rutt('POST', '/support/team/status', async (req, res, b) => {
    kravTeam(req);
    const a = teamArende(b.nr);
    if (!STATUS.includes(b.status)) throw fel(400, 'Okänd status.');
    q('UPDATE support_arenden SET status=? WHERE id=?').run(b.status, a.id);
    return { arende: teamUt(q('SELECT * FROM support_arenden WHERE id=?').get(a.id)) };
  });
};
