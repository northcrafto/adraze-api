// Test: Prowls lägen i Falk (Validator, Critic, Writer). Klienten skickar bara lägets namn, servern lägger på prompten
// från falk-lagen/, och promptens tokens dras inte från användarens kvot. Låtsas-AI: inga riktiga anrop.
// Kör: node test/falk-lagen-test.mjs
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite'; import { fileURLToPath } from 'node:url';
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 18541, AI_PORT = 18542, BAS = `http://127.0.0.1:${PORT}`;

const ai = { anrop: [], usage: null };
const aiSrv = http.createServer((req, res) => {
  let kropp = ''; req.on('data', (d) => { kropp += d; });
  req.on('end', () => {
    const b = JSON.parse(kropp || '{}'); ai.anrop.push(b);
    const tecken = b.messages.reduce((a, m) => a + String(m.content || '').length, 0);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'VERDICT: REJECTED' } }], usage: { total_tokens: ai.usage ?? Math.ceil(tecken / 3) + 100 } }));
  });
});
await new Promise((r) => aiSrv.listen(AI_PORT, '127.0.0.1', r));

const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-falk-lagen-'));
for (const f of fs.readdirSync(REPO)) if (f.endsWith('.js')) fs.copyFileSync(path.join(REPO, f), path.join(tmp, f));
const lagen = path.join(tmp, 'lagen'); fs.mkdirSync(lagen);
const VAL = '# VALIDATOR\n' + 'Vem är offret? '.repeat(800);   // 12 000 tecken = 4 000 tokens
fs.writeFileSync(path.join(lagen, 'validator.md'), VAL); fs.writeFileSync(path.join(lagen, 'writer.md'), '# WRITER\nSkriv rapporten.');
const ENV = { PATH: process.env.PATH, HOME: tmp, PORT: String(PORT), MAIL_LOGG: '1', BREVO_API_KEY: '', CHATT_HOTLISTOR: '0', CLAMD_PORT: '1',
  CHATT_NYCKEL: crypto.randomBytes(32).toString('hex'), SUPPORT_SECRET: crypto.randomBytes(32).toString('hex'),
  STRIPE_SECRET_KEY: '', AI_CHAT_BASE: `http://127.0.0.1:${AI_PORT}/v1/chat/completions`, AI_CHAT_KEY: 'lats', AI_CHAT_MODEL: 'deepseek/deepseek-v4-flash-0731',
  FALK_LAGEN_DIR: lagen, FALK_MINUT_TAK: '1000' };
let logg = ''; const srv = spawn(process.execPath, [path.join(tmp, 'server.js')], { cwd: tmp, env: ENV, stdio: ['ignore', 'pipe', 'pipe'] });
srv.stdout.on('data', (d) => { logg += d; }); srv.stderr.on('data', (d) => { logg += d; });
process.on('exit', () => { try { srv.kill(); } catch {} aiSrv.close(); fs.rmSync(tmp, { recursive: true, force: true }); });
for (let i = 0; i < 100 && !logg.includes('adraze-api på'); i++) await new Promise((r) => setTimeout(r, 50));
const db = new DatabaseSync(path.join(tmp, 'adraze.db'));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
let n = 0;
function konto(pro) {
  n++;
  const id = Number(db.prepare('INSERT INTO users(email,pass,verified,created_at,pro_until) VALUES(?,?,1,?,?)')
    .run(`lage${n}@test.invalid`, 'x:y', Date.now(), pro ? Date.now() + 20 * 86400_000 : null).lastInsertRowid);
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(token), id, Date.now() + 86400_000);
  return { id, token };
}
const fraga = async (v, extra = {}) => {
  const r = await fetch(BAS + '/falk/chat', { method: 'POST', headers: { 'cf-connecting-ip': '10.9.0.' + v.id, authorization: 'Bearer ' + v.token, 'content-type': 'application/json' },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'KONTEXT: Du är Falk.' }, { role: 'assistant', content: 'Okej.' }, { role: 'user', content: 'IDOR på /api/users/2' }], ...extra }) });
  let j = null; try { j = await r.json(); } catch {} return { s: r.status, j };
};
let ok = 0, fel = 0; const koll = (namn, v, info) => { if (v) { ok++; console.log('  ok  ', namn); } else { fel++; console.log('  FEL ', namn, JSON.stringify(info ?? '').slice(0, 400)); } };
const sys = () => ai.anrop.at(-1).messages.find((m) => m.role === 'system').content;

// 1) Utan läge: precis som förr
const g0 = konto(false); let r = await fraga(g0);
koll('utan läge: svar, ingen lägesprompt, vanlig svarslängd', r.s === 200 && !sys().includes('AKTIVT LÄGE') && ai.anrop.at(-1).max_tokens === 1500, [r.s, ai.anrop.at(-1).max_tokens]);
const utan = r.j.kvot.anvant;

// 2) Validator: prompten läggs först i systemmeddelandet, och längre svar tillåts även för gratis
const g1 = konto(false); r = await fraga(g1, { lage: 'validator' });
koll('validator: svar', r.s === 200 && r.j?.reply === 'VERDICT: REJECTED', r);
koll('validator: prompten ligger först hos AI:n', sys().startsWith('AKTIVT LÄGE: VALIDATOR') && sys().includes(VAL.trim()) && sys().includes('web_search'), sys().slice(0, 80));
koll('validator: klientens meddelanden följer med oförändrade', ai.anrop.at(-1).messages.at(-1).content === 'IDOR på /api/users/2' && ai.anrop.at(-1).messages.length === 4, ai.anrop.at(-1).messages.length);
koll('validator: längre svar tillåts för gratis', ai.anrop.at(-1).max_tokens === 3000, ai.anrop.at(-1).max_tokens);
// 3) Kvoten: lägets prompt (drygt 4 000 tokens) dras inte från användaren
koll('validator: prompten dras inte från kvoten', Math.abs(r.j.kvot.anvant - utan) <= 2, [r.j.kvot.anvant, utan]);
// ... men räknas mot dygnstaket
const dag = db.prepare('SELECT tokens FROM falk_dag').get().tokens;
koll('validator: hela kostnaden räknas mot dygnstaket', dag > utan * 2 + 4000, dag);

// 4) Writer finns, critic saknar fil och okända lägen ignoreras utan fel
r = await fraga(konto(false), { lage: 'writer' });
koll('writer: egen prompt', r.s === 200 && sys().startsWith('AKTIVT LÄGE: WRITER') && sys().includes('Skriv rapporten.'), sys().slice(0, 60));
r = await fraga(konto(false), { lage: 'critic' });
koll('läge utan fil: vanlig Falk', r.s === 200 && !sys().includes('AKTIVT LÄGE'), sys().slice(0, 60));
for (const lage of ['__proto__', 'constructor', 'toString', '../validator', 42, ['validator']]) {
  r = await fraga(konto(false), { lage });
  koll('okänt läge ignoreras: ' + JSON.stringify(lage), r.s === 200 && !sys().includes('AKTIVT LÄGE'), [r.s, sys().slice(0, 60)]);
}
// 5) Pro behåller sin längre svarslängd
r = await fraga(konto(true), { lage: 'validator' });
koll('pro: 4000 i svarslängd även i läge', ai.anrop.at(-1).max_tokens === 4000 && ai.anrop.at(-1).model === 'deepseek/deepseek-v4-flash-0731', ai.anrop.at(-1).max_tokens);
// 6) Slut på kvot stoppar även lägena
const g2 = konto(false); await fraga(g2); db.prepare('UPDATE falk_kvot SET tokens=50000 WHERE user_id=?').run(g2.id);
const fore = ai.anrop.length; r = await fraga(g2, { lage: 'validator' });
koll('slut på kvot: 429 och inget AI-anrop', r.s === 429 && r.j?.error === 'kvot_slut' && ai.anrop.length === fore, r);

console.log(`\n${ok} ok, ${fel} fel`); if (fel) console.log(logg.slice(-1500)); process.exit(fel ? 1 : 0);
