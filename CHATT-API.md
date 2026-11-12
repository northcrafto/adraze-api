# AdRaze-chatten – API-kontrakt

Säkerkoll-communityns chatt-backend, portad till AdRaze-kontona (`chatt.js`). Bas: `https://api.adraze.app`.

## Allmänt

- **Regeln:** varje Säkerkoll-route `X` heter `/chatt` + `X`, med samma metod, samma request- och response-JSON, samma statuskoder och felkoder. Path-parametrar flyttas: `:id` → fältet `id`, `:gid` → fältet `gid`, i POST-kroppen för POST och i query-strängen för GET.
- **Inloggning:** AdRaze-kontot (`Authorization: Bearer <token>` från `/auth/*` med `app:true`, eller kakan `adr_s`). Säkerkolls `/users/register`, `/users/login`, `/users/logout` och sessionstokens finns inte. Inga svar innehåller `token`.
- **Lyckat svar:** `{ ok: true, ...Säkerkolls fält }`.
- **Fel:** `{ ok: false, error: "<kod>", message?: "<svensk text>", ...extra }` med samma status och kod som Säkerkoll (t.ex. `403 {error:"not_contacts"}`). Undantag som kommer från AdRaze-routern före chatten: `401 {error:"Du är inte inloggad."}`, `413 {error:"För stor förfrågan."}`, `415 {error:"Fel format."}` (POST måste ha `content-type: application/json`), `404 {error:"Finns inte."}`.
- **Ingen chattprofil än:** alla rutter utom `/chatt/jag`, `/chatt/registrera` och `/chatt/users/recovery/*` (params/reveal) svarar `403 {error:"no_profile"}`.
- **Avstängd:** `403 {error:"suspended", suspended_until, message}`.
- **Rate limit:** `429 {error:"rate_limited", message, retry_after_seconds}`.
- **Id:n:** användar-id = AdRaze `users.id` som **sträng** (`"12"`), precis som Säkerkolls id var strängar. In-fält (`to_id`, `user_id`, `with`, `id` för användare) tar `"12"` (eller 12). Grupp-id är slumpsträngar. Meddelande-id är heltal (som i Säkerkoll).
- **Profilbild:** AdRaze-kontots `users.avatar` (data-URL, JPEG 256×256). Sätts via `/me/avatar` eller `/chatt/users/avatar`. Alla `avatar`-fält kommer därifrån.
- **Pro/kontonummer finns inte:** `pro` är alltid `false`, `has_account` alltid `false`, `account_last4`/`account` alltid `null`.

## Profil (ersätter Säkerkolls register/login)

| Metod | Rutt | In | Ut |
|---|---|---|---|
| GET | `/chatt/jag` | – | Ingen profil: `{profil:null, forslag}` (ledigt användarnamn från `users.namn` eller mejlens början). Annars `{profil:true, id, username, bubble, has_account:false, account_last4:null, has_recovery, avatar, public_key, auto}` (`auto` = profilen är låst med kontonyckeln) |
| POST | `/chatt/registrera` | `{username, login_hash, public_key, enc_priv}` + valfritt räddning direkt: `{salt, rec_auth, rec_blob}` (alla tre eller inget) | `{id, username, has_recovery}`. Fel: `400 invalid_username` (3–20 tecken `A-Za-z0-9_`), `400 invalid_login_hash/invalid_public_key/invalid_enc_priv/invalid_input`, `409 username_taken` (versalokänsligt), `409 already_registered`, `429 too_many_users_per_ip` |
| POST | `/chatt/users/login` | `{login_hash, username?}` | Lås upp nycklarna på ny enhet (motsvarar Säkerkolls `/users/login`, men bara för den egna profilen): `{id, username, public_key, enc_priv, account:null, avatar}`. Fel: `401 invalid_login {attempts_left}`, `429 login_locked {retry_after_seconds}` (5 fel → 5 min) |
| GET | `/chatt/users/me` | – | `{id, username, bubble, has_account:false, account_last4:null, has_recovery, avatar}` |

Gränser: `login_hash` ≤200, `public_key` ≤2000, `enc_priv` ≤4000 base64-tecken (`[A-Za-z0-9+/=_-]`).

## Kontonyckel (chatten följer AdRaze-kontot)

Ingen hemlig kod längre: servern håller en slumpad hemlighet per konto (32 byte i `chatt_nycklar`, krypterad med AES-256-GCM under `CHATT_NYCKEL` i `.env`, 64 hex; utan den svarar rutterna `503`). Klienten härleder `login_hash = b64(sha256("adraze-chatt-auto-v1:" + secret))` och omslagsnyckeln `sha256("adraze-chatt-wrap-v1:" + secret)` (AES-GCM) för `enc_priv`. Samma konto på en annan dator = samma nycklar, direkt in med alla kontakter.

| Metod | Rutt | In | Ut |
|---|---|---|---|
| GET | `/chatt/nyckel` | – | `{secret}` (base64, `Cache-Control: no-store`), skapas första gången. 60/15 min |
| POST | `/chatt/users/ny-nyckel` | `{public_key, enc_priv, login_hash}` | `{}` – byter en gammal kodprofils nycklar mot kontonyckeln (`login_hash` måste vara kontots); räddningen nollas. 10/h |

**Backup av `CHATT_NYCKEL`:** tappas den kan ingen låsa upp sina chattnycklar. Kopia på mint i `~/.config/adraze-api/chatt-nyckel.env`.

## Inställningar, kod, räddning

| Metod | Rutt | In | Ut |
|---|---|---|---|
| GET | `/chatt/users/privacy` | – | `{privacy:{read_receipts, typing, requests:"all"\|"none", show_pro, presence, call_mail}}` (`presence`, `call_mail` är `true` om inget satts) |
| POST | `/chatt/users/privacy` | valfria av `{read_receipts, typing, show_pro, presence, call_mail}` (bool), `requests` | `{privacy}`. `presence:false` = visa inte när jag är online (och se inte andras); `call_mail:false` = inga mejl om missade samtal |
| POST | `/chatt/users/bubble` | `{color?:"#rrggbb", frame?: alg\|groda\|katt\|haj\|bjorn\|drake}` (båda tomma = ta bort) | `{bubble:{color,frame}\|null}`; `400 invalid_bubble` |
| POST | `/chatt/users/avatar` | `{avatar: dataURL-JPEG \| null \| ""}` (≤120 000 tecken) | `{avatar}`; `400 invalid_avatar`. Skriver `users.avatar` |
| POST | `/chatt/users/bio` | `{bio: text≤300 \| null \| ""}` | `{bio}`; `400 invalid_bio` |
| POST | `/chatt/users/verify-code` | `{login_hash}` | `{enc_priv}`; `403 wrong_code`, `429 locked` |
| POST | `/chatt/users/recovery/params` | `{username}` | `{salt}` (låtsas-salt, stabilt, för okända namn) |
| POST | `/chatt/users/recovery/set` | `{login_hash, salt, rec_auth, rec_blob}` | `{has_recovery:true}` (ingen `token`); `403 wrong_code` |
| POST | `/chatt/users/recovery/reveal` | `{username, rec_auth}` | `{username, rec_blob}`; `403 invalid_recovery`, `429 locked`. Kräver AdRaze-inloggning och att namnet är ens eget |
| POST | `/chatt/users/recovery/remove` | `{rec_auth}` | `{has_recovery:false}`; `403 invalid_recovery` |
| POST | `/chatt/users/rename` | `{new_username, old_login_hash, new_login_hash, enc_priv}` | `{username}` (ingen `token`); `403 wrong_code`, `400 same_username`, `409 username_taken`, `429 too_many_renames` (max 3/vecka). Gamla namnet blir ledigt direkt |
| POST | `/chatt/users/delete` | `{login_hash}` | `{}` – raderar chattprofilen med allt (inte AdRaze-kontot); `403 wrong_code` |

## Rapporter och länkar

| Metod | Rutt | In | Ut |
|---|---|---|---|
| POST | `/chatt/reports` | `{username, reason, details?, message_id?, message_kind?:"dm"\|"group", group_id?, excerpt?, evidence_img?}` | `{}` eller `{duplicate:true}`. reason: spam, scam, harassment, threat, hate, sexual, impersonation, doxxing, child, other (`other` kräver details ≥3). Fel: `400 invalid_reason/invalid_username/details_required/cant_report_self`, `404 user_not_found`, `403 no_relation`. Max 15/h |
| POST | `/chatt/links/check` | `{url}` | `{verdict:"clean"\|"warn"\|"danger", hits:[{why, list?, soft?}], lists_updated_at, lists_ready}`; `400 invalid_url` |
| POST | `/chatt/links/preview` | `{url}` | `{url, title, desc, site, icon, error?:"unreachable"}` eller `{blocked:true, reason?}`; `400 invalid_url` |

## Kontakter

| Metod | Rutt | In | Ut |
|---|---|---|---|
| GET | `/chatt/users/lookup?username=` | – | `{exists:false}` eller `{exists:true, id, username, public_key, avatar}`. `public_key` och `avatar` är `null` om man inte är kontakter (samma regel som `users/key`), och blockerade par får `{exists:false}` |
| GET | `/chatt/users/key?id=` | – | `{id, username, public_key, avatar}`; `404 not_found`, `403 not_contacts` |
| GET | `/chatt/users/profile?id=` | – | `{id, username, avatar, bio, created_at, friends, pro:false, is_self}`; `404`, `403 not_contacts` |
| POST | `/chatt/contacts/request` | `{username}` | `{status:"pending"\|"accepted"}`; `404 user_not_found`, `400 cant_add_self`, `403 blocked`, `403 requests_closed` |
| POST | `/chatt/contacts/accept` | `{username}` | `{}`; `404 no_pending_request`, `403 blocked` |
| POST | `/chatt/contacts/remove` | `{username}` | `{}` |
| POST | `/chatt/contacts/block` | `{username}` | `{}`; `400 cant_block_self` |
| POST | `/chatt/contacts/unblock` | `{username}` | `{}` |
| GET | `/chatt/contacts` | – | `{contacts:[{id, username, avatar, bubble, online, last_seen}], incoming:[{id, username, avatar}], outgoing:[…], blocked:[{id, username}]}` |

## Meddelanden

| Metod | Rutt | In | Ut |
|---|---|---|---|
| POST | `/chatt/messages/typing` | `{to_id}` eller `{group_id}` | `{}` eller `{off:true}`; `403 not_contacts/not_member`, `400 invalid_input` |
| POST | `/chatt/messages/send` | `{to_id, ciphertext (≤16384), attachment_id?}` | `{id, created_at}`; `400 invalid_input/bad_attachment`, `404 user_not_found`, `403 not_contacts` |
| GET | `/chatt/messages?with=&since=&changed_since=` | – | `{messages:[{id, mine, ciphertext, created_at, deleted, edited}], server_time, changes:[{id, deleted, edited, ciphertext}], peer_read_until, peer_read_at, typing}`; `400 missing_with`, `403 not_contacts` |
| GET | `/chatt/messages/overview` | – | `{unread:[{id, n}]}` |
| POST | `/chatt/messages/edit` | `{id, ciphertext}` | `{}`; `404`, `403 not_sender`, `400 already_deleted` |
| POST | `/chatt/messages/delete` | `{id}` | `{}`; `404`, `403 not_sender` |
| POST | `/chatt/messages/hide` | `{id}` | `{}`; `404`, `403 not_participant` |

## Bilagor och stickers

| Metod | Rutt | In | Ut |
|---|---|---|---|
| POST | `/chatt/messages/attachment` | `{ciphertext (≤2 200 000), to_id}` eller `{ciphertext, group_id}` | `{id}` (32 hex); `400 invalid_input`, `403 not_contacts/not_member`, `413 quota_exceeded` (bilagor per konto: högst 500 MB totalt och 200 MB per dygn) |
| GET | `/chatt/messages/attachment?id=` | – | `{ciphertext}`; `404`, `403 forbidden` (bara avsändare, mottagare eller gruppmedlem) |
| GET | `/chatt/stickers` | – | `{stickers:[{id, bytes, created_at}], max:120}` |
| GET | `/chatt/stickers?id=` | – | `{ciphertext}`; `404 not_found` (Säkerkolls `GET /stickers/:id`) |
| POST | `/chatt/stickers` | `{ciphertext (≤900 000)}` | `{id}`; `400 invalid_input/too_many` |
| POST | `/chatt/stickers/delete` | `{id}` | `{}` |

Bilagor som laddats upp men aldrig skickats städas efter 6 h. En bilaga kan bara bindas till ett meddelande, med samma mottagare/grupp som vid uppladdningen.

## Grupper

| Metod | Rutt | In | Ut |
|---|---|---|---|
| POST | `/chatt/groups/create` | `{name_enc, members:[{user_id, key_envelope}]}` (1–50, skaparen ska ingå) | `{id, created_at}`; `400 invalid_name/invalid_members/invalid_member_entry/creator_missing`, `404 member_not_found`, `403 not_contacts` |
| GET | `/chatt/groups` | – | `{groups:[{id, name_enc, owner_id, avatar_enc, key_envelope, wrapped_by, member_count, last_message_at, unread}]}` |
| GET | `/chatt/groups/members?id=` | – | `{owner_id, members:[{id, username, avatar, joined_at, is_admin, online?, last_seen?}]}` (online-fälten bara för mig själv och mina kontakter); `403 not_member` |
| GET | `/chatt/groups/messages?id=&since=&changed_since=` | – | `{messages:[{id, sender_id, sender_username, sender_bubble, mine, ciphertext, created_at, deleted, edited}], server_time, reads:[{id, username, read_at}], typing:[username], changes}`; `403 not_member` |
| POST | `/chatt/groups/messages` | `{id, ciphertext, attachment_id?}` | `{id, created_at}` (`id` i svaret = meddelandets id) |
| POST | `/chatt/groups/members` | `{id, user_id, key_envelope}` | `{}` eller `{already_member:true}`; `409 group_full`, `403 not_contacts` |
| POST | `/chatt/groups/rename` | `{id, name_enc}` | `{}`; `403 not_admin` |
| POST | `/chatt/groups/avatar` | `{id, avatar_enc (≤200 000) \| null \| ""}` | `{}`; `403 not_admin`, `400 invalid_avatar` |
| POST | `/chatt/groups/leave` | `{id}` | `{}` (sista medlemmen raderar gruppen) |
| POST | `/chatt/groups/kick` | `{id, user_id}` | `{}`; `400 cant_kick_self`, `403 cant_kick_owner`, `404 not_member/group_not_found` (alla medlemmar får kicka, aldrig ägaren) |
| POST | `/chatt/groups/promote` | `{id, user_id}` | `{}`; `403 not_admin` |
| POST | `/chatt/groups/demote` | `{id, user_id}` | `{}`; `403 cant_demote_owner` |
| POST | `/chatt/groups/messages/edit` | `{gid, id, ciphertext}` | `{}`; `403 not_member/not_sender`, `404` |
| POST | `/chatt/groups/messages/delete` | `{gid, id}` | `{}` |
| POST | `/chatt/groups/messages/hide` | `{gid, id}` | `{}` |

## Online-status

`online` (bool) och `last_seen` (ms, avrundat nedåt till 5 min) i kontaktlistan och gruppens medlemslista. Online = AdRaze
har frågat servern de senaste 2 minuterna (chattpanelen laddas dold så fort man är inloggad, så det betyder "AdRaze är igång
och inloggad"). Båda fälten är `null` om någon av de två har slagit av `presence`.

## Samtal (ringsignal)

Själva samtalet går direkt mellan datorerna (WebRTC). Offer/answer skickas som krypterade kontrollposter i meddelandekanalen
(se nedan); servern ser bara chiffertext. Rutterna här är bara ringsignalen: vem som ringer och ett slumpat samtals-id, i minnet.

| Metod | Rutt | In | Ut |
|---|---|---|---|
| POST | `/chatt/samtal/ring` | `{to_id, call_id}` (call_id 12–40 tecken `[A-Za-z0-9_-]`) | `{call_id, ring_ms}`; `403 not_contacts` (barnkonton: bara familjen), `409 call_exists`, `429` (30 per 10 min). Ett äldre utgående samtal som fortfarande ringer läggs på |
| GET | `/chatt/samtal` | – | `{incoming:[{call_id, from_id, from_username, started_at, ring_ms}], calls:[{call_id, state, with_id, outgoing}], server_time}` |
| POST | `/chatt/samtal/svar` | `{call_id, svar:"svara"\|"avboj"}` | `{state}`; `404 not_found` (bara mottagaren) |
| POST | `/chatt/samtal/avsluta` | `{call_id}` | `{state}`; `404 not_found`. Den som ringer och lägger på efter minst 8 s ringning = `missat` |

`state`: `ringer`, `svarat`, `avbojt`, `missat`, `avslutat`. Ringer det i 30 s utan svar blir det `missat`. Har det ringt minst
8 s får mottagaren ett mejl "<användarnamn> försökte ringa dig i AdRaze" om: `call_mail` är på, kontot är verifierat, inte
ett barnkonto och inte en `.invalid`-adress, och det inte gått något sådant mejl för samma par de senaste 30 minuterna
(mejlklassen `samtal`, `MAIL_SAMTAL_PER_DAG`, standard 30).

## Kontrollposter (klienten, servern ser bara chiffertext)

Reaktioner, samtal och skärmdelning skickas som vanliga krypterade meddelanden med klartexten
`{"sk":"txt","c":"<reservtext>","r"?:<citat>,"ax":{…}}`. Gamla klienter visar `c` som ett vanligt meddelande; nya läser `ax`:

- `{t:"rx", m:"<meddelande-id>", e:"<emoji>", on:bool}` – reaktion. En post per person, meddelande och emoji; ändras med edit.
- `{t:"ring", h:"offer"|"answer"|"slut", s:"<samtals-id>", sdp?, o?, d?}` – röstsamtal (o = missat/avbojt/klart/avbrutet, d = sekunder).
- `{t:"sk", h:"start"|"offer"|"answer"|"slut", s, n?, till?, sdp?}` – visa en flik (skärmdelning), högst 4 tittare.

## Finns inte (medvetet)

Säkerkolls `/users/register`, `/users/login` (med token), `/users/logout`, `/links/scan`, `/admin/reports*`, announcements, push, Pro, lapp, AI, familj. Rapporter sparas i `chatt_rapporter` men ingen granskningspanel eller mejlnotis finns än.
