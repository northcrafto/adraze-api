# adraze-api

Servrarna bakom [AdRaze](https://adraze.app): konto-API:t och [AdRaze Proxy](https://proxy.adraze.app). Webbsidorna, tillägget och webbläsaren ligger i [northcrafto/adraze](https://github.com/northcrafto/adraze).

Licens: **AGPL-3.0**. Kör du en ändrad version som tjänst åt andra ska du dela källkoden.

## Konto-API (`server.js`)

Konton (lösenord + sexsiffrig kod, eller Google), sessioner, statistik som tillägget skickar, chatt, support och "Stöd oss" (Stripe).
Ren Node 22 utan beroenden (`node:sqlite`), mejl via Brevo.

    cp .env.example .env   # fyll i nycklarna
    node --no-warnings server.js

Körs som `systemctl --user`-tjänsten `adraze-api` på 127.0.0.1:8492 och nås via Cloudflare Tunnel som `api.adraze.app`.

## AdRaze Proxy (`proxy/`)

En webbproxy i stil med CroxyProxy, med AdRazes blockerare inbyggd. Den bygger på [Scramjet](https://github.com/MercuryWorkshop/scramjet), [Wisp](https://github.com/MercuryWorkshop/wisp-js) och [libcurl.js](https://github.com/ading2210/libcurl.js).
TLS sker i webbläsaren, så servern ser bara värdnamn och krypterade byte.

Blockeringen sker i tre lager, med samma regler som tillägget:

1. Wisp-servern vägrar ansluta till kända reklam-, spårar- och farliga värdar.
2. En service worker prövar varje förfrågan mot tilläggets DNR-regler (`filtermotor.cjs`).
3. HTML-sidor får tilläggets kosmetik-CSS och sidskript (kakrutor, popunders, YouTube-reklam).

Skydd: servern ansluter bara till port 80/443, aldrig till privata eller lokala adresser, och slår upp namn med 1.1.1.2. Den kör TCP, inte UDP, och har gränser för antal anslutningar per IP och totalt.

    cd proxy && npm ci && PROXY_PORT=8495 node proxy.mjs

`webb/` byggs av `site/bygg.py` i huvudrepot, och `extension/` är tilläggets `rules`, `data`, `stubbar` och `content`. `deploy.sh` gör allt det och startar om tjänsten.
