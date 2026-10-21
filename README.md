# adraze-api

Konto-API för AdRaze: konton (lösenord + sexsiffrig kod, eller Google), sessioner och statistik som tillägget skickar.
Ren Node 22 utan beroenden (`node:sqlite`), mejl via Brevo (adraze.app domänautentiserad).

Körs på doxing som `systemctl --user` -tjänsten `adraze-api` på 127.0.0.1:8492, nås via Cloudflare Tunnel som `api.adraze.app`.

    cp .env.example .env   # fyll i nycklarna
    node --no-warnings server.js
