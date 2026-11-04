#!/bin/bash
# Lägger ut AdRaze Proxy på doxing: serverkoden härifrån, sidan från ~/adraze/proxy (bygg först med
# python3 ~/adraze/site/bygg.py) och tilläggets regler/kosmetik/sidskript från ~/adraze/extension.
# Kör: ./deploy.sh   (startar bara om adraze-proxy)
set -euo pipefail
cd "$(dirname "$0")"
MAL=doxing:adraze-api/proxy
ssh doxing 'mkdir -p ~/adraze-api/proxy/webb ~/adraze-api/proxy/extension'
rsync -a --delete --exclude node_modules --exclude webb --exclude extension ./ "$MAL/"
# Sidans js/css får ?v=<innehållshash> så att Cloudflare och webbläsare aldrig ger en gammal version
WEBB=$(mktemp -d); trap 'rm -rf "$WEBB"' EXIT
rsync -a --delete ~/adraze/proxy/ "$WEBB/"
# Samma bakgrundsfoton som AdRaze-webbläsaren (servern godtar bara de här i /adraze/bild/)
cp ~/adraze/browser/ui/bakgrunder.json "$WEBB/bakgrunder.json"
for f in proxy.js proxy.css main.js style.css; do
  [ -f "$WEBB/$f" ] || continue
  v=$(sha256sum "$WEBB/$f" | cut -c1-10)
  find "$WEBB" -name '*.html' -exec sed -i "s#\(src\|href\)=\"/$f\"#\1=\"/$f?v=$v\"#g" {} +
done
rsync -a --delete "$WEBB/" "$MAL/webb/"
rsync -a --delete --include '/rules/***' --include '/data/***' --include '/stubbar/***' --include '/content/***' --exclude '*' ~/adraze/extension/ "$MAL/extension/"
rsync -a ../adraze-proxy.service doxing:.config/systemd/user/adraze-proxy.service
ssh doxing 'cd ~/adraze-api/proxy && npm ci --omit=dev --no-audit --no-fund >/dev/null && systemctl --user daemon-reload && systemctl --user enable --now adraze-proxy >/dev/null 2>&1; systemctl --user restart adraze-proxy && sleep 8 && curl -fsS http://127.0.0.1:8495/adraze/status && echo'
