#!/bin/bash
# Bygger krypterade lägets motor (Go + uTLS -> wasm) till ../transport/krypterad.wasm (+ .br/.gz för servern).
# Kräver Go >= 1.24 (GO=/sökväg/till/go om den inte ligger i PATH).
set -euo pipefail
cd "$(dirname "$0")"
GO=${GO:-go}
UT=../transport
GOOS=js GOARCH=wasm "$GO" build -trimpath -ldflags="-s -w" -o "$UT/krypterad.wasm" .
cp "$("$GO" env GOROOT)/lib/wasm/wasm_exec.js" "$UT/wasm_exec.js"
node -e '
const z = require("zlib"), fs = require("fs"), f = process.argv[1], b = fs.readFileSync(f);
fs.writeFileSync(f + ".br", z.brotliCompressSync(b, { params: { [z.constants.BROTLI_PARAM_QUALITY]: 11, [z.constants.BROTLI_PARAM_SIZE_HINT]: b.length } }));
fs.writeFileSync(f + ".gz", z.gzipSync(b, { level: 9 }));
' "$UT/krypterad.wasm"
ls -la "$UT"
