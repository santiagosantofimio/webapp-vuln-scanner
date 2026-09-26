#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Uso: scripts/deploy-report.sh <url> [-- <opciones de argus>]" >&2
  echo "Ejemplo: scripts/deploy-report.sh https://localhost:8080" >&2
  echo "Ejemplo: scripts/deploy-report.sh https://mi-sitio.com -- --i-own-this" >&2
  exit 1
fi

URL="$1"
shift
if [ "${1:-}" = "--" ]; then
  shift
fi

PROJECT="${ARGUS_PAGES_PROJECT:-argus-sentinel}"
BUILD_DIR="${ARGUS_BUILD_DIR:-site}"

mkdir -p "$BUILD_DIR"

if command -v argus >/dev/null 2>&1; then
  ARGUS=(argus)
else
  ARGUS=(python -m argus)
fi

set +e
"${ARGUS[@]}" "$URL" --html "$BUILD_DIR/index.html" "$@"
STATUS=$?
set -e

if [ ! -s "$BUILD_DIR/index.html" ]; then
  echo "No se generó el reporte HTML; se aborta el despliegue." >&2
  exit 1
fi

if [ ! -f wrangler.jsonc ] && [ ! -f wrangler.toml ]; then
  cat > wrangler.jsonc <<EOF
{
  "name": "${PROJECT}",
  "compatibility_date": "$(date +%F)",
  "assets": { "directory": "${BUILD_DIR}" }
}
EOF
fi

npx --yes wrangler deploy

echo "Reporte de ${URL} publicado en Cloudflare Pages (proyecto: ${PROJECT})."
echo "El escaneo terminó con código ${STATUS} (distinto de 0 = hubo hallazgos)."
