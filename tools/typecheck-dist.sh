#!/bin/bash
# Type-checks the emitted declarations standalone under the module resolution and library
# configurations consumers use. The main and Passport entry points are checked separately because
# Passport intentionally brings Node.js framework types into its declaration graph.
set -e

TSC="./node_modules/.bin/tsc"
BASE="--noEmit --ignoreConfig --strict --skipLibCheck false --target esnext"
MAIN="build/index.d.ts"
PASSPORT="build/passport.d.ts"

for ENTRY in "$MAIN" "$PASSPORT"; do
  if [ ! -f "$ENTRY" ]; then
    echo "$ENTRY not found - run 'npm run build' first" >&2
    exit 1
  fi
done

run() {
  local entry="$1"
  shift
  echo "  $entry $*"
  # shellcheck disable=SC2086
  $TSC $BASE "$@" "$entry"
}

echo "main entry module resolution modes"
run "$MAIN" --module preserve --moduleResolution bundler --lib esnext,dom,dom.iterable
run "$MAIN" --module node16 --moduleResolution node16 --lib esnext,dom,dom.iterable
run "$MAIN" --module nodenext --moduleResolution nodenext --lib esnext,dom,dom.iterable

echo "supported main-entry consumer configurations"
# Browser / bundler: DOM lib, no @types/node
run "$MAIN" --module preserve --moduleResolution bundler --lib esnext,dom,dom.iterable \
  --typeRoots /nonexistent
# Node: @types/node, no DOM lib
run "$MAIN" --module nodenext --moduleResolution nodenext --lib esnext --types node

echo "Passport entry Node.js configurations"
run "$PASSPORT" --module preserve --moduleResolution bundler --lib esnext --types node
run "$PASSPORT" --module node16 --moduleResolution node16 --lib esnext --types node
run "$PASSPORT" --module nodenext --moduleResolution nodenext --lib esnext --types node

# Neither DOM lib nor @types/node. The published main-entry types are not expected to be
# self-contained here, but their ambient dependencies are a contract. Pin the exact set so a new
# dependency surfaces in CI. `crypto` must not appear: CryptoKey is delegated to oauth4webapi's
# checked host alias and fallback.
echo "ambient globals depended on by the main entry with a bare lib"
EXPECTED="AbortSignal Headers ReadableStream Request Response URL URLSearchParams"
# shellcheck disable=SC2086
ACTUAL=$(
  $TSC $BASE --module preserve --moduleResolution bundler --lib esnext \
    --typeRoots /nonexistent "$MAIN" 2>&1 |
    sed -n "s/.*error TS2304: Cannot find name '\([A-Za-z0-9_]*\)'.*/\1/p" | sort -u | tr '\n' ' ' | xargs
)
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "  FAIL: the ambient globals the published main-entry types depend on changed" >&2
  echo "    expected: $EXPECTED" >&2
  echo "    actual:   $ACTUAL" >&2
  exit 1
fi
echo "  $ACTUAL"

echo "OK"
