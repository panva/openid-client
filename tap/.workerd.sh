#!/bin/bash

. ./tap/.server.sh

WORKERD_BIN=${WORKERD_BIN:-"$(pwd)/tap/workerd/node_modules/.bin/workerd"}
WORKERD_MODULE=${WORKERD_MODULE:-"$(pwd)/tap/workerd/node_modules/workerd"}

COMPATIBILITY_DATE=$(WORKERD_MODULE="$WORKERD_MODULE" node -p "const d = require(process.env.WORKERD_MODULE).compatibilityDate, t = new Date().toISOString().slice(0,10); d > t ? t : d")
WORKERD_VERSION=$(WORKERD_MODULE="$WORKERD_MODULE" node -p "require(process.env.WORKERD_MODULE + '/package.json').version")

echo "Using workerd $WORKERD_VERSION, compatibility date $COMPATIBILITY_DATE"

./node_modules/.bin/esbuild \
  --log-level=warning \
  --format=esm \
  --bundle \
  --minify-syntax \
  --target=esnext \
  --outfile=tap/run-workerd.js \
  tap/run-workerd.ts

cat <<EOT > $(pwd)/tap/.workerd.capnp
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .tapWorker),
    (name = "fullNetwork", network = .myNetwork),
  ],
);

const tapWorker :Workerd.Worker = (
  modules = [
    (name = "worker", esModule = embed "run-workerd.js")
  ],
  globalOutbound = "fullNetwork",
  compatibilityDate = "$COMPATIBILITY_DATE",
);

const myNetwork :Workerd.Network = (
  allow = ["public", "private"],
  deny = []
);
EOT

"$WORKERD_BIN" test --verbose "$(pwd)/tap/.workerd.capnp"
