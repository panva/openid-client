#!/bin/bash

. ./tap/.server.sh

echo "Using $(deno --version | head -1)"

deno run --allow-read --allow-net --allow-env --import-map tap/import_map.json tap/run-deno.ts
