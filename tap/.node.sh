#!/bin/bash

source .node_flags.sh

. ./tap/.server.sh

node tap/run-node.ts
