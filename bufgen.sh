#!/usr/bin/env bash

set -euo pipefail

pnpm exec buf format proto -w
pnpm exec buf lint
rm -rf gen/go/proto gen/es/proto
pnpm exec buf generate
