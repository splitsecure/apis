#!/usr/bin/env bash

set -euo pipefail

pnpm exec buf format proto -w
pnpm exec buf lint
rm -rf gen
pnpm exec buf generate
