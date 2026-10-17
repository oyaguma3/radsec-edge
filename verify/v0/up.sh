#!/usr/bin/env bash
# 起動の順（上流 → エッジ → AP の役）。radsecproxy は起動のときに server のホスト名を引けないと終了するため。
set -euo pipefail
cd "$(dirname "$0")"
docker compose up -d upstream
sleep 2
docker compose up -d edge-a1 edge-a2 edge-b1 edge-c1
sleep 3
docker compose up -d
sleep 5
docker compose ps -a --format '{{.Service}}\t{{.State}}\t{{.Status}}'
