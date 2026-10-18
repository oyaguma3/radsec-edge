#!/usr/bin/env bash
# 単独モードの通し（E2E。設計概要 §17、§22）。本PoC・radsec-ca・エッジ（この作業ツリー）を 1 台のホストに導入し、
# eapaka_test → AP の役の radsecproxy → エッジ → 本PoC の経路で確かめる。
#
# 使い方: scripts/e2e.sh [作業ディレクトリ]（既定 ./e2e-work）
#   KEEP=1 を付けると、終わった後もコンテナと作業ディレクトリを残す（調べるとき用）。
# 必要なもの: Docker（compose プラグイン。Docker Desktop は不可。bridge のゲートウェイの IP にポートを公開するため）、
#   git、curl、openssl、python3、sudo（ホストのディレクトリと KEK の所有者を変える）。
#
# 待ち受けはループバックと、テナントのネットワーク（radsec-edge-tenants。$SUBNET）のゲートウェイの IP（ホストの中だけの
# アドレス）に限る。テナントのポート、本PoC の RADIUS、radsec-ca の管理API と配布の口は、そのゲートウェイの IP に公開する
# （§22.2 の 1）。エッジから本PoC へは別の bridge の公開ポートへ送るので、本PoC からは送信元が本PoC のネットワークの
# ゲートウェイに見える（§22.2 の末尾）。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mkdir -p "${1:-$ROOT/e2e-work}" && cd "${1:-$ROOT/e2e-work}" && pwd)
SRC=$WORK/src
BIN=$WORK/bin
LOGS=$WORK/logs
CASES=$WORK/cases
PKI=$WORK/pki
mkdir -p "$SRC" "$BIN" "$LOGS" "$CASES" "$PKI"

# shellcheck source=e2e-versions.env
source "$ROOT/scripts/e2e-versions.env"

POC=$SRC/eapaka-radius-server-poc
CA=$SRC/radsec-ca
EAPAKA_TEST=$SRC/eapaka_test

# 試験の値。
SUBNET=172.31.83.0/24
GW=172.31.83.1
TENANT=tenant-a
PORT=20831
EDGE_NAME=e2e-edge
URN_PREFIX=example
DOMAIN=radsec.test
IMSI=440200000000001
KI=465b5ce8b199b49faa5f0a2ee238a6bc # 3GPP TS 35.208 Test Set 1
OPC=cd63cb71954a9f4e48a5994e37a02baf
SSID=MySSID
NAS_SPOOF=spoofed-nas # eapaka_test が名乗る NAS-Identifier（エッジが置き換える）
NAS_ID=$TENANT-ap-001 # エッジが置き換えた後の NAS-Identifier（認可ポリシーはこれだけを許す）
AP_SECRET=e2e-ap-secret
CURL_IMAGE=curlimages/curl:8.11.1
EDGE_C=radsec-edge-radsec-edge-1

step() { printf '\n== %s\n' "$*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
pass() { echo "ok: $*"; }
rand() { openssl rand -hex 16; }

# fingerprint は PEM の証明書の SHA-256 フィンガープリント（16 進小文字、区切りなし）を出す。
fingerprint() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }

# setenv は .env の項目を置き換える（なければ末尾に加える）。
setenv() {
	local file=$1 key=$2 value=$3
	python3 - "$file" "$key" "$value" <<'PY'
import sys
path, key, value = sys.argv[1:]
lines = open(path, encoding="utf-8").read().splitlines()
if any(l.startswith(key + "=") for l in lines):
    lines = [f"{key}={value}" if l.startswith(key + "=") else l for l in lines]
else:
    lines.append(f"{key}={value}")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
}

# json はファイルの JSON から python の式（d が JSON）の値を出す。
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1"; }

# fetch はリポジトリの決まったコミットを取得する（公開リポジトリなので認証は要らない）。
fetch() {
	local repo=$1 ref=$2 dir=$3
	rm -rf "$dir"
	git init -q "$dir"
	git -C "$dir" fetch -q --depth 1 "https://github.com/oyaguma3/$repo.git" "$ref"
	git -C "$dir" checkout -q FETCH_HEAD
	echo "$repo: $(git -C "$dir" log -1 --format='%h %s')"
}

# edge_compose / ca_compose / poc_compose は各 compose を、E2E の設定で動かす。
edge_compose() { docker compose --project-directory "$ROOT" -f "$ROOT/compose.yaml" -f "$WORK/edge-override.yaml" --env-file "$WORK/edge.env" "$@"; }
ca_compose() { (cd "$CA" && docker compose -f compose.yaml -f "$WORK/ca-override.yaml" "$@"); }
poc_compose() { (cd "$POC/deployments" && docker compose "$@"); }

# edge は、エッジの画面の口を、radsec-edge のコンテナのネットワークの中から叩く（画面は開発用の設定でループバックだけで
# 待ち受ける。§22.2 の 3）。edge <メソッド> <パス> [curl の引数...]。本文を標準出力に出す。
edge() {
	local method=$1 path=$2
	shift 2
	docker run --rm -i --network "container:$EDGE_C" "$CURL_IMAGE" -sS --fail-with-body -H 'Sec-Fetch-Site: same-origin' \
		-H 'HX-Request: true' -X "$method" "$@" "http://127.0.0.1:8447$path"
}

# edge_pem は PEM のファイルを pem の項目として送る。
edge_pem() { edge POST "$1" --data-urlencode "pem@-" <"$2"; }

# expect_html は、画面の応答に文字列があることを確かめる。
expect_html() {
	local what=$1 file=$2 text=$3
	grep -qF -- "$text" "$file" || {
		python3 -c 'import html,re,sys; t=html.unescape(re.sub(r"<[^>]+>"," ",open(sys.argv[1]).read())); print(re.sub(r"\s+"," ",t)[:3000])' "$file" >&2
		fail "$what: 応答に「$text」がない"
	}
}

# ca_api は radsec-ca の管理API を呼ぶ（試験用の管理クライアント e2e として）。ca_api <メソッド> <パス> [本文]
ca_api() {
	local method=$1 path=$2 body=${3:-}
	curl -sS --fail-with-body --cacert "$WORK/ca-server.pem" --cert "$PKI/e2e-client.pem" --key "$PKI/e2e-client.key" \
		-H 'X-Operator-Id: e2e' -H "Idempotency-Key: e2e-$(rand)" -H 'Content-Type: application/json' \
		-X "$method" "https://$GW:9448$path" ${body:+-d "$body"}
}

# ca_sign は CSR に署名させ、証明書（PEM）をファイルに書いてシリアル番号を出す。ca_sign <プロファイル> <テナント> <ap|edge>=<名前> <CSR> <出力>
ca_sign() {
	local profile=$1 tenant=$2 material=$3 csr=$4 out=$5
	local body
	body=$(python3 -c 'import json,sys; k,v=sys.argv[3].split("="); print(json.dumps({"profile":sys.argv[1],"tenant":sys.argv[2],k:v,"csr":open(sys.argv[4]).read()}))' \
		"$profile" "$tenant" "$material" "$csr")
	ca_api POST /certs "$body" >"$out.json"
	json "$out.json" 'd["certificate"]' >"$out"
	json "$out.json" 'd["serial"]'
}

# prov_api は本PoC の provisioning-api を呼ぶ。
prov_api() {
	local method=$1 path=$2 body=${3:-}
	curl -sS --fail-with-body --cacert "$POC/deployments/certs/provisioning/server.pem" \
		--cert "$PKI/prov-client.pem" --key "$PKI/prov-client.key" -H 'X-Operator-Id: e2e' -H 'Content-Type: application/json' \
		-X "$method" "https://127.0.0.1:9444/admin/v1$path" ${body:+-d "$body"}
}

# ap_key は AP の鍵と CSR を作る（AP が作る想定。CA は公開鍵だけを使う）。ap_key <名前>
ap_key() {
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$PKI/$1.key" -out "$PKI/$1.csr" -subj "/CN=$1" 2>/dev/null
}

# ap_start は AP の役のコンテナを（作り直して）起動する。ap_start <名前> <証明書の接頭辞> <公開する UDP のポートの最初>
ap_start() {
	local name=$1 cert=$2 port=$3 dir=$WORK/ap-$1
	mkdir -p "$dir"
	cp "$PKI/server-ca.pem" "$dir/server-ca.pem"
	cp "$PKI/$cert.pem" "$dir/ap.pem"
	cp "$PKI/$cert.key" "$dir/ap.key"
	sed -e "s/@@HOST@@/primary.$TENANT.$DOMAIN/" -e "s/@@PORT@@/$PORT/" -e "s/@@SECRET@@/$AP_SECRET/" \
		"$ROOT/scripts/e2e/ap/radsecproxy.conf.tmpl" >"$dir/radsecproxy.conf"
	chmod -R a+rX "$dir"
	docker rm -f "e2e-ap-$name" >/dev/null 2>&1 || true
	# AP は DNS のスロットの名前でエッジにつなぐ（サーバー証明書の SAN と照合する）。名前はテナントのネットワークの
	# ゲートウェイ（テナントのポートを公開しているアドレス）に向ける。
	docker run -d --name "e2e-ap-$name" --network e2e-ap --init --read-only \
		--add-host "primary.$TENANT.$DOMAIN:$GW" -p "127.0.0.1:$port:1812/udp" -p "127.0.0.1:$((port + 1)):1813/udp" \
		-v "$dir:/conf:ro" radsec-edge-e2e-ap >/dev/null
	sleep 3
}

# auth は eapaka_test で 1 回認証し、Accept なら 0 を返す。auth <名前> <AP の役の UDP のポート>
auth() {
	local name=$1 port=$2
	local cfg=$CASES/config-$name.yaml case=$CASES/case-accept.yaml
	cat >"$cfg" <<EOF
radius:
  server_addr: "127.0.0.1:$port"
  secret: "$AP_SECRET"
  timeout_ms: 3000
  retries: 2
radius_attrs:
  nas_ip_address: "192.0.2.10"
  nas_identifier: "$NAS_SPOOF"
  called_station_id: "aa-bb-cc-dd-ee-ff:$SSID"
  calling_station_id: "00-11-22-33-44-55"
eap:
  method_mismatch_policy: "strict"
  outer_identity_update_on_permanent_req: true
  permanent_id_policy: "always"
  aka_prime:
    net_name: "WLAN"
identity:
  realm: "wlan.mnc010.mcc440.3gppnetwork.org"
sim:
  imsi: "$IMSI"
  ki: "$KI"
  opc: "$OPC"
  amf: "8000"
  sqn_initial_hex: "000000000000"
sqn_store:
  mode: "file"
  path: "$CASES/sqn-$IMSI.json"
EOF
	cat >"$case" <<EOF
version: 1
name: accept
identity: "0$IMSI@wlan.mnc010.mcc440.3gppnetwork.org"
expect:
  result: accept
  mppe:
    require_present: true
EOF
	"$BIN/eapaka_test" -c "$cfg" run "$case" >"$LOGS/eapaka_test-$name-$(date +%s%N).log" 2>&1
}

expect_accept() {
	auth "$2" "$3" || fail "$1: 認証が Accept にならない（$LOGS の eapaka_test のログ）"
	pass "$1"
}

expect_no_accept() {
	if auth "$2" "$3"; then
		fail "$1: 認証が Accept になった"
	fi
	pass "$1"
}

# wait_for はコマンドが成功するのを最大 $2 秒待つ。wait_for <説明> <秒> <コマンド...>
wait_for() {
	local what=$1 secs=$2
	shift 2
	for _ in $(seq "$secs"); do
		"$@" >/dev/null 2>&1 && return 0
		sleep 1
	done
	fail "$what"
}

collect_logs() {
	set +e
	edge_compose logs --no-color >"$LOGS/radsec-edge.log" 2>&1
	docker logs "radsecproxy-$TENANT" >"$LOGS/radsecproxy-$TENANT.log" 2>&1
	for c in e2e-ap-a e2e-ap-b; do docker logs "$c" >"$LOGS/$c.log" 2>&1; done
	ca_compose logs --no-color >"$LOGS/radsec-ca.log" 2>&1
	poc_compose logs --no-color >"$LOGS/eapaka-radius-server-poc.log" 2>&1
	set -e
}

cleanup() {
	local rc=$?
	collect_logs
	if [[ ${KEEP:-0} == 1 ]]; then
		echo "KEEP=1 のため片付けない（作業ディレクトリ $WORK）"
		return
	fi
	set +e
	docker rm -f e2e-ap-a e2e-ap-b >/dev/null 2>&1
	# テナントのコンテナは agent が作ったもので、compose の管理の外にある。
	docker ps -aq --filter label=radsec-edge.tenant | xargs -r docker rm -f >/dev/null 2>&1
	edge_compose --profile build down -v --remove-orphans >/dev/null 2>&1
	ca_compose down -v --remove-orphans >/dev/null 2>&1
	poc_compose down -v --remove-orphans >/dev/null 2>&1
	docker network rm e2e-ap radsec-edge-tenants >/dev/null 2>&1
	# ログ以外を消す（コンテナの利用者が書いたファイルがある）
	find "$WORK" -mindepth 1 -maxdepth 1 ! -name logs -exec sudo rm -rf {} +
	echo "片付けた（ログは $LOGS に残した）"
	return $rc
}
trap cleanup EXIT

step "ソースの取得（scripts/e2e-versions.env）"
fetch eapaka-radius-server-poc "$POC_REF" "$POC"
fetch radsec-ca "$RADSEC_CA_REF" "$CA"
fetch eapaka_test "$EAPAKA_TEST_REF" "$EAPAKA_TEST"
echo "radsec-edge: $(git -C "$ROOT" log -1 --format='%h %s')$(git -C "$ROOT" diff --quiet || echo '（作業ツリーに変更あり）')"

step "試験の道具（eapaka_test、AP の役のイメージ）"
# ホストに Go がなくても動くよう、コンテナでビルドする。
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
	-v "$EAPAKA_TEST:/src" -w /src golang:1.27.2 go build -o /src/eapaka_test.bin ./cmd/eapaka_test
mv "$EAPAKA_TEST/eapaka_test.bin" "$BIN/eapaka_test"
docker build -q -t radsec-edge-e2e-ap "$ROOT/scripts/e2e/ap" >/dev/null
pass "eapaka_test と AP の役のイメージ"

step "ネットワーク"
docker network create --subnet "$SUBNET" radsec-edge-tenants >/dev/null
docker network create e2e-ap >/dev/null
pass "radsec-edge-tenants（$SUBNET、ゲートウェイ $GW）と e2e-ap"

step "本PoC: 起動（provisioning-api を含む）"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$PKI/prov-client.key" -out "$PKI/prov-client.pem" \
	-days 1 -subj /CN=e2e 2>/dev/null
cd "$POC/deployments"
cp .env.example .env
setenv .env VALKEY_PASSWORD "$(rand)"
setenv .env PROVISIONING_API_ADMIN_CLIENTS "e2e=$(fingerprint "$PKI/prov-client.pem")"
setenv .env PROVISIONING_API_NODE_NAME e2e
setenv .env COMPOSE_PROFILES provisioning
setenv .env COMPOSE_FILE docker-compose.yml:docker-compose.override.yml
# RADIUS のポートは、テナントのネットワークのゲートウェイの IP だけに公開する（エッジのテナントのコンテナから届く）。
cat >docker-compose.override.yml <<EOF
services:
  auth-server:
    ports: !override
      - "$GW:1812:1812/udp"
  acct-server:
    ports: !override
      - "$GW:1813:1813/udp"
EOF
mkdir -p certs/provisioning
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout certs/provisioning/server.key \
	-out certs/provisioning/server.pem -days 30 -subj "/CN=provisioning-api" \
	-addext "subjectAltName=DNS:provisioning-api,DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 600 certs/provisioning/server.key
docker compose up -d --build --quiet-pull --wait --wait-timeout 600
POC_GW=$(docker network inspect deployments_default -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
pass "本PoC が起動（本PoC のネットワークのゲートウェイ $POC_GW）"

step "radsec-ca: 起動"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$PKI/e2e-client.key" -out "$PKI/e2e-client.pem" \
	-days 1 -subj /CN=e2e 2>/dev/null
cd "$CA"
cp .env.example .env
setenv .env CA_ORG "E2E Org"
setenv .env CA_URN_PREFIX "$URN_PREFIX"
setenv .env CA_DNS_DOMAIN "$DOMAIN"
setenv .env CA_BIND_ADDR "$GW"
setenv .env CA_ADMIN_CLIENTS "e2e=$(fingerprint "$PKI/e2e-client.pem")"
setenv .env CA_TLS_HOSTS "$GW"
setenv .env CA_ACCESS_TEAM_DOMAIN unused.cloudflareaccess.com
setenv .env CA_ACCESS_AUD unused
setenv .env CA_INITIAL_ADMIN_EMAIL e2e@example.com
setenv .env CA_VERSION e2e
mkdir -p secrets
openssl rand -hex 32 >secrets/kek
sudo chown 65532 secrets/kek
sudo chmod 600 secrets/kek
# 画面は開発用の設定でループバックだけ（E2E は管理API で操作する）。cloudflared は動かさない。
cat >"$WORK/ca-override.yaml" <<EOF
services:
  radsec-ca:
    environment:
      CA_GUI_ADDR: "127.0.0.1:8448"
      CA_DEV_USER_EMAIL: e2e@example.com
      CA_ACCESS_TEAM_DOMAIN: ""
      CA_ACCESS_AUD: ""
  cloudflared:
    profiles: ["off"]
EOF
ca_compose up -d --build --quiet-pull --wait --wait-timeout 600
ca_compose exec -T radsec-ca /radsec-ca server-cert >"$WORK/ca-server.pem" 2>/dev/null </dev/null
ca_api GET /status >"$WORK/ca-status.json"
[[ $(json "$WORK/ca-status.json" 'd["service"]') == radsec-ca ]] || fail "radsec-ca の /status"
pass "radsec-ca が起動（KEK $(json "$WORK/ca-status.json" 'd["kekId"]')）"

step "エッジ: 起動"
EDGE_HOST=$WORK/edge-host
mkdir -p "$EDGE_HOST/data" "$EDGE_HOST/tenants"
sudo chown 10084:10083 "$EDGE_HOST/data" "$EDGE_HOST/tenants"
sudo chmod 0750 "$EDGE_HOST/data" "$EDGE_HOST/tenants"
UP_SECRET=$(rand)
cat >"$WORK/edge.env" <<EOF
EDGE_HOST_DIR=$EDGE_HOST
EDGE_DOCKER_GID=$(stat -c %g /var/run/docker.sock)
EDGE_AGENT_PUBLISH_ADDR=$GW
EDGE_URN_PREFIX=$URN_PREFIX
EDGE_DNS_DOMAIN=$DOMAIN
EDGE_UPSTREAM_AUTH=$GW:1812
EDGE_UPSTREAM_ACCT=$GW:1813
EDGE_UPSTREAM_SECRET=$UP_SECRET
EDGE_CRL_BASE_URL=http://$GW:8449
EDGE_RECONCILE_INTERVAL=10s
EDGE_ACCESS_TEAM_DOMAIN=unused.cloudflareaccess.com
EDGE_ACCESS_AUD=unused
EDGE_VERSION=e2e
EOF
# 画面は開発用の設定でループバックだけ。テナントのネットワークは先に作ったもの（固定のサブネット）を使う。
cat >"$WORK/edge-override.yaml" <<EOF
services:
  radsec-edge:
    environment:
      EDGE_GUI_ADDR: "127.0.0.1:8447"
      EDGE_DEV_USER_EMAIL: e2e@example.com
      EDGE_ACCESS_TEAM_DOMAIN: ""
      EDGE_ACCESS_AUD: ""
  cloudflared:
    profiles: ["off"]
networks:
  tenants:
    name: radsec-edge-tenants
    external: true
EOF
edge_compose --profile build build -q
edge_compose up -d --wait --wait-timeout 300
pass "エッジが起動"

step "本PoC: RADIUSクライアント（エッジ）、加入者、認可ポリシー"
prov_api POST /clients "{\"ip\":\"$POC_GW\",\"secret\":\"$UP_SECRET\",\"name\":\"$EDGE_NAME\"}" >/dev/null
prov_api POST /subscribers "{\"imsi\":\"$IMSI\",\"ki\":\"$KI\",\"opc\":\"$OPC\"}" >/dev/null
# エッジが置き換えた NAS-Identifier だけを許す（eapaka_test が名乗る値では通らない）。
prov_api PUT "/policies/$IMSI" "{\"default\":\"deny\",\"rules\":[{\"nasId\":\"$NAS_ID\",\"allowedSsids\":[\"$SSID\"]}]}" >/dev/null
pass "RADIUSクライアント $POC_GW、加入者 $IMSI（認可ポリシーは NAS-Identifier $NAS_ID だけ）"

step "radsec-ca: テナントのクライアントCA"
for t in "$TENANT" tenant-b tenant-x; do
	ca_api POST /cas "{\"tenant\":\"$t\"}" >"$WORK/ca-$t.json"
	json "$WORK/ca-$t.json" 'd["certificate"]' >"$PKI/ca-$t.pem"
done
ca_api GET /cas/server >"$WORK/ca-server-ca.json"
json "$WORK/ca-server-ca.json" 'd["certificate"]' >"$PKI/server-ca.pem"
pass "tenant.$TENANT（試験の本体）、tenant.tenant-b（テナントをまたぐ試験）、tenant.tenant-x（戻しの試験）"

step "エッジ: テナントの作成と証明書・CRL の取り込み（画面の口）"
edge POST /tenants -d "slug=$TENANT" -d "port=$PORT" -d "auth=$GW:1812" -d "acct=$GW:1813" >/dev/null
edge_pem "/tenants/$TENANT/client-ca" "$PKI/ca-$TENANT.pem" >"$WORK/r.html"
expect_html "クライアントCA の取り込み" "$WORK/r.html" "CRL も取得しました"
for kind in server probe; do
	edge POST "/tenants/$TENANT/csr/$kind" >"$WORK/r.html"
	python3 -c 'import html,re,sys; print(html.unescape(re.search(r"-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----", open(sys.argv[1]).read(), re.S).group(0)))' \
		"$WORK/r.html" >"$PKI/$kind.csr"
done
ca_sign tenant-server "$TENANT" "edge=$EDGE_NAME" "$PKI/server.csr" "$PKI/edge-server.pem" >/dev/null
PROBE_SERIAL=$(ca_sign probe-client "$TENANT" "edge=$EDGE_NAME" "$PKI/probe.csr" "$PKI/edge-probe.pem")
edge_pem "/tenants/$TENANT/cert/server" "$PKI/edge-server.pem" >"$WORK/r.html"
expect_html "サーバー証明書の取り込み" "$WORK/r.html" "サーバー証明書を取り込みました"
edge_pem "/tenants/$TENANT/cert/probe" "$PKI/edge-probe.pem" >"$WORK/r.html"
expect_html "ヘルスチェック用の証明書の取り込み" "$WORK/r.html" "ヘルスチェック用の証明書を取り込みました"
pass "テナント $TENANT（ポート $PORT）、クライアントCA、CRL、サーバー証明書、ヘルスチェック用の証明書"

step "AP の証明書と登録、反映"
ap_key ap-a
AP_SERIAL=$(ca_sign ap-client "$TENANT" ap=ap-001 "$PKI/ap-a.csr" "$PKI/ap-a.pem")
edge POST "/tenants/$TENANT/aps" -d name=ap-001 --data-urlencode "pem@-" <"$PKI/ap-a.pem" >"$WORK/r.html"
expect_html "AP の登録" "$WORK/r.html" "$NAS_ID"
edge POST "/tenants/$TENANT/apply" >"$WORK/r.html"
expect_html "反映" "$WORK/r.html" "反映しました"
pass "AP ap-001（証明書 $AP_SERIAL）、反映（構文検査・作成・ヘルスチェック）"

step "認証: eapaka_test → AP の役 → エッジ → 本PoC"
ap_start a ap-a 11812
expect_accept "AP の証明書で RadSec でつなぎ、認証が通る（認可ポリシーは置き換えた NAS-Identifier $NAS_ID だけを許す）" a 11812
# 認可ポリシーは置き換えた後の値だけを許すので、Accept になったことが置き換えの確かめになる。ログでも見る。
if poc_compose logs --no-color auth-server 2>/dev/null | grep -qF "$NAS_SPOOF"; then
	fail "auth-server のログに、置き換える前の NAS-Identifier $NAS_SPOOF がある"
fi
pass "本PoC に名乗った NAS-Identifier $NAS_SPOOF は届かない"

step "Accounting-On"
# radsecproxy は User-Name のない Accounting-Request を上流に送らず、自分で応答する。本物の AP は RadSec でエッジに直接送り、
# エッジが User-Name を補う（設計概要 §10.3 の supplementAttribute 1）が、この試験の AP の役も radsecproxy なので、
# AP の役を通すために User-Name を入れて送る（エッジが補う動きは、この試験では確かめない）。
docker exec e2e-ap-a sh -c "printf 'Acct-Status-Type = Accounting-On\nUser-Name = \"e2e-acct-on\"\nNAS-Identifier = \"$NAS_SPOOF\"\nNAS-IP-Address = 192.0.2.10\n' | radclient -x 127.0.0.1:1813 acct $AP_SECRET" >"$LOGS/radclient-acct-on.log" 2>&1 ||
	fail "radclient の Accounting-On（$LOGS/radclient-acct-on.log）"
acct_on() { poc_compose logs --no-color acct-server 2>/dev/null | grep '"accounting on"' | grep -qF "\"nas_identifier\":\"$NAS_ID\""; }
wait_for "acct-server に Accounting-On（NAS-Identifier $NAS_ID）が届かない" 30 acct_on
pass "Accounting-On が NAS-Identifier $NAS_ID で届く"

step "AP の最後の接続（画面）"
seen_up() { edge GET "/tenants/$TENANT" | grep -qF "接続中"; }
wait_for "画面の AP の一覧が「接続中」にならない" 40 seen_up
pass "画面の AP の一覧に「接続中」"

step "テナントをまたぐ証明書は通らない"
ap_key ap-b
ca_sign ap-client tenant-b ap=ap-001 "$PKI/ap-b.csr" "$PKI/ap-b.pem" >/dev/null
ap_start b ap-b 11822
expect_no_accept "テナント B の CA が発行した証明書では、テナント A のポートで認証できない" b 11822
docker logs "radsecproxy-$TENANT" 2>&1 | grep -q "unable to get local issuer certificate" || fail "エッジの radsecproxy に証明書の拒否の行がない"
pass "エッジの radsecproxy が unable to get local issuer certificate で拒否"

step "失効: CA で失効 → エッジが CRL を取り直して SIGHUP → 拒否"
ca_api POST "/certs/$AP_SERIAL/revoke" '{"reason":"keyCompromise"}' >/dev/null
edge POST "/tenants/$TENANT/crl/refresh" >"$WORK/r.html"
expect_html "CRL の取り直し" "$WORK/r.html" "CRL を取りに行きました"
sleep 2
expect_no_accept "失効させた証明書の AP は認証できない" a 11812
seen_reject() { edge GET "/tenants/$TENANT" | grep -qF "証明書の拒否"; }
wait_for "画面の AP の一覧に「証明書の拒否」が出ない" 40 seen_reject
pass "画面の AP の一覧に「証明書の拒否」"

step "証明書の更新: 同じ名前で発行し直すと、エッジの設定を変えずにつながる"
ap_key ap-a2
AP2_SERIAL=$(ca_sign ap-client "$TENANT" ap=ap-001 "$PKI/ap-a2.csr" "$PKI/ap-a2.pem")
ap_start a ap-a2 11812
expect_accept "新しい証明書の AP は認証できる" a 11812

step "反映の前の確認: クライアントCA を差し替えて、ヘルスチェック用の証明書を出し直さないままの反映は断る"
edge POST "/tenants/$TENANT/update" -d "port=$PORT" -d "auth=$GW:1812" -d "acct=$GW:1813" \
	-d "crl_url=http://$GW:8449/crl/tenant.tenant-x.pem" >/dev/null
edge_pem "/tenants/$TENANT/client-ca" "$PKI/ca-tenant-x.pem" >"$WORK/r.html"
expect_html "別の CA の取り込み" "$WORK/r.html" "CRL も取得しました"
# 反映は断られる（422）ので、curl の誤りは無視して本文を見る。
edge POST "/tenants/$TENANT/apply" >"$WORK/r.html" || true
expect_html "反映を断る" "$WORK/r.html" "今のクライアントCA で検証できません"
# radsecproxy には何もしていないので、AP の接続は切れていない。
expect_accept "反映を断ったので、AP はそのまま認証できる" a 11812
edge POST "/tenants/$TENANT/update" -d "port=$PORT" -d "auth=$GW:1812" -d "acct=$GW:1813" -d "crl_url=" >/dev/null
edge_pem "/tenants/$TENANT/client-ca" "$PKI/ca-$TENANT.pem" >"$WORK/r.html"
expect_html "CA を戻す" "$WORK/r.html" "CRL も取得しました"
edge POST "/tenants/$TENANT/apply" >"$WORK/r.html"
expect_html "反映（正しい CA）" "$WORK/r.html" "反映しました"
expect_accept "正しい CA に戻して反映した後も、AP は認証できる" a 11812

step "ヘルスチェック用の証明書の失効: CRL は戻さずに置き、その後の AP の失効も効く"
ca_api POST "/certs/$PROBE_SERIAL/revoke" '{"reason":"keyCompromise"}' >/dev/null
edge POST "/tenants/$TENANT/crl/refresh" >"$WORK/r.html"
expect_html "CRL の取り直し（probe の失効）" "$WORK/r.html" "ヘルスチェック用の証明書が失効しています"
expect_accept "ヘルスチェック用の証明書を失効させても、AP は認証できる" a 11812
ca_api POST "/certs/$AP2_SERIAL/revoke" '{"reason":"keyCompromise"}' >/dev/null
edge POST "/tenants/$TENANT/crl/refresh" >/dev/null
sleep 2
expect_no_accept "ヘルスチェック用の証明書が失効していても、AP の失効は効く" a 11812
edge POST "/tenants/$TENANT/apply" >"$WORK/r.html" || true
expect_html "失効した probe での反映を断る" "$WORK/r.html" "ヘルスチェック用の証明書が失効しています"
edge POST "/tenants/$TENANT/csr/probe" >"$WORK/r.html"
python3 -c 'import html,re,sys; print(html.unescape(re.search(r"-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----", open(sys.argv[1]).read(), re.S).group(0)))' \
	"$WORK/r.html" >"$PKI/probe2.csr"
ca_sign probe-client "$TENANT" "edge=$EDGE_NAME" "$PKI/probe2.csr" "$PKI/edge-probe2.pem" >/dev/null
edge_pem "/tenants/$TENANT/cert/probe" "$PKI/edge-probe2.pem" >/dev/null
edge POST "/tenants/$TENANT/apply" >"$WORK/r.html"
expect_html "probe を出し直して反映" "$WORK/r.html" "反映しました"
ap_key ap-a3
ca_sign ap-client "$TENANT" ap=ap-001 "$PKI/ap-a3.csr" "$PKI/ap-a3.pem" >/dev/null
ap_start a ap-a3 11812
expect_accept "ヘルスチェック用の証明書を出し直した後、新しい証明書の AP は認証できる" a 11812

step "すべて成功"
