#!/bin/bash
# 運用ガイド（docs/operations.md）の管理モードの手順を、compose で実際に流して確かめる（CI のジョブと手元の確かめ）。
#
# 確かめること: 導入（ホストのディレクトリ・ピン・Fluent Bit）、mTLS、公開するポート、ピンの入れ替えと SIGHUP、サーバー証明書の作り直しと SIGHUP、
# 宣言から反映まで（CSR と証明書、CRL の取得）、AP の接続、ログ（docker logs と Fluent Bit のファイル）、監査ログのファイル、バックアップと戻し、削除。
#
# 手元で動かすときは sudo がなくてもよい（UID 10084 で読み書きできるよう、試験の間だけ権限を広げる）。
# compose のプロジェクト名を変えるので、ほかの compose とはぶつからない（テナントのネットワーク radsec-edge-tenants の名前だけは固定）。
set -euo pipefail

cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME=edge-guide-check
export COMPOSE_FILE=compose.yaml:compose.managed.yaml:compose.fluent-bit.yaml
WORK=$(mktemp -d)
HOSTDIR=$PWD/.guide-host
FLUENT_PORT=24325
RS_IMAGE=radsec-edge/radsecproxy:1.11.4-pc1
BIND=127.0.0.1

fail() {
	echo "FAIL: $*" >&2
	docker compose logs --no-color --tail 40 radsec-edge radsec-edge-agent >&2 || true
	exit 1
}
pass() { echo "ok: $*"; }

cleanup() {
	docker ps -aq --filter label=radsec-edge.tenant | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker rm -f edge-guide-crl >/dev/null 2>&1 || true
	docker compose down -v --remove-orphans >/dev/null 2>&1 || true
	# UID 10084 が作ったファイルはコンテナの中から消す。
	docker run --rm -v "$PWD:/w" busybox:1.37.0 rm -rf /w/.guide-host /w/secrets >/dev/null 2>&1 || true
	rm -rf .env "$WORK"
}
trap cleanup EXIT

[ ! -e .env ] && [ ! -e secrets ] && [ ! -e .guide-host ] || { echo "the working tree already has .env, secrets or .guide-host" >&2; exit 2; }

# UID 10084 に読み書きさせる。sudo があれば手順どおり chown し、なければ権限を広げる。
own() {
	if sudo -n true 2>/dev/null; then
		sudo chown -R 10084:10083 "$@"
	else
		chmod -R a+rwX "$@"
	fi
}

# put <ファイル> は標準入力をファイルにその場で書く（動いているコンテナが同じファイルを見続けるよう、置き換えない）。
put() {
	if sudo -n true 2>/dev/null; then
		sudo tee "$1" >/dev/null
	else
		cat >"$1"
	fi
}

# 運用ガイド 10.1・10.2
mkdir -p "$HOSTDIR/data" "$HOSTDIR/tenants" "$HOSTDIR/audit" "$HOSTDIR/logs" secrets
own "$HOSTDIR/data" "$HOSTDIR/tenants" "$HOSTDIR/audit"
: >secrets/tunnel-token
chmod 644 secrets/tunnel-token
cp .env.example .env
sed -i -e "s|^EDGE_HOST_DIR=.*|EDGE_HOST_DIR=$HOSTDIR|" -e "s|^EDGE_DOCKER_GID=.*|EDGE_DOCKER_GID=$(stat -c %g /var/run/docker.sock)|" \
	-e 's|^EDGE_UPSTREAM_SECRET=.*|EDGE_UPSTREAM_SECRET=guide-secret-123|' -e "s|^EDGE_AGENT_PUBLISH_ADDR=.*|EDGE_AGENT_PUBLISH_ADDR=$BIND|" \
	-e 's|^EDGE_ACCESS_TEAM_DOMAIN=.*|EDGE_ACCESS_TEAM_DOMAIN=guide.cloudflareaccess.com|' -e 's|^EDGE_ACCESS_AUD=.*|EDGE_ACCESS_AUD=guide-aud|' \
	-e 's|^EDGE_CRL_BASE_URL=.*|EDGE_CRL_BASE_URL=http://edge-guide-crl:8080|' .env
cat >>.env <<ENV
EDGE_BIND_ADDR=$BIND
EDGE_TLS_HOSTS=$BIND
EDGE_FLUENT_BIT_PORT=$FLUENT_PORT
ENV

client_cert() { # 管理クライアントの証明書を作り、フィンガープリントを出す
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/$1.key" -out "$WORK/$1.pem" -days 2 -subj "/CN=$1" 2>/dev/null
	openssl x509 -in "$WORK/$1.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f'
}
FP_OLD=$(client_cert old)
FP_NEW=$(client_cert new)
echo "provisioner=$FP_OLD" >secrets/admin-clients
own secrets/admin-clients
docker compose build radsec-edge >/dev/null
docker image inspect "$RS_IMAGE" >/dev/null 2>&1 || docker build -q -t "$RS_IMAGE" images/radsecproxy >/dev/null
docker compose up -d --wait radsec-edge radsec-edge-agent fluent-bit
pass "起動"

docker compose exec -T radsec-edge /radsec-edge server-cert >"$WORK/server.pem" 2>/dev/null
# api <証明書> <メソッド> <パス> [本文のファイル]
api() {
	local who=$1 method=$2 path=$3 body=${4:-}
	local args=(--silent --show-error --max-time 30 --cacert "$WORK/server.pem" --cert "$WORK/$who.pem" --key "$WORK/$who.key" -X "$method"
		-H "X-Operator-Id: guide" -w '\n%{http_code}')
	[ "$method" = GET ] || args+=(-H "Idempotency-Key: $(date +%s%N)")
	[ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data-binary "@$WORK/$body")
	curl "${args[@]}" "https://$BIND:9447$path"
}
code() { tail -n1 <<<"$1"; }
body() { sed '$d' <<<"$1"; }
jqv() { python3 -c 'import json,sys; v=json.load(sys.stdin); print(eval(sys.argv[1],{"v":v}))' "$1"; }

r=$(api old GET /status) && [ "$(code "$r")" = 200 ] || fail "/status: $r"
[ "$(body "$r" | jqv 'v["mode"]')" = managed ] || fail "/status のモード: $r"
[ "$(body "$r" | jqv 'v["capacity"]["max"]')" = 150 ] || fail "/status の容量: $r"
[ "$(body "$r" | jqv 'v["agent"]["dockerOk"]')" = True ] || fail "/status の agent: $r"
pass "mTLS で /status"
if api new GET /status >/dev/null 2>&1; then fail "登録していない証明書が通った"; fi
pass "登録していない証明書は断る"

# 管理API だけを公開する。画面は公開しない。
docker compose port radsec-edge 9447 | grep -q "^$BIND:" || fail "管理API が公開されていない"
if docker compose port radsec-edge 8447 2>/dev/null | grep -q .; then fail "画面が公開されている"; fi
pass "管理API だけをトンネルのアドレスに公開"

# 運用ガイド 10.3: ピンの入れ替え（ファイルをその場で書き換えて SIGHUP）。
printf 'provisioner=%s\nprovisioner=%s\n' "$FP_OLD" "$FP_NEW" | put secrets/admin-clients
docker compose kill -s SIGHUP radsec-edge >/dev/null
sleep 1
r=$(api new GET /status) && [ "$(code "$r")" = 200 ] || fail "新しい証明書: $r"
r=$(api old GET /status) && [ "$(code "$r")" = 200 ] || fail "入れ替えの間の古い証明書: $r"
echo "provisioner=$FP_NEW" | put secrets/admin-clients
docker compose kill -s SIGHUP radsec-edge >/dev/null
sleep 1
if api old GET /status >/dev/null 2>&1; then fail "古い証明書が残っている"; fi
docker compose logs --no-color radsec-edge | grep -q EDGE_ADMIN_CLIENTS_RELOADED || fail "読み直しのログがない"
pass "ピンの入れ替えと SIGHUP"

# 運用ガイド 10.4: サーバー証明書の作り直し。
docker compose exec -T radsec-edge /radsec-edge replace-server-cert >"$WORK/server-new.pem" 2>/dev/null
docker compose kill -s SIGHUP radsec-edge >/dev/null
sleep 1
cmp -s "$WORK/server.pem" "$WORK/server-new.pem" && fail "サーバー証明書が変わっていない"
if api new GET /status >/dev/null 2>&1; then fail "古いサーバー証明書で検証できた"; fi
cp "$WORK/server-new.pem" "$WORK/server.pem"
r=$(api new GET /status) && [ "$(code "$r")" = 200 ] || fail "新しいサーバー証明書: $r"
pass "サーバー証明書の作り直しと SIGHUP"

# 試験の CA（本番は radsec-ca が発行し、配布の口に CRL を置く）。
ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
ec "$WORK/ca.key"
openssl req -x509 -new -key "$WORK/ca.key" -subj "/CN=tenant-a client CA" -days 30 -out "$WORK/ca.pem" \
	-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
ec "$WORK/sca.key"
openssl req -x509 -new -key "$WORK/sca.key" -subj "/CN=server CA" -days 30 -out "$WORK/sca.pem" \
	-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
mkdir -p "$WORK/crlca" "$WORK/dist/crl"
: >"$WORK/crlca/index.txt"
echo 01 >"$WORK/crlca/crlnumber"
printf '[ca]\ndefault_ca=d\n[d]\ndatabase=%s\ncrlnumber=%s\ndefault_md=sha256\ndefault_crl_days=7\n' "$WORK/crlca/index.txt" "$WORK/crlca/crlnumber" >"$WORK/crlca/ca.cnf"
openssl ca -config "$WORK/crlca/ca.cnf" -gencrl -keyfile "$WORK/ca.key" -cert "$WORK/ca.pem" -out "$WORK/dist/crl/tenant.tenant-a.pem" 2>/dev/null
chmod -R a+rX "$WORK"
# 配布の口の代わり（radsec-edge が tenants のネットワークから取りに来る）。
docker run -d --name edge-guide-crl --network radsec-edge-tenants -v "$WORK/dist:/www:ro" busybox:1.37.0 httpd -f -p 8080 -h /www >/dev/null

python3 - "$WORK" <<'PY'
import json, sys
w = sys.argv[1]
json.dump({"revision": 3, "slug": "tenant-a", "port": 20993, "authUpstream": "10.255.0.1:1812", "acctUpstream": "10.255.0.1:1813",
           "clientCas": [{"id": "tenant.tenant-a", "kind": "issued", "certificate": open(w + "/ca.pem").read(), "hasCrl": True}],
           "aps": [{"name": "ap-001", "kind": "ap"}, {"name": "hq", "kind": "group", "purpose": "unifi"}]}, open(w + "/tenant.json", "w"))
PY
r=$(api new PUT /tenants/42 tenant.json) && [ "$(code "$r")" = 201 ] || fail "宣言: $r"
[ "$(body "$r" | jqv 'v["pending"]')" = True ] || fail "宣言の pending: $r"
r=$(api new POST /tenants/42/apply) && [ "$(code "$r")" = 422 ] || fail "証明書がないときの反映: $r"
body "$r" | grep -q NOT_READY || fail "証明書がないときの反映: $r"
pass "宣言"

# CSR に署名して証明書を置く（鍵はエッジの外に出ない）。
sign() { # sign <kind server|probe> <CA> <拡張>
	local kind=$1 ca=$2 ext=$3
	r=$(api new POST "/tenants/42/$kind-csr") && [ "$(code "$r")" = 200 ] || fail "$kind-csr: $r"
	body "$r" | jqv 'v["csr"]' >"$WORK/$kind.csr"
	openssl x509 -req -in "$WORK/$kind.csr" -CA "$WORK/$ca.pem" -CAkey "$WORK/$ca.key" -CAcreateserial -days 30 -out "$WORK/$kind-cert.pem" \
		-extfile <(printf '%s\n' "$ext") 2>/dev/null
	python3 -c 'import json,sys; json.dump({"certificate": open(sys.argv[1]).read()}, open(sys.argv[2], "w"))' "$WORK/$kind-cert.pem" "$WORK/$kind-cert.json"
	r=$(api new PUT "/tenants/42/$kind-cert" "$kind-cert.json") && [ "$(code "$r")" = 200 ] || fail "$kind-cert: $r"
}
DOMAIN=$(sed -n 's/^EDGE_DNS_DOMAIN=//p' .env)
URN=$(sed -n 's/^EDGE_URN_PREFIX=//p' .env)
sign server sca "subjectAltName=DNS:primary.tenant-a.$DOMAIN,DNS:secondary.tenant-a.$DOMAIN,DNS:tertiary.tenant-a.$DOMAIN
extendedKeyUsage=serverAuth"
sign probe ca "subjectAltName=URI:urn:$URN:nas:tenant-a:probe
extendedKeyUsage=clientAuth"

r=$(api new POST /tenants/42/apply) && [ "$(code "$r")" = 202 ] || fail "反映: $r"
for _ in $(seq 60); do
	r=$(api new GET /tenants/42)
	[ "$(body "$r" | jqv 'v["apply"]["state"]')" = idle ] && [ "$(body "$r" | jqv 'v["apply"].get("lastResult","")')" != "" ] && break
	sleep 2
done
[ "$(body "$r" | jqv 'v["apply"]["lastResult"]')" = ok ] || fail "反映の結果: $r"
[ "$(body "$r" | jqv 'v["appliedRevision"]')" = 3 ] || fail "反映済みの版: $r"
[ "$(body "$r" | jqv 'v["pending"]')" = False ] || fail "未反映のまま: $r"
pass "CSR・証明書・CRL の取得・反映"

# テナントのコンテナのログの設定（待ち行列を絞る。aka-mvpset の verify/edge-logs）。
[ "$(docker inspect -f '{{.HostConfig.LogConfig.Type}} {{index .HostConfig.LogConfig.Config "fluentd-buffer-limit"}} {{index .HostConfig.LogConfig.Config "tag"}}' radsecproxy-tenant-a)" = "fluentd 8192 tenant.42" ] ||
	fail "テナントのコンテナのログの設定"

# AP の接続。登録した AP は client ブロックに一致し、ログと last-seen に出る。
ec "$WORK/ap.key"
openssl req -new -key "$WORK/ap.key" -subj "/CN=tenant-a-ap-001" -out "$WORK/ap.csr" 2>/dev/null
openssl x509 -req -in "$WORK/ap.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial -days 30 -out "$WORK/ap.pem" \
	-extfile <(printf 'subjectAltName=URI:urn:%s:nas:tenant-a:ap-001\nextendedKeyUsage=clientAuth\n' "$URN") 2>/dev/null
(sleep 1) | timeout 5 openssl s_client -connect "$BIND:20993" -cert "$WORK/ap.pem" -key "$WORK/ap.key" -CAfile "$WORK/sca.pem" >/dev/null 2>&1 || true
for _ in $(seq 20); do
	r=$(api new GET "/tenants/42/logs?lines=50")
	grep -q 'client tenant-a-ap-001,' <<<"$(body "$r")" && break
	sleep 1
done
grep -q 'client tenant-a-ap-001,' <<<"$(body "$r")" || fail "AP の接続がログにない: $r"
pass "AP の接続（docker logs は dual logging のキャッシュで読める）"
r=$(api new GET /tenants/42/last-seen) && [ "$(code "$r")" = 200 ] || fail "last-seen: $r"

# 運用ガイド 10.5: Fluent Bit のファイル（root が作るのでコンテナの中から読む）。
LOGS=$HOSTDIR/logs
for _ in $(seq 20); do
	docker run --rm -v "$LOGS:/l:ro" busybox:1.37.0 grep -q 'client tenant-a-ap-001,' /l/radsecproxy.log 2>/dev/null && break
	sleep 1
done
docker run --rm -v "$LOGS:/l:ro" busybox:1.37.0 grep -q 'client tenant-a-ap-001,' /l/radsecproxy.log || fail "Fluent Bit のファイルにテナントのログがない"
docker run --rm -v "$LOGS:/l:ro" busybox:1.37.0 grep -q 'radsecproxy-tenant-a' /l/radsecproxy.log || fail "Fluent Bit のファイルにコンテナの名前がない"
docker run --rm -v "$LOGS:/l:ro" busybox:1.37.0 grep -q '"msg":"management API"' /l/radsec-edge.log || fail "Fluent Bit のファイルに radsec-edge のログがない"
pass "Fluent Bit のファイル"

# 運用ガイド 7 章と 10: 監査ログのファイル。
AUDIT=$(docker run --rm -v "$HOSTDIR/audit:/a:ro" busybox:1.37.0 sh -c 'cat /a/audit-*.jsonl')
for action in tenant.declare server.csr probe_cert.import tenant.apply server-cert.replace; do
	grep -q "\"action\":\"$action\"" <<<"$AUDIT" || fail "監査ログのファイルに $action がない: $AUDIT"
done
grep -q '"mgmtClient":"provisioner"' <<<"$AUDIT" || fail "監査ログのファイルに管理クライアントがない"
pass "監査ログのファイル"

# 運用ガイド 7 章: バックアップと戻し（data を写す。tenants は反映で作り直せる）。
docker compose stop radsec-edge >/dev/null
docker run --rm -v "$HOSTDIR:/h" busybox:1.37.0 sh -c 'cp -a /h/data /h/data.bak'
docker compose up -d --wait radsec-edge
python3 - "$WORK" <<'PY'
import json, sys
w = sys.argv[1]
d = json.load(open(w + "/tenant.json"))
d["revision"] = 4
d["aps"].append({"name": "ap-002", "kind": "ap"})
json.dump(d, open(w + "/tenant2.json", "w"))
PY
r=$(api new PUT /tenants/42 tenant2.json) && [ "$(code "$r")" = 200 ] || fail "2 回目の宣言: $r"
[ "$(body "$r" | jqv 'len(v["aps"])')" = 3 ] || fail "2 回目の宣言の AP: $r"
docker compose stop radsec-edge >/dev/null
docker run --rm -v "$HOSTDIR:/h" busybox:1.37.0 sh -c 'rm -rf /h/data/* && cp -a /h/data.bak/. /h/data/ && rm -rf /h/data.bak'
docker compose up -d --wait radsec-edge
r=$(api new GET /tenants/42) && [ "$(code "$r")" = 200 ] || fail "戻した後: $r"
[ "$(body "$r" | jqv 'v["revision"]')" = 3 ] || fail "戻した後の版: $r"
pass "バックアップと戻し"

# テナントの削除（コンテナも消える）。
r=$(api new DELETE /tenants/42) && [ "$(code "$r")" = 204 ] || fail "削除: $r"
[ -z "$(docker ps -aq --filter label=radsec-edge.tenant)" ] || fail "テナントのコンテナが残っている"
pass "テナントの削除"

# 単独モードのデータでは管理モードを起動しない（EA4）は単体の試験で確かめる。
echo "すべて確かめました"
