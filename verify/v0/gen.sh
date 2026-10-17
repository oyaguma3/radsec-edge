#!/usr/bin/env bash
# 段階 0 の実機の検証（設計概要 §18）の PKI と radsecproxy の設定を作る。simwifi の ~/aka-work/radsec-v0 で動かす。
set -euo pipefail
cd "$(dirname "$0")"
CG=./bin/certgen
URN=urn:example:nas
DOMAIN=radsec.test

rm -rf pki conf
mkdir -p pki conf

# ---- PKI ----
$CG ca -cn "RadSec server CA (verify)" -out pki/server-ca
for t in tenant-a tenant-b tenant-c; do
  $CG ca -cn "$t client CA (verify)" -out "pki/$t-ca"
  $CG crl -ca "pki/$t-ca" -number 1 -out "pki/$t.crl"
done
# テナントのサーバー証明書（テナントとエッジの組ごと。設計概要 §9.2）
# SAN_MODE=wildcard なら *.<テナント>.<ドメイン>、それ以外は primary / secondary / tertiary の 3 つの名前を明示する
srv() {
  local dns="primary.$1.$DOMAIN,secondary.$1.$DOMAIN,tertiary.$1.$DOMAIN"
  [ "${SAN_MODE:-}" = wildcard ] && dns="*.$1.$DOMAIN"
  $CG leaf -ca pki/server-ca -cn "$1 server $2" -dns "$dns" -usage server -out "pki/$1-$2-server" >/dev/null
}
srv tenant-a edge-a1
srv tenant-a edge-a2
srv tenant-b edge-b1
srv tenant-c edge-c1
# AP の証明書（CN = NAS-Identifier、SAN の URI。設計概要 §8.1）
ap() { $CG leaf -ca "pki/$1-ca" -cn "$1-$2" -uri "$URN:$1:$2" -usage client -days 730 -out "pki/$1-$2" >"pki/$1-$2.serial"; }
ap tenant-a ap-001
ap tenant-a ap-002
ap tenant-b ap-001

# ---- エッジ側の radsecproxy の設定（設計概要 §10.3 のひな形） ----
# edge_conf <コンテナ> <テナント> <AP の名前...>
edge_conf() {
  local c=$1 t=$2; shift 2
  local d=conf/$c
  mkdir -p "$d"
  cp "pki/$t-$c-server.pem" "$d/server.pem"
  cp "pki/$t-$c-server.key" "$d/server.key"
  # CA の証明書と CRL を 1 つのファイルに入れる（CACertificateFile は CRL も含められる）
  cat "pki/$t-ca.pem" "pki/$t.crl" >"$d/ca-bundle.pem"
  {
    cat <<EOF
# $c（テナント $t）
ListenTLS *:2083
LogLevel 3

tls tenant {
    CACertificateFile  /conf/ca-bundle.pem
    CertificateFile    /conf/server.pem
    CertificateKeyFile /conf/server.key
    CRLCheck on
    TlsVersion TLS1_2:TLS1_3
}

EOF
    local a nasid
    for a in "$@"; do
      nasid="$t-$a"
      cat <<EOF
rewrite nasid-$nasid {
    removeAttribute 32
    addAttribute 32:'$nasid
    supplementAttribute 1:'$nasid
}
client $nasid {
    type tls
    host 0.0.0.0/0
    tls tenant
    certificateNameCheck off
    matchCertificateAttribute CN:/^$nasid\$/
    matchCertificateAttribute SubjectAltName:URI:/^$URN:$t:$a\$/
    rewriteIn nasid-$nasid
}

EOF
    done
    cat <<EOF
server upstream-auth {
    type udp
    host upstream
    port 1812
    secret upsecret
    statusServer on
}
server upstream-acct {
    type udp
    host upstream
    port 1813
    secret upsecret
    statusServer on
}

realm * {
    server upstream-auth
    accountingServer upstream-acct
}
EOF
  } >"$d/radsecproxy.conf"
}

# ---- AP の役の radsecproxy の設定 ----
# ap_conf <コンテナ> <証明書の接頭辞> <サーバーのホスト名...>（先頭が primary）
ap_conf() {
  local c=$1 cert=$2; shift 2
  local d=conf/$c
  mkdir -p "$d"
  cp pki/server-ca.pem "$d/server-ca.pem"
  cp "pki/$cert.pem" "$d/ap.pem"
  cp "pki/$cert.key" "$d/ap.key"
  {
    cat <<EOF
# $c（AP の役。証明書 $cert）
ListenUDP *:1812
ListenUDP *:1813
LogLevel 4

tls ap {
    CACertificateFile  /conf/server-ca.pem
    CertificateFile    /conf/ap.pem
    CertificateKeyFile /conf/ap.key
    TlsVersion TLS1_2:TLS1_3
}

client local {
    type udp
    host 127.0.0.1
    secret testing123
}

EOF
    local h i=0 names=()
    for h in "$@"; do
      i=$((i + 1))
      names+=("s$i")
      cat <<EOF
server s$i {
    type tls
    host $h
    port 2083
    tls ap
    statusServer on
}

EOF
    done
    echo "realm * {"
    for h in "${names[@]}"; do echo "    server $h"; done
    for h in "${names[@]}"; do echo "    accountingServer $h"; done
    echo "}"
  } >"$d/radsecproxy.conf"
}

edge_conf edge-a1 tenant-a ap-001 ap-002
edge_conf edge-a2 tenant-a ap-001 ap-002
edge_conf edge-b1 tenant-b ap-001
# 容量の測定（V10）: AP を 500 台分登録したテナント（証明書は作らない）
edge_conf edge-c1 tenant-c $(seq -f 'ap-%03g' 1 500)

ap_conf ap-a tenant-a-ap-001 primary.tenant-a.$DOMAIN secondary.tenant-a.$DOMAIN
ap_conf ap-r tenant-a-ap-002 primary.tenant-a.$DOMAIN secondary.tenant-a.$DOMAIN
ap_conf ap-b tenant-b-ap-001 primary.tenant-b.$DOMAIN
# テナントをまたぐ試験: テナント A の AP の証明書で、テナント B のエッジにつなぐ
ap_conf ap-x tenant-a-ap-001 primary.tenant-b.$DOMAIN

chmod -R a+rX pki conf
echo "gen.sh: 完了"
