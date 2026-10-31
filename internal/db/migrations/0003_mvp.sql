-- MVP セットのための変更（設計概要 §24.6）。時刻はすべて UNIX 時間のミリ秒（UTC）。
-- SQLite は CHECK を変えられず、親の行を消すと子の行も消える（ON DELETE CASCADE）ので、子の表を写してから作り直す。

CREATE TABLE aps_copy AS SELECT * FROM aps;
CREATE TABLE crls_copy AS SELECT * FROM crls;
CREATE TABLE ap_seen_copy AS SELECT * FROM ap_seen;
CREATE TABLE log_cursors_copy AS SELECT * FROM log_cursors;
DROP TABLE aps;
DROP TABLE crls;
DROP TABLE ap_seen;
DROP TABLE log_cursors;

-- テナント。ポートの範囲を 20000〜21999 に広げる。
-- source_cidrs は許す送信元のアドレスの範囲（カンマ区切り。空なら制限なし。§24.3）。
-- shared_match_attr と shared_match_pattern は共通のブロックの照合の形（空なら条件なし。§24.3）。
-- client_ca_pem は発行した CA（テナントに必ず 1 つ）。持ち込みの CA は tenant_brought_cas に置く。
CREATE TABLE tenants_new (
    id                   TEXT    PRIMARY KEY,
    slug                 TEXT    NOT NULL UNIQUE,
    port                 INTEGER NOT NULL UNIQUE CHECK (port BETWEEN 20000 AND 21999),
    auth_upstream        TEXT    NOT NULL,
    acct_upstream        TEXT    NOT NULL,
    crl_url              TEXT    NOT NULL DEFAULT '',
    client_ca_pem        TEXT    NOT NULL DEFAULT '',
    server_cert_pem      TEXT    NOT NULL DEFAULT '',
    probe_cert_pem       TEXT    NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    desired_version      INTEGER NOT NULL DEFAULT 1,
    applied_version      INTEGER NOT NULL DEFAULT 0,
    applied_hash         TEXT    NOT NULL DEFAULT '',
    applied_port         INTEGER NOT NULL DEFAULT 0,
    applied_at           INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    source_cidrs         TEXT    NOT NULL DEFAULT '',
    shared_match_attr    TEXT    NOT NULL DEFAULT '',
    shared_match_pattern TEXT    NOT NULL DEFAULT ''
) STRICT;
INSERT INTO tenants_new (id, slug, port, auth_upstream, acct_upstream, crl_url, client_ca_pem, server_cert_pem, probe_cert_pem, enabled,
        desired_version, applied_version, applied_hash, applied_port, applied_at, created_at, updated_at)
    SELECT id, slug, port, auth_upstream, acct_upstream, crl_url, client_ca_pem, server_cert_pem, probe_cert_pem, enabled,
        desired_version, applied_version, applied_hash, applied_port, applied_at, created_at, updated_at FROM tenants;
DROP TABLE tenants;
ALTER TABLE tenants_new RENAME TO tenants;

-- テナントの持ち込みの CA（§24.3）。ca_id は radsec-ca の ID（brought.<slug>.<名前>）。
-- has_crl が 0 の CA があると、そのテナントは CRLCheck off になる。自己署名かは証明書からエッジが判定する。
CREATE TABLE tenant_brought_cas (
    tenant_id  TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    ca_id      TEXT    NOT NULL,
    cert_pem   TEXT    NOT NULL,
    has_crl    INTEGER NOT NULL CHECK (has_crl IN (0, 1)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, ca_id)
) STRICT;

-- AP とグループ（§24.3）。kind は ap か group。purpose はグループの用途（表示だけ）。
-- name はテナントの中で種類をまたいで一意（グループと AP で CN が同じになるため）。
CREATE TABLE aps (
    tenant_id      TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name           TEXT    NOT NULL,
    nas_id         TEXT    NOT NULL UNIQUE,
    cert_serial    TEXT    NOT NULL DEFAULT '',
    cert_not_after INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    kind           TEXT    NOT NULL DEFAULT 'ap' CHECK (kind IN ('ap', 'group')),
    purpose        TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, name)
) STRICT;
INSERT INTO aps (tenant_id, name, nas_id, cert_serial, cert_not_after, created_at, updated_at)
    SELECT tenant_id, name, nas_id, cert_serial, cert_not_after, created_at, updated_at FROM aps_copy;

-- CRL はテナントと CA の組ごとに持つ（§24.6）。ca_id が空なら発行した CA の CRL。number は 10 進の文字列で、ないこともある。
CREATE TABLE crls (
    tenant_id       TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    ca_id           TEXT    NOT NULL DEFAULT '',
    pem             TEXT    NOT NULL DEFAULT '',
    number          TEXT    NOT NULL DEFAULT '',
    this_update     INTEGER NOT NULL DEFAULT 0,
    next_update     INTEGER NOT NULL DEFAULT 0,
    source          TEXT    NOT NULL DEFAULT '' CHECK (source IN ('', 'fetch', 'upload')),
    installed_at    INTEGER NOT NULL DEFAULT 0,
    etag            TEXT    NOT NULL DEFAULT '',
    last_attempt_at INTEGER NOT NULL DEFAULT 0,
    last_success_at INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, ca_id)
) STRICT;
INSERT INTO crls (tenant_id, pem, number, this_update, next_update, source, installed_at, etag, last_attempt_at, last_success_at, last_error)
    SELECT tenant_id, pem, number, this_update, next_update, source, installed_at, etag, last_attempt_at, last_success_at, last_error FROM crls_copy;

CREATE TABLE ap_seen (
    tenant_id   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    ap          TEXT    NOT NULL,
    connected   INTEGER NOT NULL DEFAULT 0 CHECK (connected IN (0, 1)),
    last_up     INTEGER NOT NULL DEFAULT 0,
    last_down   INTEGER NOT NULL DEFAULT 0,
    last_ip     TEXT    NOT NULL DEFAULT '',
    last_reject INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, ap)
) STRICT;
INSERT INTO ap_seen SELECT * FROM ap_seen_copy;

CREATE TABLE log_cursors (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    since     TEXT NOT NULL
) STRICT;
INSERT INTO log_cursors SELECT * FROM log_cursors_copy;

-- 共通のブロックの接続を、送信元の IP ごとに持つ（持ち込みの CA の AP は台帳にいないので、IP でしか見えない。§24.3）。
-- connections は今の接続の数。テナントごとに last_up の新しい 1,000 件まで残す。
CREATE TABLE shared_seen (
    tenant_id   TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    ip          TEXT    NOT NULL,
    connections INTEGER NOT NULL DEFAULT 0,
    last_up     INTEGER NOT NULL DEFAULT 0,
    last_down   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, ip)
) STRICT;

DROP TABLE aps_copy;
DROP TABLE crls_copy;
DROP TABLE ap_seen_copy;
DROP TABLE log_cursors_copy;
