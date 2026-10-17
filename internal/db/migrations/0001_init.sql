-- 初版のスキーマ（設計概要 §7.2）。時刻はすべて UNIX 時間のミリ秒（UTC）。
-- 鍵（テナントのサーバー証明書とヘルスチェック用の証明書の秘密鍵）は DB に入れず、ファイルに置く。

-- テナント（AP のグループ）。単独モードでは id は slug と同じ（§21.2 の 4）。
-- desired_version は望む状態の版（変更のたびに 1 増やす）、applied_version と applied_hash は反映済みの版と設定のハッシュ。
CREATE TABLE tenants (
    id              TEXT    PRIMARY KEY,
    slug            TEXT    NOT NULL UNIQUE,
    port            INTEGER NOT NULL UNIQUE CHECK (port BETWEEN 20830 AND 20999),
    auth_upstream   TEXT    NOT NULL,
    acct_upstream   TEXT    NOT NULL,
    crl_url         TEXT    NOT NULL DEFAULT '',
    client_ca_pem   TEXT    NOT NULL DEFAULT '',
    server_cert_pem TEXT    NOT NULL DEFAULT '',
    probe_cert_pem  TEXT    NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    desired_version INTEGER NOT NULL DEFAULT 1,
    applied_version INTEGER NOT NULL DEFAULT 0,
    applied_hash    TEXT    NOT NULL DEFAULT '',
    applied_at      INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;

-- AP。nas_id（<テナントの slug>-<AP の名前>）はエッジの中で一意（設計概要 §8.2）。
-- 証明書のシリアル番号と期限は表示用（照合は SAN の URI で行う）。
CREATE TABLE aps (
    tenant_id      TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name           TEXT    NOT NULL,
    nas_id         TEXT    NOT NULL UNIQUE,
    cert_serial    TEXT    NOT NULL DEFAULT '',
    cert_not_after INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, name)
) STRICT;

-- テナントの CRL（設計概要 §9.5）。pem は最後に置いた（検証を通った）CRL。number は 10 進の文字列（CRL の番号は大きな整数）。
-- etag と last_* は取得の状態。
CREATE TABLE crls (
    tenant_id       TEXT    PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    pem             TEXT    NOT NULL DEFAULT '',
    number          TEXT    NOT NULL DEFAULT '',
    this_update     INTEGER NOT NULL DEFAULT 0,
    next_update     INTEGER NOT NULL DEFAULT 0,
    source          TEXT    NOT NULL DEFAULT '' CHECK (source IN ('', 'fetch', 'upload')),
    installed_at    INTEGER NOT NULL DEFAULT 0,
    etag            TEXT    NOT NULL DEFAULT '',
    last_attempt_at INTEGER NOT NULL DEFAULT 0,
    last_success_at INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT ''
) STRICT;

-- 反映の履歴（設計概要 §11.1）。テナントを消しても残すので、外部キーにしない。
CREATE TABLE applies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    hash        TEXT    NOT NULL DEFAULT '',
    trigger     TEXT    NOT NULL,
    action      TEXT    NOT NULL DEFAULT '',
    result      TEXT    NOT NULL,
    error       TEXT    NOT NULL DEFAULT '',
    operator    TEXT    NOT NULL DEFAULT '',
    started_at  INTEGER NOT NULL,
    finished_at INTEGER NOT NULL
) STRICT;
CREATE INDEX applies_tenant ON applies (tenant_id, id);

-- 監査ログ（設計概要 §7.2）。detail は JSON。鍵や共有シークレットを入れない。
CREATE TABLE audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    time     INTEGER NOT NULL,
    operator TEXT    NOT NULL DEFAULT '',
    source   TEXT    NOT NULL CHECK (source IN ('gui', 'api', 'system')),
    action   TEXT    NOT NULL,
    target   TEXT    NOT NULL DEFAULT '',
    detail   TEXT    NOT NULL DEFAULT '{}',
    trace_id TEXT    NOT NULL DEFAULT '',
    remote   TEXT    NOT NULL DEFAULT ''
) STRICT;
