-- 管理モードのための変更（設計概要 §24.11）。時刻はすべて UNIX 時間のミリ秒（UTC）。

-- revision は中央（OSS/BSS）が付けた望む状態の版（EA3）。applied_revision は反映済みの版。単独モードでは 0 のまま。
ALTER TABLE tenants ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN applied_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE applies ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;

-- 管理API の管理クライアントの識別名（ピンのファイルの名前）。
ALTER TABLE audit ADD COLUMN mgmt_client TEXT NOT NULL DEFAULT '';

-- 管理API の Idempotency-Key（radsec-ca と同じ。24 時間覚える）。
CREATE TABLE idempotency (
    mgmt_client TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    req_hash    TEXT    NOT NULL,
    status      TEXT    NOT NULL CHECK (status IN ('pending', 'done')),
    resp_status INTEGER NOT NULL DEFAULT 0,
    resp_type   TEXT    NOT NULL DEFAULT '',
    response    BLOB    NOT NULL DEFAULT x'',
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (mgmt_client, key)
) STRICT;
CREATE INDEX idempotency_expires ON idempotency (expires_at);
