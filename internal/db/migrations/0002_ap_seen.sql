-- AP の最後の接続（設計概要 §12.1、§22.2 の 6）。radsecproxy のログの接続の確立・切断・証明書の拒否の行から作る。
-- AP の登録とは別に持つ（AP を消しても記録は残すが、画面には登録のある AP だけを出す）。
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

-- テナントのログをどこまで読んだか（Docker の時刻。RFC 3339 のナノ秒）。
CREATE TABLE log_cursors (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    since     TEXT NOT NULL
) STRICT;
