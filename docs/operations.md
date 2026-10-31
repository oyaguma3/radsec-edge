# radsec-edge 運用ガイド

- 状態: 2026-10-31。単独モードの手順は `scripts/e2e.sh`（simwifi）で確かめた。管理モードの手順（10 章）は `scripts/check-guide.sh`（CI のジョブ「運用ガイドの手順の通し確認」）で確かめる。aka-provisioner・radsec-ca とつないだ通しと、WireGuard・Cloudflare を通す部分は MVP セットの段階 4・5 の通しで確かめる。
- 対象: エッジを導入・運用する人（事業者の運用者）。CA（radsec-ca）の導入と運用は、radsec-ca の運用ガイドを見る。
- 2〜9 章は単独モード（エッジの画面だけで運用する）を中心に書いている。管理モード（MVP セットで aka-provisioner から使う）は 10 章を先に読み、共通の部分（1 章、5〜7 章）を参照する。

## 1. 構成

| 部品 | 内容 |
|---|---|
| `radsec-edge` | 画面（8447。cloudflared からだけ受ける）、テナントと AP の望む状態（SQLite）、設定の生成と反映、整合ループ、CRL の取得、AP の最後の接続 |
| `radsec-edge-agent` | Docker を操作する唯一の部品（docker.sock を持つ）。ネットワークを使わず、unix ソケットだけで `radsec-edge` と話す |
| `radsecproxy-<テナント>` | テナントごとの radsecproxy（agent が作る。compose の管理の外）。テナントのポート（20000〜21999）で AP の RadSec を受ける |
| `cloudflared` | Cloudflare Tunnel のコネクター（画面を Cloudflare Access の後ろに出す） |

- ホストのディレクトリ `EDGE_HOST_DIR`（既定 `/var/lib/radsec-edge`）の `data` に SQLite と鍵、`tenants` にテナントの radsecproxy の設定を置く。`tenants` はホストと同じパスでマウントする（agent がテナントのコンテナにそのパスをマウントするため）。
- 利用者: `radsec-edge` は UID 10084・GID 10083、agent は UID 10085・GID 10083（と docker のグループ）、radsecproxy は UID・GID 10083。テナントのファイルはグループ 10083 で読ませる。
- 上流（本PoC など）へは、トンネル（WireGuard）の中の UDP で送る。本PoC には、エッジのトンネルの IP を RADIUSクライアントとして 1 件登録し、共有シークレットは `EDGE_UPSTREAM_SECRET` と同じにする（設計概要 §12.3）。

## 2. 導入

### 2.1 ホストのディレクトリと docker のグループ

```bash
sudo install -d -o 10084 -g 10083 -m 0750 /var/lib/radsec-edge/data /var/lib/radsec-edge/tenants
stat -c %g /var/run/docker.sock   # EDGE_DOCKER_GID に書く
```

### 2.2 設定

`cp .env.example .env` して書き換え、`chmod 600 .env` にする。

| 項目 | 内容 |
|---|---|
| `EDGE_DOCKER_GID` | 2.1 の docker のグループの番号 |
| `EDGE_URN_PREFIX`・`EDGE_DNS_DOMAIN` | CA の `CA_URN_PREFIX`・`CA_DNS_DOMAIN` と同じ値 |
| `EDGE_UPSTREAM_AUTH`・`EDGE_UPSTREAM_ACCT` | 新しいテナントの上流の既定（IP アドレス:ポート。ホスト名は使えない。radsecproxy は名前を引けないと起動しないため） |
| `EDGE_UPSTREAM_SECRET` | 上流との共有シークレット（8〜128 文字の英数字と `._~+/=@-`） |
| `EDGE_STAMP_VENDOR_ID`・`EDGE_STAMP_VENDOR_TYPE` | テナントの刻印の VSA（既定 32473・1。起動のときにログに出す）。単独モードの刻印の値はテナントの slug。上流が使わなければ無視される |
| `EDGE_CRL_BASE_URL` | CA の配布の口（例 `http://10.0.0.1:8449`）。空なら、テナントの画面で CRL を貼り付けて取り込む |
| `EDGE_TENANT_CAPACITY` | 1 台に置くテナントの数の上限（既定 150）。4 GB のエッジで 150、2 GB で 60 が保証値。超える新しいテナントは断る |
| `EDGE_AGENT_PUBLISH_ADDR` | テナントのポートを公開するアドレス。空ならすべてのアドレス。公開のアドレスを 1 つに絞るときに書く |
| `EDGE_ACCESS_TEAM_DOMAIN`・`EDGE_ACCESS_AUD` | Cloudflare Access のチームのドメインと AUD タグ |

Cloudflare Tunnel のトークンは `secrets/tunnel-token` に置き、`sudo chown 65532 secrets/tunnel-token && sudo chmod 600 secrets/tunnel-token` にする。Tunnel の公開ホスト名の向け先は `http://radsec-edge:8447`。Access のポリシーで、事業者の運用者だけを許す（エッジは利用者の表を持たない）。

### 2.3 イメージと起動

イメージは公開していないので、タグからソースでビルドする。radsecproxy のイメージ（`radsec-edge/radsecproxy:1.11.4-pc1`。radsecproxy 1.11.4 のソースを GitHub から取り、SHA-256 を確かめてパッチを当ててビルドする）も作る。VPS の上ではビルドせず、手元か CI で作って `docker save` で送る。

```bash
docker compose --profile build build
docker compose up -d
docker compose logs radsec-edge radsec-edge-agent
```

画面のダッシュボードで、agent と Docker が「正常」、イメージとネットワーク（`radsec-edge-tenants`）が「あり」になっていることを確かめる。

## 3. テナントを始める（CA の画面と組み合わせる）

1. CA の画面でテナントのクライアントCA を作る（テナントの名前はエッジと同じ。radsec-ca の運用ガイド 3 章）。
2. エッジの画面の「テナント」でテナントを作る。テナントの名前（slug）は SAN・NAS-Identifier・DNS の名前に入るので、作った後は変えられない。ポートは空なら空いているものを割り当てる。
3. テナントの詳細の「証明書」で、CA の証明書を「クライアントCA」に取り込む。CRL の取得先（`EDGE_CRL_BASE_URL` かテナントごとの値）があれば、CRL も続けて取りに行く。なければ「CRL」に CA の画面から取り出した CRL を貼り付ける。
4. 「サーバー証明書」の「鍵を作って CSR を出す」で CSR を出し、CA の画面の「署名」で `tenant-server`（テナントとエッジの名前）として署名して、できた証明書を取り込む。「ヘルスチェック用の証明書」も同じく `probe-client` で署名して取り込む。鍵はエッジで作り、外に出ない。
5. 「反映」で反映する。構文検査・コンテナの作成・ヘルスチェック（ヘルスチェック用の証明書で Status-Server を送る）が通れば「反映しました」になる。
6. 「設定」の「DNS に登録する名前」（`primary.<テナント>.<ドメイン>` など）を DNS に登録し、エッジの公開のアドレスに向ける（単独モードのエッジは 1 台なので、まず `primary`）。

反映に要るもの（クライアントCA の証明書・CRL・サーバー証明書・ヘルスチェック用の証明書）がそろっていないと、反映を断り、足りないものを画面に出す。ヘルスチェック用の証明書が今のクライアントCA で検証できない（クライアントCA を差し替えた後に出し直していない）、期限が切れている、失効しているときも、反映を断る。

### 3.1 ヘルスチェック用の証明書の出し直し

- クライアントCA を差し替えたら、ヘルスチェック用の証明書も CSR を出し直し、新しい CA（`probe-client`）で署名して取り込んでから反映する。
- ヘルスチェック用の証明書を CA で失効させた場合も、エッジはその CRL を置いて SIGHUP する（AP の失効を止めないため）。そのときは Status-Server を送らず、コンテナが動いていることだけを確かめる。画面とダッシュボードに「ヘルスチェック用の証明書が失効しています」と出るので、出し直す（出し直すまで反映できない）。

## 4. AP

### 4.1 登録

1. AP の CSR を CA の画面の「署名」で `ap-client`（テナントと AP の名前）として署名し、証明書を AP に入れる。AP には、サーバーCA の証明書（CA `server` の証明書）、スロットの名前（`primary` を主、`secondary`・`tertiary` を予備）、テナントのポートも設定する。
2. エッジの画面のテナントの「AP」で、同じ名前の AP を登録する。証明書を貼り付けると、クライアントCA の発行で SAN が合うことを確かめて、シリアル番号と期限を記録する（照合は SAN の URI で行うので、貼り付けなくても動く）。
3. 「反映」する（client ブロックが増えるので、radsecproxy を再起動する。このテナントの AP の接続がいったん切れる）。

AP の NAS-Identifier は `<テナント>-<AP>` になり、AP が名乗る値は置き換える。本PoC の認可ポリシーの `nasId` にはこの値を書く。

### 4.2 最後の接続

テナントの「AP」の「最後の接続」に、接続中か、最後に接続した時刻と接続元、証明書の拒否の時刻を出す。エッジは radsecproxy のログを 1 分ごとに読むので、少し遅れて変わる。コンテナを再起動すると、その前の接続は切れたものとして扱う。

### 4.3 削除・失効・更新

- すぐにつながらなくするには、CA の画面で証明書を失効させる。エッジは 5 分ごとに CRL を取りに行き、変わっていれば SIGHUP で読み直させる（接続中の AP も切れる）。急ぐときは、テナントの「CRL」の「今すぐ取りに行く」。
- エッジの画面で AP を削除すると、次の反映で client ブロックが消える（削除だけのために再起動しない）。
- 証明書の更新は、同じテナントと AP の名前で新しい CSR に署名して AP に入れる。エッジの設定は変わらない。古い証明書は CA で失効させる（理由 `superseded`）。

## 5. 監視

- ダッシュボードの「CRL の期限と取得」: nextUpdate までの残りが `EDGE_CRL_WARN`（既定 3 日）を切ったテナントと、取得に失敗しているテナントを出す。**nextUpdate を過ぎると、radsecproxy は新しい接続を拒否する**（既存の接続は使える）。CA が止まっていないか、トンネルが通っているかを確かめる。期限の切れた CRL は置かない（置くと全接続が切れるため）。
- ダッシュボードの「コンテナが動いていないテナント」「未反映の変更のあるテナント」「ヘルスチェック用の証明書に問題のあるテナント」。
- テナントの「反映の履歴」: 反映・整合・CRL の更新の結果。失敗の理由（構文検査の出力など）は「理由」を開く。
- ログ: `docker compose logs radsec-edge`（JSON。`msg` が `apply`・`audit`・`reconcile` など）。radsecproxy のログはテナントの「ログの末尾」か `docker logs radsecproxy-<テナント>`。

## 6. 運用の操作

| 操作 | 画面 | 内容 |
|---|---|---|
| 再起動 | テナントの「状態」 | radsecproxy を再起動する（AP の接続がいったん切れる） |
| 停止・起動 | テナントの「状態」 | 停止すると、コンテナを止め、整合ループも起動しない。望む状態の版は変わらない。停止中は反映できない |
| 設定の変更 | テナントの「設定」 | ポート・上流・CRL の取得先。反映するまで radsecproxy には効かない（整合ループも未反映の変更は反映しない） |
| 削除 | テナントの詳細の下 | コンテナ・設定・鍵・AP の登録を消す（反映の履歴と監査ログは残る） |

反映に失敗すると、前の版に戻す（前の版がなければコンテナを止める）。結果は画面と「反映の履歴」に出る。

## 7. バックアップと戻し方

- バックアップの対象は `EDGE_HOST_DIR/data`（SQLite と、サーバー証明書・ヘルスチェック用の証明書の鍵）。`tenants` は SQLite と鍵から作り直せる（反映すると生成する）。
- `docker compose stop radsec-edge` で止めてから `data` を写す（動かしたままだと、SQLite の WAL の途中を写すことがある）。鍵が入るので、写しの置き場所に気を付ける。
- 戻すときは、止めてから `data` を置き換え（所有者 10084:10083）、起動して、テナントごとに反映する。
- 古いバックアップに戻して、DB の反映済みの版と `tenants` の今の版が違うと、次の整合ループが DB の反映済みの版に戻して再起動する（その版のディレクトリが残っていなければ、次の反映で再起動して読み込ませる）。

## 8. 試験（E2E）

`scripts/e2e.sh` は、本PoC・radsec-ca・エッジを 1 台に導入し、AP の役（radsecproxy と radclient）と eapaka_test で単独モードの通しを確かめる（設計概要 §17、§22）。組み合わせるコミットは `scripts/e2e-versions.env`。Docker Desktop では動かない（bridge のゲートウェイの IP にポートを公開するため）。

```bash
scripts/e2e.sh ~/aka-work/radsec-e2e/work   # 例。KEEP=1 で終わった後も残す
```

確かめること: 認証が通る（認可ポリシーは置き換えた NAS-Identifier だけを許す）、置き換える前の NAS-Identifier が本PoC に届かない、Accounting-On が置き換えた NAS-Identifier で届く、画面の「接続中」、ほかのテナントの CA の証明書では通らない、失効させた証明書が CRL の取り直しの後に拒否される、証明書の更新でエッジの設定を変えずにつながる、クライアントCA を差し替えてヘルスチェック用の証明書を出し直さない反映を断る（AP の接続は切れない）、ヘルスチェック用の証明書を失効させても CRL を置き、その後の AP の失効が効く。前の版に戻す動きは、Docker の結合の試験（`EDGE_TEST_DOCKER=1 go test ./internal/edge/`）で確かめる。

## 9. 片付け

```bash
docker compose down
docker ps -aq --filter label=radsec-edge.tenant | xargs -r docker rm -f   # テナントのコンテナ（agent が作ったもの）
```

`EDGE_HOST_DIR` はコンテナの利用者のファイルを含むので、消すときは `sudo rm -rf` を使う。

## 10. 管理モード（aka-provisioner から使う）

望む状態の正本は中央（aka-ossbss）にあり、aka-provisioner を通して管理API（9447、mTLS）で届く。エッジの SQLite は写しで、画面はテナント・AP・証明書・CRL の変更ができない（反映のやり直し、再起動、停止と起動、CRL の取り直し、ログは使える）。単独モードのデータは引き継がない（数字でない ID のテナントがある DB では、管理モードは起動しない。単独モードでテナントを消すか、空の `data` で始める）。

### 10.1 Docker の設定

`/etc/docker/daemon.json` に次を書いて dockerd を再起動する（aka-mvpset の決定事項 27）。`userland-proxy` をオフにすると公開ポートごとの docker-proxy がなくなり、1 テナントあたり約 3.6 MiB 減る。`live-restore` をオンにすると、dockerd を再起動してもテナントのコンテナと AP の接続が続く。

```json
{ "userland-proxy": false, "live-restore": true }
```

WireGuard（`wg-quick@wg0`）を Docker より先に上げる。トンネルのアドレスがホストにないと、管理API のポートを公開できずに `radsec-edge` が起動しない。

### 10.2 導入

2.1 に加えて、監査ログとログのディレクトリを作る。

```bash
sudo install -d -o 10084 -g 10083 -m 0750 /var/lib/radsec-edge/audit
```

```bash
sudo install -d -m 0755 /var/lib/radsec-edge/logs
```

`.env` に 2.2 の項目と次を書く。

| 項目 | 内容 |
|---|---|
| `COMPOSE_FILE` | `compose.yaml:compose.managed.yaml`（Fluent Bit も使うときは `:compose.fluent-bit.yaml` を足す） |
| `EDGE_BIND_ADDR` | 管理API を公開するトンネルのアドレス |
| `EDGE_TLS_HOSTS` | 管理API のサーバー証明書の SAN（aka-provisioner がつなぐアドレス。ふつうは `EDGE_BIND_ADDR` と同じ） |
| `EDGE_CRL_BASE_URL` | radsec-ca の配布の口（管理モードでは必須） |
| `EDGE_UPSTREAM_SECRET` | aka-radius に登録する、このエッジの共有シークレット |

管理クライアント（aka-provisioner）のピンのファイルを置く。1 行に `識別名=SHA-256 フィンガープリント`。UID 10084 で読めるようにする。

```bash
mkdir -p secrets && chmod 700 secrets
```

```bash
echo "provisioner=$(openssl x509 -in client.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')" > secrets/admin-clients
```

```bash
sudo chown 10084 secrets/admin-clients && sudo chmod 400 secrets/admin-clients
```

起動して、管理API のサーバー証明書とフィンガープリントを取り出す（aka-provisioner の登録簿の `serverFingerprint` に書く）。

```bash
docker compose up -d
```

```bash
docker compose exec -T radsec-edge /radsec-edge server-cert > edge-admin.pem
```

エッジを足す手順の全体（WireGuard のピア、aka-radius の RADIUS クライアントのコマンド、aka-provisioner の登録簿、aka-ossbss のエッジの台帳）は設計概要 §14.1 と aka-ossbss のガイドを見る。

### 10.3 ピンの入れ替え（aka-provisioner のクライアント証明書を替えるとき）

新旧の 2 行を**その場で**書き、`SIGHUP` で読み直す（`sed -i` などでファイルを置き換えると、動いているコンテナは古い中身を読み続ける）。aka-provisioner が新しい証明書を使い始めたら古い行を消して、もう一度 `SIGHUP` を送る。読めないときは前のピンのまま続け、ログに `EDGE_ADMIN_CLIENTS_RELOAD_ERR` を出す。

```bash
docker compose kill -s SIGHUP radsec-edge
```

### 10.4 管理API のサーバー証明書の入れ替え

作り直して（監査ログに残る）新しいフィンガープリントを aka-provisioner の登録簿に書き、`SIGHUP` で読み直す。

```bash
docker compose exec -T radsec-edge /radsec-edge replace-server-cert > edge-admin.pem
```

```bash
docker compose kill -s SIGHUP radsec-edge
```

### 10.5 ログと監査ログ

`compose.fluent-bit.yaml` を重ねると、エッジの Fluent Bit（ループバックの `EDGE_FLUENT_BIT_PORT`、既定 24224）にログを送り、`EDGE_HOST_DIR/logs` の `radsec-edge.log`・`radsec-edge-agent.log`・`radsec-edge-cloudflared.log`・`radsecproxy.log`（全テナント。行の `container_name` で見分ける）に書く。`docker logs` と画面の「ログの末尾」も読める。

- **有効にすると、テナントのコンテナはひな形が変わるので、次の整合ループで 1 回作り直され、そのエッジの AP の接続がいったん切れる。** 導入のときに有効にするか、エッジを 1 台ずつ切り替える。
- Fluent Bit が止まっていても、コンテナは動き続け、ログはメモリーに溜めて戻ったときに送る。ただし、止まっている間に作り直した・再起動したコンテナの未送信の行は失われる。
- `fluentd-buffer-limit` と forward の受信バッファーは絞ってある。既定の値に戻すと、150 テナントで約 700 MiB 増える（aka-mvpset の `verify/edge-logs/`）。

ファイルはホストの logrotate で日ごとに圧縮し、2 週間持つ。監視用の PC が取りに行く。`/etc/logrotate.d/radsec-edge`:

```
/var/lib/radsec-edge/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
}
```

監査ログは SQLite に加えて、日ごとの `EDGE_HOST_DIR/audit/audit-YYYYMMDD.jsonl` にも書く（日本時間で区切り、前の日までを gzip で圧縮し、`EDGE_AUDIT_RETENTION_DAYS`、既定 14 日で消す）。監視用の PC が取りに行く。操作者は `operator`（`X-Operator-Id`）、管理クライアントは `mgmtClient`、トレースID は `traceId`。ログの `event_id`:

| `event_id` | 内容 |
|---|---|
| `EDGE_AUTH_REJECTED` | 管理API が断ったクライアント証明書（登録していない、有効期間の外） |
| `EDGE_ADMIN_CLIENTS_RELOADED`・`EDGE_ADMIN_CLIENTS_RELOAD_ERR` | ピンの読み直し |
| `EDGE_SERVER_CERT_RELOADED`・`EDGE_SERVER_CERT_RELOAD_ERR` | サーバー証明書の読み直し |
| `EDGE_AUDIT_FILE_ERR` | 監査ログのファイルの圧縮か削除に失敗した |

### 10.6 反映の見方

中央からの `apply` は裏で動き、結果は `GET /tenants/{id}` の `apply` と画面の「反映の履歴」に出る。

| 結果 | 内容 |
|---|---|
| 成功 | 反映した |
| 失敗（前の版のまま） | 構文検査の誤りなど。radsecproxy は変わっていない |
| 失敗（前の版に戻した） | ヘルスチェックが通らなかったので前の版に戻した |
| 途中で止まった（前の版に戻した） | 反映の途中で `radsec-edge` が止まっていた。次の整合ループか次の反映で、反映済みの版に戻して再起動した（AP の接続がいったん切れる）。望む状態は変わらないので、中央が反映し直す |

反映やその他の処理が動いている間の変更の要求は、5 秒待って `503 TENANT_BUSY` を返す（中央が次の周回でやり直す）。

### 10.7 業者の CA の侵害・失効を知ったとき

持ち込みの CA は束に業者の CA だけを置くので、業者の CA が上位の CA に失効させられても、エッジも CA も気づけない。業者の CA の侵害・失効を知ったら、**新しい CA を待たずに**システム管理者がその CA をテナントから外す（設計概要 §24.9）。

1. aka-ossbss でその持ち込みの CA をテナントから外す。そのテナントを置いたすべてのエッジに宣言と反映が届く。
2. 各エッジの画面の「持ち込みの CA」から消え、「反映の履歴」が成功になったことを確かめる。束だけが変わるときは SIGHUP で効き、既存の接続も検証し直して切る。そのテナントの最後の持ち込みの CA を外して共通のブロックが消えるときと、`CRLCheck`・`PartialChain` が変わるときは再起動になる。
3. 外し終わってから、radsec-ca でその CA を止める（radsec-ca の運用ガイド 4.4）。

業者の新しい CA を登録するまで、その業者の AP はつながらない。

### 10.8 バックアップ

7 章と同じ（`EDGE_HOST_DIR/data` を止めて写す。管理API のサーバー証明書の鍵 `data/tls/` と、テナントの鍵 `data/keys/` を含むので、写しの置き場所に気を付ける）。`data` を失っても望む状態は中央から届くが、テナントのサーバー証明書とヘルスチェック用の証明書は鍵ごと作り直しになる（`missing` に出るので、中央が CSR から出し直す）。管理API のサーバー証明書も変わるので、aka-provisioner の登録簿を書き換える。
