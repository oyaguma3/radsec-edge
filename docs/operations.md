# radsec-edge 運用ガイド（単独モード）

- 状態: 2026-10-18。段階 3（単独モードの通し）の時点の手順。管理モード（段階 4）の手順は、その段階で足す。
- 対象: エッジを導入・運用する人（事業者の運用者）。CA（radsec-ca）の導入と運用は、radsec-ca の運用ガイドを見る。

## 1. 構成

| 部品 | 内容 |
|---|---|
| `radsec-edge` | 画面（8447。cloudflared からだけ受ける）、テナントと AP の望む状態（SQLite）、設定の生成と反映、整合ループ、CRL の取得、AP の最後の接続 |
| `radsec-edge-agent` | Docker を操作する唯一の部品（docker.sock を持つ）。ネットワークを使わず、unix ソケットだけで `radsec-edge` と話す |
| `radsecproxy-<テナント>` | テナントごとの radsecproxy（agent が作る。compose の管理の外）。テナントのポート（20830〜20999）で AP の RadSec を受ける |
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
| `EDGE_CRL_BASE_URL` | CA の配布の口（例 `http://10.0.0.1:8449`）。空なら、テナントの画面で CRL を貼り付けて取り込む |
| `EDGE_AGENT_PUBLISH_ADDR` | テナントのポートを公開するアドレス。空ならすべてのアドレス。公開のアドレスを 1 つに絞るときに書く |
| `EDGE_ACCESS_TEAM_DOMAIN`・`EDGE_ACCESS_AUD` | Cloudflare Access のチームのドメインと AUD タグ |

Cloudflare Tunnel のトークンは `secrets/tunnel-token` に置き、`sudo chown 65532 secrets/tunnel-token && sudo chmod 600 secrets/tunnel-token` にする。Tunnel の公開ホスト名の向け先は `http://radsec-edge:8447`。Access のポリシーで、事業者の運用者だけを許す（エッジは利用者の表を持たない）。

### 2.3 イメージと起動

イメージは公開していないので、タグからソースでビルドする。radsecproxy のイメージ（`radsec-edge/radsecproxy:1.11.2-1-deb13u1`）も作る。

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

反映に要るもの（クライアントCA の証明書・CRL・サーバー証明書・ヘルスチェック用の証明書）がそろっていないと、反映を断り、足りないものを画面に出す。

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
- ダッシュボードの「コンテナが動いていないテナント」「未反映の変更のあるテナント」。
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

## 8. 試験（E2E）

`scripts/e2e.sh` は、本PoC・radsec-ca・エッジを 1 台に導入し、AP の役（radsecproxy と radclient）と eapaka_test で単独モードの通しを確かめる（設計概要 §17、§22）。組み合わせるコミットは `scripts/e2e-versions.env`。Docker Desktop では動かない（bridge のゲートウェイの IP にポートを公開するため）。

```bash
scripts/e2e.sh ~/aka-work/radsec-e2e/work   # 例。KEEP=1 で終わった後も残す
```

確かめること: 認証が通る（認可ポリシーは置き換えた NAS-Identifier だけを許す）、置き換える前の NAS-Identifier が本PoC に届かない、Accounting-On が置き換えた NAS-Identifier で届く、画面の「接続中」、ほかのテナントの CA の証明書では通らない、失効させた証明書が CRL の取り直しの後に拒否される、証明書の更新でエッジの設定を変えずにつながる、ヘルスチェックが通らない反映で前の版に戻る。

## 9. 片付け

```bash
docker compose down
docker ps -aq --filter label=radsec-edge.tenant | xargs -r docker rm -f   # テナントのコンテナ（agent が作ったもの）
```

`EDGE_HOST_DIR` はコンテナの利用者のファイルを含むので、消すときは `sudo rm -rf` を使う。
