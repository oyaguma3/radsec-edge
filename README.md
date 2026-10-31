# radsec-edge

RadSec（RADIUS over TLS）の AP を受けるエッジノードです。AP のグループ（テナント）ごとに [radsecproxy](https://github.com/radsecproxy/radsecproxy) のコンテナを立て、AP をクライアント証明書（SAN の URI）で識別して NAS-Identifier を AP ごとの値に置き換え、上流の RADIUS サーバー（[EAP-AKA RADIUS PoC](https://github.com/oyaguma3/eapaka-radius-server-poc) など）へ送ります。コンテナの設定と起動・停止は、Web GUI と API で制御します。

```
AP ──RadSec（TLS）──> radsecproxy（テナントごと）──RADIUS（UDP。WireGuard の中）──> 上流の RADIUS サーバー
                        ▲ 設定の生成・反映・監視
                     radsec-edge（Web GUI・管理API）── radsec-edge-agent（Docker の操作）
```

- 1 つのテナントを複数のエッジに置けます（`primary` / `secondary` / `tertiary`）。
- 単独モード（エッジの画面だけで運用する）と、管理モード（[aka-ossbss](https://github.com/oyaguma3/aka-ossbss) から [aka-provisioner](https://github.com/oyaguma3/aka-provisioner) を通して運用する）を持ちます。
- AP とエッジの証明書は、独立した CA（[radsec-ca](https://github.com/oyaguma3/radsec-ca)）が発行します。

## 状態

開発中です。単独モードは、CA（[radsec-ca](https://github.com/oyaguma3/radsec-ca)）と本PoC をつないだ通しの確かめ（E2E）まで済ませました。管理モードはエッジの側（管理API、管理モードの画面、配備、Fluent Bit）まで作り、中央（aka-provisioner・aka-ossbss）とつなぐ作業を MVP セット（[aka-mvpset](https://github.com/oyaguma3/aka-mvpset)）の段階 4 で進めています。

- 設計概要: [docs/design-overview.md](docs/design-overview.md)（段階は §20、段階 1 は §21、段階 3 は §22、MVP セットの変更は §24）
- 運用ガイド: [docs/operations.md](docs/operations.md)（管理モードは 10 章）
- 管理API: [docs/openapi/edge-api.yaml](docs/openapi/edge-api.yaml)
- 段階 0 の実機の検証（radsecproxy の振る舞いの確認）の道具と手順: [verify/v0/](verify/v0/)

## 部品

| 部品 | 役目 |
|---|---|
| `radsec-edge` | テナントと AP の望む状態（SQLite）、設定の生成と反映、整合ループ、CRL の取得、運用者向けの画面（8447。Cloudflare Access の JWT で利用者を確かめる）、管理API（9447、mTLS。管理モードだけ） |
| `radsec-edge-agent` | Docker を操作する唯一の部品。`radsec-edge` から unix ソケットで決まった操作だけを受け、テナントの radsecproxy のコンテナを固定のひな形から作る |
| radsecproxy（テナントごと） | `images/radsecproxy` のイメージ（radsecproxy 1.11.4 に PartialChain のパッチを当ててソースからビルドしたもの）。ポート 20000〜21999 の 1 つで AP の RadSec を受ける |

反映は「設定の生成 → `radsecproxy -p` の構文検査 → 版のディレクトリの付け替え → SIGHUP か再起動 → ヘルスチェック（ヘルスチェック用の証明書で Status-Server を送る）」の順に行い、失敗したら前の版に戻します。

## 導入（単独モード）

詳しくは[運用ガイド](docs/operations.md)を見てください。

イメージは公開していないので、タグからソースでビルドします。

1. ホストのディレクトリを作ります（`radsec-edge` は UID 10084・GID 10083、radsecproxy は UID・GID 10083 で動きます）。

   ```bash
   sudo install -d -o 10084 -g 10083 -m 0750 /var/lib/radsec-edge/data /var/lib/radsec-edge/tenants
   ```

2. `.env` を作ります（`cp .env.example .env` して書き換え、`chmod 600 .env`）。`EDGE_DOCKER_GID` は `stat -c %g /var/run/docker.sock` の値です。Cloudflare Tunnel のトークンは `secrets/tunnel-token` に置きます。
3. イメージを作って起動します。

   ```bash
   docker compose --profile build build
   docker compose up -d
   ```

4. Cloudflare Tunnel の公開ホスト名の向け先を `http://radsec-edge:8447` にし、Cloudflare Access で運用者だけを許可します。

画面でテナントを作り、クライアントCA の証明書・CRL・サーバー証明書・ヘルスチェック用の証明書を取り込み（サーバー証明書とヘルスチェック用の証明書は、画面で出した CSR を CA で署名します）、AP を登録して反映します。

## 導入（管理モード）

`compose.managed.yaml`（と、ログを Fluent Bit に送るときは `compose.fluent-bit.yaml`）を重ねます。手順は[運用ガイド 10 章](docs/operations.md)を見てください。

## 開発

- Go 1.27.3 と Docker が要ります。`go test ./...` で単体の試験、`EDGE_TEST_DOCKER=1 go test ./...` で本物の Docker と radsecproxy を使う結合の試験も動きます（先に `docker build -t radsec-edge/radsecproxy:1.11.4-pc1 images/radsecproxy`）。
- `scripts/check-guide.sh` は、管理モードの手順（導入、ピンの入れ替え、宣言から反映、Fluent Bit、監査ログ、バックアップ）を compose で流して確かめます（CI のジョブと同じ）。
- `scripts/e2e.sh` は、本PoC・radsec-ca・エッジを 1 台に導入して、eapaka_test と AP の役（radsecproxy）で単独モードの通しを確かめます（Docker Desktop では動きません。運用ガイド 8 章）。GitHub Actions では「E2E」のワークフローを手で起動します。
- 画面の CSS は `sh scripts/build-css.sh` で作ります（Tailwind CSS のスタンドアロン CLI と daisyUI を、版を固定して取得します）。

## ライセンス

[MIT](LICENSE)
