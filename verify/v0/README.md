# 段階 0 の実機の検証（radsecproxy）

設計概要 `docs/design-overview.md` §18 の V1〜V10 を simwifi で確かめたときの道具と設定。結果は §18.1、設計への反映の案は §18.2。

## 中身

| ファイル | 内容 |
|---|---|
| `tools/cmd/certgen` | CA・証明書・CRL を作る（Go の `crypto/x509`。将来の CA と同じ作り方） |
| `tools/cmd/fakeradius` | 上流（本PoC の代わり）。すべて受け付け、届いた要求の送信元・NAS-Identifier（とその個数）・User-Name をログに出す |
| `image/Dockerfile` | `debian:13-slim` に radsecproxy・freeradius-utils（radclient）・openssl を入れたイメージ。エッジ側と AP の役の両方に使う |
| `gen.sh` | PKI と、各コンテナの radsecproxy の設定を作る（設計概要 §10.3 のひな形） |
| `compose.yaml` | 上流 1、エッジ側 4（テナント A×2、B、C=AP 500 台分）、AP の役 4。外に出ない内部のネットワークだけで、ホストにポートを公開しない |
| `up.sh` | 起動の順（上流 → エッジ → AP の役）を守って起動する |

## 動かし方（simwifi）

```bash
cd tools && CGO_ENABLED=0 go build -trimpath -o ../bin/ ./cmd/... && cd ..
ssh simwifi 'mkdir -p ~/aka-work/radsec-v0'
tar -c image bin gen.sh compose.yaml up.sh | ssh simwifi 'tar -x -C ~/aka-work/radsec-v0'
ssh simwifi 'cd ~/aka-work/radsec-v0 && docker build -q -t radsec-v0:latest image && bash gen.sh && bash up.sh'
```

認証の要求は、AP の役のコンテナの中の radclient で出す（例 `docker compose exec -T ap-a sh -c 'printf "User-Name = \"u@example\"\nUser-Password = \"x\"\nMessage-Authenticator = 0x00\n" | radclient 127.0.0.1:1812 auth testing123'`）。上流のログ（`docker compose logs upstream`）で、NAS-Identifier の置き換えとエッジ（送信元）を見る。

コンテナのルートのファイルシステムは読み取り専用なので、スクリプトは `docker compose exec -T <サービス> sh -s < スクリプト` で渡す。`openssl s_client` は `-quiet` を付けると入力の終わりで止まらないので、`-brief` と `timeout` を使う。

## 片付け（simwifi）

```bash
ssh simwifi 'cd ~/aka-work/radsec-v0 && docker compose down -v; cd ~ && sudo rm -rf ~/aka-work/radsec-v0 && docker image prune -af && docker builder prune -af'
```
