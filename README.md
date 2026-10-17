# radsec-edge

RadSec（RADIUS over TLS）の AP を受けるエッジノードです。AP のグループ（テナント）ごとに [radsecproxy](https://github.com/radsecproxy/radsecproxy) のコンテナを立て、AP をクライアント証明書（SAN の URI）で識別して NAS-Identifier を AP ごとの値に置き換え、上流の RADIUS サーバー（[EAP-AKA RADIUS PoC](https://github.com/oyaguma3/eapaka-radius-server-poc) など）へ送ります。コンテナの設定と起動・停止は、Web GUI と API で制御します。

```
AP ──RadSec（TLS）──> radsecproxy（テナントごと）──RADIUS（UDP。WireGuard の中）──> 上流の RADIUS サーバー
                        ▲ 設定の生成・反映・監視
                     radsec-edge（Web GUI・管理API）── radsec-edge-agent（Docker の操作）
```

- 1 つのテナントを複数のエッジに置けます（`primary` / `secondary` / `tertiary`）。
- 単独モード（エッジの画面だけで運用する）と、管理モード（[eapaka-ossbss-sample](https://github.com/oyaguma3/eapaka-ossbss-sample) から [eapaka-node-provisioner](https://github.com/oyaguma3/eapaka-node-provisioner) を通して運用する）を持ちます。
- AP とエッジの証明書は、独立した CA（[radsec-ca](https://github.com/oyaguma3/radsec-ca)）が発行します。

## 状態

設計中です。実装はまだありません。

- 設計概要: [docs/design-overview.md](docs/design-overview.md)
- 段階 0 の実機の検証（radsecproxy の振る舞いの確認）の道具と手順: [verify/v0/](verify/v0/)

## ライセンス

[MIT](LICENSE)
