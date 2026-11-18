# テナントの radsecproxy のイメージ（設計概要 §4、§10.2、§24.5、§24.15）。agent はこのイメージだけからコンテナを作る。
# radsecproxy 1.11.5 のソースの tar（SHA-256 を固定）に 2 つのパッチを当ててビルドする。
#   - partialchain-leafcrl.patch: tls ブロックのオプション PartialChain（自己署名でない CA も信頼の起点にする）と、そのときの CRL の確認を
#     リーフだけにする変更で、aka-mvpset の verify/r10 のラボで確かめたもの。PartialChain を書かないテナントの動きは無改造と同じ。
#   - client-idletimeout.patch: client ブロックのオプション IdleTimeout（要求のない AP の TLS 接続を閉じるまでの秒数。0 は閉じない）。
#     開発版（未リリース）にある同じ名前のオプションを取り込んだもの。書かなければ無改造と同じ 900 秒（aka-mvpset の A6-13）。
# タグは radsec-edge/radsecproxy:1.11.5-pc2（radsecproxy の版とパッチの版）。上げるときは、ここと agent の Image を一緒に変える。
FROM debian:13.7-slim AS build
ARG RADSECPROXY_VERSION=1.11.5
ARG RADSECPROXY_SHA256=cc8488664179d8c4b9a7a26ecbc2137492bf251a19b65f65edb7d8a99864194e
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev nettle-dev pkg-config ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY partialchain-leafcrl.patch client-idletimeout.patch /src/
RUN cd /src \
 && curl -fsSLO "https://github.com/radsecproxy/radsecproxy/releases/download/${RADSECPROXY_VERSION}/radsecproxy-${RADSECPROXY_VERSION}.tar.gz" \
 && echo "${RADSECPROXY_SHA256}  radsecproxy-${RADSECPROXY_VERSION}.tar.gz" | sha256sum -c - \
 && tar -xzf "radsecproxy-${RADSECPROXY_VERSION}.tar.gz" \
 && cd "radsecproxy-${RADSECPROXY_VERSION}" \
 && patch -p1 < ../partialchain-leafcrl.patch \
 && patch -p1 < ../client-idletimeout.patch \
 && ./configure -q \
 && make -s -j4 radsecproxy \
 && install -D -m 0755 radsecproxy /out/usr/sbin/radsecproxy

FROM debian:13.7-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 libnettle8t64 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10083 radsecproxy-edge \
 && useradd --system --uid 10083 --gid 10083 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin radsecproxy-edge
COPY --from=build /out/usr/sbin/radsecproxy /usr/sbin/radsecproxy
USER 10083:10083
# -f: フォアグラウンドで動かし、ログを標準エラーに出す（Docker のログで読む。§10.3）。
CMD ["radsecproxy", "-f", "-c", "/conf/current/radsecproxy.conf"]
