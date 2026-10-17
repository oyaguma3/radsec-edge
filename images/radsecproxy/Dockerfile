# テナントの radsecproxy のイメージ（設計概要 §4、§10.2）。agent はこのイメージだけからコンテナを作る。
# タグは radsec-edge/radsecproxy:1.11.2-1-deb13u1（パッケージの版の + はタグに使えないので - にする）。
# パッケージの版を上げるときは、ここと agent のイメージの名前（internal/agent の Image）を一緒に変える。
FROM debian:13.7-slim
ARG RADSECPROXY_VERSION=1.11.2-1+deb13u1
RUN apt-get update \
 && apt-get install -y --no-install-recommends "radsecproxy=${RADSECPROXY_VERSION}" \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10083 radsecproxy-edge \
 && useradd --system --uid 10083 --gid 10083 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin radsecproxy-edge
USER 10083:10083
# -f: フォアグラウンドで動かし、ログを標準エラーに出す（Docker のログで読む。§10.3）。
CMD ["radsecproxy", "-f", "-c", "/conf/current/radsecproxy.conf"]
