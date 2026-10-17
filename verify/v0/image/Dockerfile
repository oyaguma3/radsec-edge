# 段階 0 の実機の検証用。エッジ側の radsecproxy と、AP の役（radsecproxy をクライアントとして使い、radclient で要求を出す）の両方に使う。
FROM debian:13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends radsecproxy freeradius-utils openssl procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
