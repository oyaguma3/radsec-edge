# E2E の AP の役（設計概要 §17）。radsecproxy をクライアントとして動かし（RADIUS（UDP）を受けて RadSec でエッジに送る）、
# radclient で Accounting-On を送る。eapaka_test は UDP だけなので、この役を間に置く。
FROM debian:13.7-slim
ARG RADSECPROXY_VERSION=1.11.2-1+deb13u1
RUN apt-get update \
 && apt-get install -y --no-install-recommends "radsecproxy=${RADSECPROXY_VERSION}" freeradius-utils \
 && rm -rf /var/lib/apt/lists/*
CMD ["radsecproxy", "-f", "-c", "/conf/radsecproxy.conf"]
