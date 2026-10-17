# radsec-edge と radsec-edge-agent のイメージ（設計概要 §4。1 つのイメージに 2 つのバイナリを入れ、compose で別のコマンドで動かす）。
FROM golang:1.27.2 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 画面の CSS を作る（Tailwind CSS のスタンドアロン CLI と daisyUI。版とチェックサムは scripts/build-css.sh で固定）。
RUN --mount=type=cache,target=/root/.cache/edge-css EDGE_CSS_CACHE=/root/.cache/edge-css sh scripts/build-css.sh
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/radsec-edge ./cmd/radsec-edge \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/radsec-edge-agent ./cmd/radsec-edge-agent \
 && mkdir -p /out/run/radsec-edge-agent

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/radsec-edge /out/radsec-edge-agent /
# agent のソケットを置くディレクトリ。compose の名前つきボリュームをここにマウントすると、空のボリュームはこの所有者と権限を
# 引き継ぐ（agent 10085 が書き、radsec-edge はグループ 10083 で入る。設計概要 §10.2）。
COPY --from=build --chown=10085:10083 --chmod=0750 /out/run/radsec-edge-agent /run/radsec-edge-agent
ENTRYPOINT ["/radsec-edge"]
CMD ["serve"]
