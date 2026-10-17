#!/bin/sh
# 画面の CSS（internal/web/static/app.css）を作る（eapaka-ossbss-sample の scripts/build-css.sh をコピーしたもの）。
# Tailwind CSS v4 のスタンドアロン CLI と daisyUI 5 のプラグインを、版を固定して取得し、SHA-256 を確かめてから使う。
# Node.js は使わない。取得したファイルは EDGE_CSS_CACHE（既定 .cache/css）に置き、次からは使い回す。
# Docker のビルドの段（Dockerfile）と手元の開発で同じものを使う。リポジトリの直下で実行する。
set -eu

TAILWIND_VERSION=v4.3.3
DAISYUI_VERSION=v5.7.43

# 版を上げるときは、リリースの各ファイルの SHA-256 も更新する（GitHub のリリースの digest、
# Tailwind CSS は sha256sums.txt と同じ値）。
DAISYUI_SHA256=c63d5c8c24920fb9a2a2c501d606ca806ec012ecb14652f25859317b147044ea
case "$(uname -m)" in
x86_64 | amd64)
	TAILWIND_ASSET=tailwindcss-linux-x64
	TAILWIND_SHA256=dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a
	;;
aarch64 | arm64)
	TAILWIND_ASSET=tailwindcss-linux-arm64
	TAILWIND_SHA256=55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195
	;;
*)
	echo "build-css: unsupported architecture $(uname -m)" >&2
	exit 1
	;;
esac
if [ "$(uname -s)" != Linux ]; then
	echo "build-css: only Linux is supported (use the Docker build on other systems)" >&2
	exit 1
fi

cache=${EDGE_CSS_CACHE:-.cache/css}
mkdir -p "$cache"

# fetch URL ファイル SHA-256: ファイルがなければ（または値が違えば）取得し、SHA-256 を確かめる。
fetch() {
	url=$1 file=$2 sum=$3
	if [ -f "$file" ] && echo "$sum  $file" | sha256sum -c --status; then
		return 0
	fi
	echo "build-css: downloading $url" >&2
	curl -fsSL --retry 3 -o "$file.tmp" "$url"
	if ! echo "$sum  $file.tmp" | sha256sum -c --status; then
		echo "build-css: checksum mismatch for $url" >&2
		rm -f "$file.tmp"
		exit 1
	fi
	mv "$file.tmp" "$file"
}

tailwind="$cache/tailwindcss-$TAILWIND_VERSION-$TAILWIND_ASSET"
daisyui="$cache/daisyui-$DAISYUI_VERSION.mjs"
fetch "https://github.com/tailwindlabs/tailwindcss/releases/download/$TAILWIND_VERSION/$TAILWIND_ASSET" "$tailwind" "$TAILWIND_SHA256"
fetch "https://github.com/saadeghi/daisyui/releases/download/$DAISYUI_VERSION/daisyui.mjs" "$daisyui" "$DAISYUI_SHA256"
chmod +x "$tailwind"

# app.input.css は同じディレクトリの daisyui.mjs を読む（.gitignore で管理の外）。
cp "$daisyui" internal/web/css/daisyui.mjs
"$tailwind" -i internal/web/css/app.input.css -o internal/web/static/app.css --minify
echo "build-css: wrote internal/web/static/app.css ($(wc -c <internal/web/static/app.css) bytes)" >&2
