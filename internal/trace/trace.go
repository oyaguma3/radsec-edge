// Package trace はトレースID を扱う。
//
// エッジは画面の要求ごとにトレースID を採番してアクセスログと監査ログに残し、agent の呼び出しに
// X-Trace-ID ヘッダーで渡す（管理モードでは provisioner から受け取った値を使う）。
package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// Header はトレースID のヘッダー。
const Header = "X-Trace-ID"

// Valid は、受け取ったトレースID の形か（英数字と - の 1〜64 文字）。
func Valid(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
			return false
		}
	}
	return true
}

type key struct{}

// New はトレースID（16進32桁。provisioner が自分で採番する形式と同じ）を作る。
func New() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// With はトレースID をコンテキストに入れる。
func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, key{}, id)
}

// From はコンテキストに入れたトレースID を返す。入っていなければ空文字列。
func From(ctx context.Context) string {
	id, _ := ctx.Value(key{}).(string)
	return id
}
