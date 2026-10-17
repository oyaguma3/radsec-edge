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
