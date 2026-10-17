// Package keystore は、エッジで作る鍵（テナントのサーバー証明書とヘルスチェック用の証明書の鍵）をファイルに置く
// （設計概要 §7.1、§9.2。鍵はエッジの外に出さない）。
//
// 置き場所は <Dir>/<テナントの ID>/<種類>.key（今の鍵）と <種類>.pending.key（CSR を出して、証明書を待っている鍵）。
// CSR を出し直すと、待っている鍵を作り直す。署名済みの証明書を取り込むと、待っている鍵を今の鍵にする。
package keystore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/oyaguma3/radsec-edge/internal/names"
	"github.com/oyaguma3/radsec-edge/internal/pki"
)

// Kind は鍵の種類。
type Kind string

const (
	Server Kind = "server"
	Probe  Kind = "probe"
)

// Store は鍵のファイルの置き場所。
type Store struct {
	Dir string
}

func (s Store) path(id string, k Kind, pending bool) (string, error) {
	if !names.ValidSlug(id) || (k != Server && k != Probe) {
		return "", fmt.Errorf("keystore: invalid tenant %q or kind %q", id, k)
	}
	name := string(k) + ".key"
	if pending {
		name = string(k) + ".pending.key"
	}
	return filepath.Join(s.Dir, id, name), nil
}

func (s Store) read(id string, k Kind, pending bool) ([]byte, error) {
	p, err := s.path(id, k, pending)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Current は今の鍵（PEM）を返す。なければ nil。
func (s Store) Current(id string, k Kind) ([]byte, error) { return s.read(id, k, false) }

// Pending は証明書を待っている鍵（PEM）を返す。なければ nil。
func (s Store) Pending(id string, k Kind) ([]byte, error) { return s.read(id, k, true) }

// NewPending は鍵を作り、証明書を待っている鍵として置いて返す（前の待っている鍵は捨てる）。
func (s Store) NewPending(id string, k Kind) ([]byte, error) {
	p, err := s.path(id, k, true)
	if err != nil {
		return nil, err
	}
	key, err := pki.NewKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return key, nil
}

// Promote は、証明書を待っている鍵を今の鍵にする。
func (s Store) Promote(id string, k Kind) error {
	from, err := s.path(id, k, true)
	if err != nil {
		return err
	}
	to, _ := s.path(id, k, false)
	return os.Rename(from, to)
}

// Remove はテナントの鍵をすべて消す（テナントを消したとき）。
func (s Store) Remove(id string) error {
	if !names.ValidSlug(id) {
		return fmt.Errorf("keystore: invalid tenant %q", id)
	}
	return os.RemoveAll(filepath.Join(s.Dir, id))
}
