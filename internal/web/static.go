package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
	"sync"
)

// staticFiles は static/ のファイルを配信する。
// embed のファイルには更新時刻がないので、内容のハッシュを ETag にして再検証させる。
type staticFiles struct {
	files    http.Handler
	etags    map[string]string
	notFound http.Handler
}

// staticHashes は static/ の各ファイルの内容のハッシュ（16 進 32 桁）。ETag と、画面から参照する URL の版（assetURL）に使う。
var staticHashes = sync.OnceValues(func() (map[string]string, error) {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	hashes := map[string]string{}
	err = fs.WalkDir(sub, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(sub, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:16])
		return nil
	})
	return hashes, err
})

// assetURL は、画面から参照する静的ファイルの URL に内容のハッシュを付けたもの（例 /static/app.css?v=…）を返す。
// 内容が変われば URL も変わるので、途中のキャッシュ（Cloudflare のエッジやブラウザ）に古い版が残っていても使われない
// （eapaka-ossbss-sample で、Access を通したときに古い CSS が使われて画面が崩れたため）。
func assetURL(name string) string {
	hashes, _ := staticHashes()
	if h, ok := hashes[name]; ok {
		return "/static/" + name + "?v=" + h[:12]
	}
	return "/static/" + name
}

func newStaticFiles(notFound http.Handler) (*staticFiles, error) {
	hashes, err := staticHashes()
	if err != nil {
		return nil, err
	}
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	etags := make(map[string]string, len(hashes))
	for name, h := range hashes {
		etags[name] = `"` + h + `"`
	}
	return &staticFiles{files: http.FileServerFS(sub), etags: etags, notFound: notFound}, nil
}

func (s *staticFiles) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	etag, ok := s.etags[name]
	if !ok {
		// ディレクトリの一覧は返さない。
		s.notFound.ServeHTTP(w, r)
		return
	}
	// http.FileServer は ETag ヘッダーがあれば If-None-Match を見て 304 を返す。
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/" + name
	s.files.ServeHTTP(w, r2)
}
