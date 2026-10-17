package rsconf

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/names"
)

// テナントのディレクトリの中の名前（設計概要 §10.2）。
const (
	// GenDir は版のディレクトリを置くディレクトリ。
	GenDir = "gen"
	// CurrentLink は今の版のディレクトリを指すシンボリックリンク（相対パス gen/<版>）。
	CurrentLink = "current"
)

// ファイルとディレクトリの権限。radsecproxy（10083:10083）はグループで読む（§10.2）。
const (
	dirMode  fs.FileMode = 0o750
	fileMode fs.FileMode = 0o640
)

// genPattern は版の名前（バンドルのハッシュの先頭 16 桁）。
var genPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ValidGen は版の名前の形か（agent が受け取った値を確かめるのにも使う）。
func ValidGen(gen string) bool { return genPattern.MatchString(gen) }

// GenName はバンドルの版の名前。
func GenName(b Bundle) string { return b.Hash()[:16] }

// Store は、テナントのディレクトリ（<Root>/<slug>/）を扱う。radsecproxy のコンテナは <Root>/<slug> を /conf にマウントし、
// /conf/current（current が指す版のディレクトリ）のファイルを読む。bind mount の元のディレクトリを差し替えても
// 動いているコンテナには見えないので、リンクを付け替える（§21.2 の 1）。
type Store struct {
	Root string
}

func (s Store) dir(slug string) (string, error) {
	if !names.ValidSlug(slug) {
		return "", fmt.Errorf("tenant dir: invalid slug %q", slug)
	}
	return filepath.Join(s.Root, slug), nil
}

// GenPath は版のディレクトリのパスを返す。
func (s Store) GenPath(slug, gen string) (string, error) {
	d, err := s.dir(slug)
	if err != nil {
		return "", err
	}
	if !ValidGen(gen) {
		return "", fmt.Errorf("tenant dir: invalid generation %q", gen)
	}
	return filepath.Join(d, GenDir, gen), nil
}

// Current は今の版の名前とバンドルを返す。まだ版がなければ "" と nil を返す。
func (s Store) Current(slug string) (string, Bundle, error) {
	d, err := s.dir(slug)
	if err != nil {
		return "", nil, err
	}
	target, err := os.Readlink(filepath.Join(d, CurrentLink))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("read current of %s: %w", slug, err)
	}
	gen, ok := strings.CutPrefix(target, GenDir+"/")
	if !ok || !ValidGen(gen) {
		return "", nil, fmt.Errorf("current of %s points to an unexpected place %q", slug, target)
	}
	b, err := s.Read(slug, gen)
	if err != nil {
		return "", nil, err
	}
	return gen, b, nil
}

// Read は版のディレクトリのバンドルを読む。
func (s Store) Read(slug, gen string) (Bundle, error) {
	p, err := s.GenPath(slug, gen)
	if err != nil {
		return nil, err
	}
	b := Bundle{}
	for _, f := range Files {
		data, err := os.ReadFile(filepath.Join(p, f))
		if err != nil {
			return nil, fmt.Errorf("read generation %s of %s: %w", gen, slug, err)
		}
		b[f] = data
	}
	return b, nil
}

// Stage はバンドルを版のディレクトリ（gen/<版>）に書き、版の名前を返す。同じ中身の版があれば、それを使う。
// 書きかけのディレクトリが残らないよう、一時的な名前で書いてから rename する。
func (s Store) Stage(slug string, b Bundle) (string, error) {
	d, err := s.dir(slug)
	if err != nil {
		return "", err
	}
	for _, f := range Files {
		if _, ok := b[f]; !ok {
			return "", fmt.Errorf("stage %s: bundle has no %s", slug, f)
		}
	}
	gen := GenName(b)
	genRoot := filepath.Join(d, GenDir)
	if err := mkdirs(s.Root, d, genRoot); err != nil {
		return "", err
	}
	final := filepath.Join(genRoot, gen)
	if old, err := s.Read(slug, gen); err == nil && old.Hash() == b.Hash() {
		// 使った時刻を新しくする（古い版を消すときに、最近使った版を残すため）。
		now := time.Now()
		os.Chtimes(final, now, now)
		return gen, nil
	}
	os.RemoveAll(final) // 壊れた（途中まで書いた）版があれば作り直す
	var rnd [6]byte
	rand.Read(rnd[:])
	tmp := filepath.Join(genRoot, ".tmp-"+gen+"-"+hex.EncodeToString(rnd[:]))
	if err := os.Mkdir(tmp, dirMode); err != nil {
		return "", fmt.Errorf("stage %s: %w", slug, err)
	}
	if err := writeFiles(tmp, b); err != nil {
		os.RemoveAll(tmp)
		return "", fmt.Errorf("stage %s: %w", slug, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.RemoveAll(tmp)
		return "", fmt.Errorf("stage %s: %w", slug, err)
	}
	return gen, syncDir(genRoot)
}

func mkdirs(dirs ...string) error {
	for _, d := range dirs {
		if err := os.Mkdir(d, dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

func writeFiles(dir string, b Bundle) error {
	for _, f := range Files {
		p := filepath.Join(dir, f)
		fh, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
		if err != nil {
			return err
		}
		_, err = fh.Write(b[f])
		if err == nil {
			err = fh.Sync()
		}
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		// umask で権限が狭まっても、グループが読めるようにする。
		if err := os.Chmod(p, fileMode); err != nil {
			return err
		}
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Activate は current を版 gen に付け替える（新しいリンクを作ってから rename するので、原子的に変わる）。
func (s Store) Activate(slug, gen string) error {
	p, err := s.GenPath(slug, gen)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("activate %s: %w", slug, err)
	}
	d := filepath.Dir(filepath.Dir(p))
	tmp := filepath.Join(d, ".current-tmp")
	os.Remove(tmp)
	if err := os.Symlink(GenDir+"/"+gen, tmp); err != nil {
		return fmt.Errorf("activate %s: %w", slug, err)
	}
	if err := os.Rename(tmp, filepath.Join(d, CurrentLink)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("activate %s: %w", slug, err)
	}
	return syncDir(d)
}

// Prune は、今の版と、使った時刻の新しい版を合わせて keep 個を残し、ほかの版のディレクトリを消す（§10.2）。
// 書きかけの一時的なディレクトリも消す。
func (s Store) Prune(slug string, keep int) error {
	d, err := s.dir(slug)
	if err != nil {
		return err
	}
	cur, _, err := s.Current(slug)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(d, GenDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	type gen struct {
		name string
		mod  time.Time
	}
	var gens []gen
	var errs []error
	for _, e := range entries {
		p := filepath.Join(d, GenDir, e.Name())
		if strings.HasPrefix(e.Name(), ".tmp-") {
			errs = append(errs, os.RemoveAll(p))
			continue
		}
		if !ValidGen(e.Name()) || e.Name() == cur {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		gens = append(gens, gen{e.Name(), info.ModTime()})
	}
	slices.SortFunc(gens, func(a, b gen) int { return b.mod.Compare(a.mod) })
	rest := keep
	if cur != "" {
		rest--
	}
	for i, g := range gens {
		if i < rest {
			continue
		}
		errs = append(errs, os.RemoveAll(filepath.Join(d, GenDir, g.name)))
	}
	return errors.Join(errs...)
}

// Remove はテナントのディレクトリを消す（テナントを消したとき）。
func (s Store) Remove(slug string) error {
	d, err := s.dir(slug)
	if err != nil {
		return err
	}
	return os.RemoveAll(d)
}

// Slugs は、ディレクトリのあるテナントの slug を返す（消したテナントのディレクトリの片付けに使う）。
func (s Store) Slugs() ([]string, error) {
	entries, err := os.ReadDir(s.Root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && names.ValidSlug(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
