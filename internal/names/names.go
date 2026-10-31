// Package names は、テナントと AP の名前の規則と、名前から決まる値（NAS-Identifier、CN、SAN、DNS の名前）を扱う
// （設計概要 §8.1）。
//
// 名前は radsecproxy の設定ファイルと正規表現に入るので、ここで検証したものだけを使う（§11.2）。
// 規則に合う名前は英小文字・数字・`-` だけからなり、設定ファイルの構文の記号や正規表現の記号を含まない。
package names

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// slugPattern はテナントの slug と AP の名前の規則（1〜32 文字。先頭と末尾は英小文字か数字）。
var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// labelPattern は DNS のラベルの規則（長さは別に確かめる）。
var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ProbeAP はヘルスチェック用に予約した AP の名前（§11.3）。利用者の AP には使わせない。
const ProbeAP = "probe"

// Slots は配置のスロットの名前（§8.3）。テナントのサーバー証明書の SAN には 3 つとも入れる。
var Slots = []string{"primary", "secondary", "tertiary"}

var (
	ErrSlug   = errors.New("英小文字・数字・- の 1〜32 文字で、先頭と末尾は英小文字か数字にしてください")
	ErrProbe  = fmt.Errorf("%q はヘルスチェック用に予約した名前なので使えません", ProbeAP)
	ErrPrefix = errors.New("URN の接頭辞は、英小文字・数字・- の 1〜32 文字で、先頭と末尾は英小文字か数字にしてください")
	ErrDomain = errors.New("ドメインは、英小文字・数字・- のラベルを . でつないだ名前（例 radsec.example.net）にしてください")
)

// ValidSlug は、テナントの slug（とテナントの ID）の規則に合うか。
func ValidSlug(s string) bool { return slugPattern.MatchString(s) }

// CheckTenant はテナントの slug を検証する。
func CheckTenant(slug string) error {
	if !ValidSlug(slug) {
		return ErrSlug
	}
	return nil
}

// CheckAP は利用者の AP の名前を検証する（予約した probe は断る）。
func CheckAP(name string) error {
	if !ValidSlug(name) {
		return ErrSlug
	}
	if name == ProbeAP {
		return ErrProbe
	}
	return nil
}

// CheckGroup はグループの名前を検証する（AP の名前と同じ規則。予約した probe は断る。§24.6）。
func CheckGroup(name string) error { return CheckAP(name) }

// CheckURNPrefix は SAN の URI の接頭辞（urn:<接頭辞>:nas:...）を検証する。
func CheckURNPrefix(p string) error {
	if !slugPattern.MatchString(p) {
		return ErrPrefix
	}
	return nil
}

// CheckDomain はサーバー証明書の SAN のドメイン（<スロット>.<テナント>.<ドメイン>）を検証する。
func CheckDomain(d string) error {
	if d == "" || len(d) > 200 {
		return ErrDomain
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return ErrDomain
	}
	for _, l := range labels {
		if len(l) > 63 || !labelPattern.MatchString(l) {
			return ErrDomain
		}
	}
	return nil
}

// NASIdentifier は AP の NAS-Identifier（<テナント>-<AP>）。AP の証明書の CN も同じ値にする。
// `-` が slug の中に入るので、NAS-Identifier だけからはテナントと AP の境目が決まらない（一意は呼び出し側で確かめる。§8.2）。
func NASIdentifier(tenant, ap string) string { return tenant + "-" + ap }

// SANURI は AP の証明書の SAN の URI（urn:<接頭辞>:nas:<テナント>:<AP>）。
func SANURI(prefix, tenant, ap string) string {
	return "urn:" + prefix + ":nas:" + tenant + ":" + ap
}

// GroupSANURI はグループの証明書の SAN の URI（urn:<接頭辞>:grp:<テナント>:<グループ>。§24.6）。
func GroupSANURI(prefix, tenant, group string) string {
	return "urn:" + prefix + ":grp:" + tenant + ":" + group
}

// SlotNames はテナントのスロットの DNS の名前（<スロット>.<テナント>.<ドメイン>）を Slots の順に返す。
func SlotNames(tenant, domain string) []string {
	out := make([]string, len(Slots))
	for i, s := range Slots {
		out[i] = s + "." + tenant + "." + domain
	}
	return out
}
