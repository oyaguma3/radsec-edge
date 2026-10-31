// fakeupstream は結合の試験で使う偽の上流（aka-radius の代わり）。UDP の 1812 と 1813 で RADIUS を受け、受け取った要求の属性を標準出力に書いて、
// 成功の応答を返す（radsecproxy の statusServer にも応える。Accounting の応答に Message-Authenticator は付けない）。共有シークレットは upsecret-123。
package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const secret = "upsecret-123"

func main() {
	done := make(chan struct{})
	for _, port := range []int{1812, 1813} {
		go serve(port)
	}
	<-done
}

func serve(port int) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 4096)
	for {
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil || n < 20 {
			continue
		}
		req := buf[:n]
		if req[0] != 12 { // Status-Server は記録しない
			fmt.Println(describe(req))
		}
		c.WriteToUDP(reply(req), addr)
	}
}

// describe は要求の属性を 1 行にする: REQ code=<番号> user=<値> nas=<値> stamps=<値,...> othervendors=<数>
func describe(p []byte) string {
	var user, nas string
	var stamps []string
	others := 0
	for a := p[20:]; len(a) >= 2 && int(a[1]) >= 2 && int(a[1]) <= len(a); a = a[a[1]:] {
		v := a[2:a[1]]
		switch a[0] {
		case 1:
			user = string(v)
		case 32:
			nas = string(v)
		case 26:
			if len(v) >= 6 && binary.BigEndian.Uint32(v) == 32473 && v[4] == 1 {
				stamps = append(stamps, string(v[6:]))
			} else {
				others++
			}
		}
	}
	return fmt.Sprintf("REQ code=%d user=%s nas=%s stamps=%s othervendors=%d", p[0], user, nas, strings.Join(stamps, ","), others)
}

// reply は成功の応答を作る（Message-Authenticator つき）。
func reply(req []byte) []byte {
	code := byte(2)
	if req[0] == 4 {
		code = 5
	}
	out := make([]byte, 20, 38)
	out[0], out[1] = code, req[1]
	copy(out[4:20], req[4:20])
	if req[0] != 4 {
		out = append(out, 80, 18)
		out = append(out, make([]byte, 16)...)
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	if req[0] != 4 {
		m := hmac.New(md5.New, []byte(secret))
		m.Write(out)
		copy(out[22:38], m.Sum(nil))
	}
	h := md5.New()
	h.Write(out)
	h.Write([]byte(secret))
	copy(out[4:20], h.Sum(nil))
	return out
}
