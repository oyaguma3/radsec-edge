// Package probe は、テナントの radsecproxy のヘルスチェックを行う（設計概要 §11.3）。
//
// ヘルスチェック用の証明書（予約した AP の名前 probe）で RadSec（TLS）でつなぎ、Status-Server（RFC 5997）を送って、
// Access-Accept が返ることを確かめる。radsecproxy はクライアントからの Status-Server に自分で応える（上流には送らない。
// §18.1 の V5）。TLS のハンドシェイクが終わるだけでは足りない（証明書が client ブロックに一致しなくても、
// クライアントの側からは接続が確立したように見える）ので、応答まで待つ。
// サーバーの証明書は、テナントのサーバー証明書と同じものであることを確かめる（反映した証明書を読み込んだことの確かめ）。
package probe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// RADIUS の値。
const (
	codeAccessAccept = 2
	codeStatusServer = 12
	attrMessageAuth  = 80
	// secret は RadSec の共有シークレット（RFC 6614 の既定。radsecproxy の tls の client も既定でこの値）。
	secret = "radsec"
)

// Check は addr の radsecproxy にヘルスチェック用の証明書 cert でつなぎ、Status-Server に応えることを確かめる。
// サーバーの証明書は serverCert と同じでなければならない。
func Check(ctx context.Context, addr string, cert tls.Certificate, serverCert *x509.Certificate) error {
	d := tls.Dialer{Config: &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// サーバー証明書は名前と信頼の連鎖ではなく、テナントのサーバー証明書そのものと比べる（エッジはサーバーCA を持たない）。
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, serverCert.Raw) {
				return errors.New("the server presented a certificate other than the tenant's server certificate")
			}
			return nil
		},
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("probe: connect %s: %w", addr, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	req, err := statusServer()
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("probe: send Status-Server: %w", err)
	}
	resp, err := readPacket(conn)
	if err != nil {
		// 証明書が client ブロックに一致しないと、radsecproxy は応えずに接続を切る。
		return fmt.Errorf("probe: no response to Status-Server (the probe certificate may not match the configuration): %w", err)
	}
	return checkResponse(req, resp)
}

// statusServer は Message-Authenticator つきの Status-Server を作る。
func statusServer() ([]byte, error) {
	p := make([]byte, 20+18)
	p[0] = codeStatusServer
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	p[1] = id[0]
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	if _, err := rand.Read(p[4:20]); err != nil {
		return nil, err
	}
	p[20], p[21] = attrMessageAuth, 18
	m := hmac.New(md5.New, []byte(secret))
	m.Write(p)
	copy(p[22:], m.Sum(nil))
	return p, nil
}

func readPacket(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if n < 20 || n > 4096 {
		return nil, fmt.Errorf("invalid RADIUS length %d", n)
	}
	p := make([]byte, n)
	copy(p, hdr)
	if _, err := io.ReadFull(r, p[4:]); err != nil {
		return nil, err
	}
	return p, nil
}

// checkResponse は応答が要求への Access-Accept で、Response Authenticator が正しいことを確かめる。
func checkResponse(req, resp []byte) error {
	if resp[1] != req[1] {
		return fmt.Errorf("probe: response identifier %d does not match %d", resp[1], req[1])
	}
	h := md5.New()
	h.Write(resp[:4])
	h.Write(req[4:20])
	h.Write(resp[20:])
	h.Write([]byte(secret))
	if !hmac.Equal(h.Sum(nil), resp[4:20]) {
		return errors.New("probe: invalid Response Authenticator")
	}
	if resp[0] != codeAccessAccept {
		return fmt.Errorf("probe: unexpected response code %d to Status-Server", resp[0])
	}
	return nil
}
