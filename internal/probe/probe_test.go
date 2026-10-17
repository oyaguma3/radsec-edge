package probe

import (
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/oyaguma3/radsec-edge/internal/pki/pkitest"
)

// fakeServer は Status-Server に応える（または応えない）RadSec のサーバー。
func fakeServer(t *testing.T, serverCert tls.Certificate, respond func(req []byte) []byte) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAnyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := readPacket(c)
				if err != nil {
					return
				}
				if resp := respond(req); resp != nil {
					c.Write(resp)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// accept は req への Access-Accept を作る。
func accept(req []byte, code byte) []byte {
	resp := make([]byte, 20)
	resp[0], resp[1] = code, req[1]
	resp[2], resp[3] = 0, 20
	h := md5.New()
	h.Write(resp[:4])
	h.Write(req[4:20])
	h.Write([]byte(secret))
	copy(resp[4:], h.Sum(nil))
	return resp
}

func pair(t *testing.T, ca *pkitest.CA, server bool) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, keyPEM := pkitest.NewKeyPair(t)
	c, certPEM := ca.Issue(t, pkitest.Leaf{CN: "x", DNS: []string{"localhost"}, Server: server}, key.Public())
	tc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tc, c
}

func TestCheck(t *testing.T) {
	ca := pkitest.NewCA(t, "ca")
	srv, srvCert := pair(t, ca, true)
	client, _ := pair(t, ca, false)
	ctx := t.Context()

	ok := fakeServer(t, srv, func(req []byte) []byte {
		if req[0] != codeStatusServer || req[20] != attrMessageAuth {
			return nil
		}
		return accept(req, codeAccessAccept)
	})
	if err := Check(ctx, ok, client, srvCert); err != nil {
		t.Fatalf("Check = %v", err)
	}

	// 別のサーバー証明書（反映した証明書を読み込んでいない）。
	_, otherCert := pair(t, ca, true)
	if err := Check(ctx, ok, client, otherCert); err == nil {
		t.Error("other server certificate accepted")
	}
	// 応えずに切る（証明書が client ブロックに一致しないとき）。
	silent := fakeServer(t, srv, func([]byte) []byte { return nil })
	if err := Check(ctx, silent, client, srvCert); err == nil || !strings.Contains(err.Error(), "no response") {
		t.Errorf("silent: %v", err)
	}
	// Access-Reject。
	reject := fakeServer(t, srv, func(req []byte) []byte { return accept(req, 3) })
	if err := Check(ctx, reject, client, srvCert); err == nil {
		t.Error("reject accepted")
	}
	// Response Authenticator の誤り。
	bad := fakeServer(t, srv, func(req []byte) []byte {
		r := accept(req, codeAccessAccept)
		r[4] ^= 1
		return r
	})
	if err := Check(ctx, bad, client, srvCert); err == nil {
		t.Error("bad authenticator accepted")
	}
	// つながらない。
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if err := Check(ctx, addr, client, srvCert); err == nil {
		t.Error("closed port accepted")
	}
}
