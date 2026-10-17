// Command fakeradius は、段階 0 の実機の検証で上流（本PoC の代わり）に置く RADIUS サーバー（設計概要 §18）。
// Access-Request はすべて Access-Accept、Accounting-Request は Accounting-Response、Status-Server は Access-Accept で応える。
// 届いた要求の送信元・NAS-Identifier・User-Name を 1 行のログに出す（NAS-Identifier の置き換えを確かめるため）。
package main

import (
	"crypto/hmac"
	"crypto/md5"
	"flag"
	"log"
	"net"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
)

func main() {
	secret := flag.String("secret", "", "共有シークレット")
	authAddr := flag.String("auth", ":1812", "認証の待ち受け")
	acctAddr := flag.String("acct", ":1813", "課金の待ち受け")
	flag.Parse()
	if *secret == "" {
		log.Fatal("-secret が要る")
	}
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	h := &handler{secret: []byte(*secret)}
	ss := radius.StaticSecretSource([]byte(*secret))
	for _, addr := range []string{*authAddr, *acctAddr} {
		srv := &radius.PacketServer{Addr: addr, Handler: h, SecretSource: ss}
		go func() { log.Fatal(srv.ListenAndServe()) }()
	}
	log.Printf("fakeradius: 待ち受け auth=%s acct=%s", *authAddr, *acctAddr)
	select {}
}

type handler struct{ secret []byte }

func (h *handler) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	src := r.RemoteAddr.(*net.UDPAddr).IP.String()
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	user := rfc2865.UserName_GetString(r.Packet)
	var respCode radius.Code
	switch r.Code {
	case radius.CodeAccessRequest:
		respCode = radius.CodeAccessAccept
	case radius.CodeStatusServer:
		respCode = radius.CodeAccessAccept
	case radius.CodeAccountingRequest:
		respCode = radius.CodeAccountingResponse
	default:
		log.Printf("recv code=%v src=%s 応答しない", r.Code, src)
		return
	}
	extra := ""
	if r.Code == radius.CodeAccountingRequest {
		extra = " acct_status=" + rfc2866.AcctStatusType_Get(r.Packet).String()
	}
	log.Printf("recv code=%v src=%s nas_id=%q user=%q nas_id_count=%d%s", r.Code, src, nasID, user, countAttr(r.Packet, rfc2865.NASIdentifier_Type), extra)

	resp := r.Response(respCode)
	if respCode == radius.CodeAccessAccept {
		rfc2865.ReplyMessage_SetString(resp, "accepted nas_id="+nasID)
		setMessageAuthenticator(resp, h.secret, r.Authenticator)
	}
	if err := w.Write(resp); err != nil {
		log.Printf("応答の送信に失敗: %v", err)
	}
}

// countAttr は属性の個数を数える（NAS-Identifier が 1 つだけになったかを確かめるため）。
func countAttr(p *radius.Packet, t radius.Type) int {
	n := 0
	for _, a := range p.Attributes {
		if a.Type == t {
			n++
		}
	}
	return n
}

// setMessageAuthenticator は応答に Message-Authenticator を付ける（RFC 3579。本PoC の auth-server と同じ計算）。
func setMessageAuthenticator(p *radius.Packet, secret []byte, requestAuth [16]byte) {
	_ = rfc2869.MessageAuthenticator_Set(p, make([]byte, 16))
	saved := p.Authenticator
	p.Authenticator = requestAuth
	data, err := p.MarshalBinary()
	p.Authenticator = saved
	if err != nil {
		return
	}
	mac := hmac.New(md5.New, secret)
	mac.Write(data)
	_ = rfc2869.MessageAuthenticator_Set(p, mac.Sum(nil))
}
