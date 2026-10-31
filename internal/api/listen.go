package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/certs"
)

const shutdownTimeout = 10 * time.Second

// ListenOptions は管理API のリスナーの設定。
type ListenOptions struct {
	Addr string
	// GetCertificate はサーバー証明書を返す。
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Pins は管理クライアントのピン（SIGHUP で読み直す）。
	Pins    *Pins
	Handler http.Handler
	Log     *slog.Logger
}

// Run は管理API の HTTPS リスナー（mTLS）を起動し、ctx が終了するかリスナーが失敗するまで待つ（aka-provisioner の
// internal/server と同じ作り）。管理クライアントは、クライアント証明書のフィンガープリントで照合する（CA は使わない。§12.1）。
// 証明書なし・未登録・有効期間外の接続は、TLS のハンドシェイクで断る。
func Run(ctx context.Context, opts ListenOptions) error {
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", opts.Addr, err)
	}
	return Serve(ctx, ln, opts)
}

// Serve は ln で待ち受ける（opts.Addr は使わない）。
func Serve(ctx context.Context, ln net.Listener, opts ListenOptions) error {
	srv := &http.Server{
		Handler:           opts.Handler,
		TLSConfig:         TLSConfig(opts),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(opts.Log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	opts.Log.Info("listening", "addr", ln.Addr().String(), "admin_clients", opts.Pins.Fingerprints())
	select {
	case <-ctx.Done():
		opts.Log.Info("shutting down")
	case err := <-errc:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		opts.Log.Warn("shutdown", "error", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// TLSConfig は、管理クライアントの証明書をフィンガープリントで照合する TLS 設定を返す。
func TLSConfig(opts ListenOptions) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAnyClientCert,
		GetCertificate: opts.GetCertificate,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("client certificate required")
			}
			cert := cs.PeerCertificates[0]
			fp := certs.Fingerprint(cert)
			if _, ok := opts.Pins.lookup(fp); !ok {
				opts.Log.Warn("admin client certificate rejected", "event_id", "EDGE_AUTH_REJECTED", "reason", "not configured", "fingerprint", fp)
				return errors.New("client certificate is not a configured admin client")
			}
			if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				opts.Log.Warn("admin client certificate rejected", "event_id", "EDGE_AUTH_REJECTED", "reason", "outside validity period", "fingerprint", fp)
				return errors.New("client certificate is outside its validity period")
			}
			return nil
		},
	}
}
