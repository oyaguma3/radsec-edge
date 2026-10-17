package agent

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oyaguma3/radsec-edge/internal/trace"
)

// Client は radsec-edge から agent を呼ぶクライアント。
type Client struct {
	hc *http.Client
}

// NewClient は unix ソケット socket の agent のクライアントを作る。
func NewClient(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	// 構文検査（捨てるコンテナ）と再起動に時間がかかるので、上限は長めにする（呼び出し側の ctx でも切る）。
	return &Client{hc: &http.Client{Transport: tr, Timeout: 2 * time.Minute}}
}

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if id := trace.From(ctx); id != "" {
		req.Header.Set("X-Trace-ID", id)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("agent: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e errorBody
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if json.Unmarshal(b, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(b))
		}
		return &Error{Status: resp.StatusCode, Message: e.Error}
	}
	if out == nil {
		return nil
	}
	return json.UnmarshalRead(io.LimitReader(resp.Body, 8<<20), out)
}

func tenantPath(id, op string) string { return "/v1/tenants/" + url.PathEscape(id) + "/" + op }

// Status は agent と Docker とテナントのコンテナの状態を返す。
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.call(ctx, http.MethodGet, "/v1/status", nil, &st)
	return st, err
}

// Ensure はテナントのコンテナを作る・起動する（あって動いていれば何もしない）。行ったことを返す。
func (c *Client) Ensure(ctx context.Context, id, slug string, port int) (string, error) {
	var res EnsureResult
	err := c.call(ctx, http.MethodPost, tenantPath(id, "ensure"), EnsureRequest{Slug: slug, Port: port}, &res)
	return res.Action, err
}

// Restart はテナントのコンテナを再起動する。
func (c *Client) Restart(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodPost, tenantPath(id, "restart"), nil, nil)
}

// Stop はテナントのコンテナを止める。
func (c *Client) Stop(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodPost, tenantPath(id, "stop"), nil, nil)
}

// Remove はテナントのコンテナを消す。
func (c *Client) Remove(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodPost, tenantPath(id, "remove"), nil, nil)
}

// SIGHUP はテナントのコンテナに SIGHUP を送る（CA と CRL の読み直し）。
func (c *Client) SIGHUP(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodPost, tenantPath(id, "signal"), SignalRequest{Signal: "HUP"}, nil)
}

// Logs はテナントのコンテナのログの末尾 lines 行を返す。
func (c *Client) Logs(ctx context.Context, id string, lines int) (string, error) {
	var res LogsResult
	err := c.call(ctx, http.MethodGet, tenantPath(id, "logs")+"?lines="+strconv.Itoa(lines), nil, &res)
	return res.Logs, err
}

// Validate はテナントの版 gen の設定を radsecproxy -p で検査する。
func (c *Client) Validate(ctx context.Context, slug, gen string) (ValidateResult, error) {
	var res ValidateResult
	err := c.call(ctx, http.MethodPost, "/v1/validate", ValidateRequest{Slug: slug, Gen: gen}, &res)
	return res, err
}
