// Package docker は Docker Engine API の必要な口だけを、unix ソケットへの HTTP で呼ぶ（設計概要 §4。公式の SDK は使わない）。
// agent だけが使う。
package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// apiVersion は使う Engine API の版。Docker 29 が受け付ける最も古い版（1.44）より新しく、
// HostConfig.Init などの使う項目がそろっている版にする。
const apiVersion = "v1.47"

// ErrNotFound は対象（コンテナ、イメージ、ネットワーク）がないことを表す。
var ErrNotFound = errors.New("docker: not found")

// Client は Docker Engine の API のクライアント。
type Client struct {
	hc *http.Client
}

// New は unix ソケット socket の Docker Engine のクライアントを作る。
func New(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{hc: &http.Client{Transport: tr}}
}

// apiError は Engine API のエラーの応答。
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("docker: %d %s", e.Status, e.Message) }

func (e *apiError) Is(target error) bool { return target == ErrNotFound && e.Status == http.StatusNotFound }

// do は要求を送り、2xx と 304 以外はエラーにする。out が nil でなければ応答の JSON を読む。
func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	resp, err := c.send(ctx, method, path, q, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.UnmarshalRead(io.LimitReader(resp.Body, 16<<20), out)
}

func (c *Client) send(ctx context.Context, method, path string, q url.Values, in any) (*http.Response, error) {
	u := "http://docker/" + apiVersion + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker: %s %s: %w", method, path, err)
	}
	if resp.StatusCode/100 == 2 || resp.StatusCode == http.StatusNotModified {
		return resp, nil
	}
	defer resp.Body.Close()
	var e struct {
		Message string `json:"message"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if json.Unmarshal(b, &e) != nil || e.Message == "" {
		e.Message = strings.TrimSpace(string(b))
	}
	return nil, &apiError{Status: resp.StatusCode, Message: e.Message}
}

// Ping は Engine に接続できることを確かめる。
func (c *Client) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/_ping", nil, nil, nil)
}

// Summary はコンテナの一覧の 1 件。
type Summary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
	State  string            `json:"State"`
}

// List は、ラベル label（"名前" または "名前=値"）の付いたコンテナを、止まっているものも含めて返す。
func (c *Client) List(ctx context.Context, label string) ([]Summary, error) {
	filters, err := json.Marshal(map[string][]string{"label": {label}})
	if err != nil {
		return nil, err
	}
	var out []Summary
	err = c.do(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(filters)}}, nil, &out)
	return out, err
}

// Inspect はコンテナの詳しい状態。
type Inspect struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Restarting bool   `json:"Restarting"`
		ExitCode   int    `json:"ExitCode"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Error      string `json:"Error"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// InspectContainer はコンテナの状態を返す。なければ ErrNotFound。
func (c *Client) InspectContainer(ctx context.Context, id string) (Inspect, error) {
	var out Inspect
	err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out)
	return out, err
}

// Create はコンテナを作り、ID を返す。spec は Engine API の ContainerCreate の本文。
func (c *Client) Create(ctx context.Context, name string, spec any) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	err := c.do(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, spec, &out)
	return out.ID, err
}

// Start はコンテナを起動する（動いていれば何もしない）。
func (c *Client) Start(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}

// Stop はコンテナを止める（猶予 timeout の後に SIGKILL）。止まっていれば何もしない。
func (c *Client) Stop(ctx context.Context, id string, timeout time.Duration) error {
	return c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop",
		url.Values{"t": {strconv.Itoa(int(timeout.Seconds()))}}, nil, nil)
}

// Restart はコンテナを再起動する。
func (c *Client) Restart(ctx context.Context, id string, timeout time.Duration) error {
	return c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/restart",
		url.Values{"t": {strconv.Itoa(int(timeout.Seconds()))}}, nil, nil)
}

// Kill はコンテナにシグナルを送る。
func (c *Client) Kill(ctx context.Context, id, signal string) error {
	return c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/kill", url.Values{"signal": {signal}}, nil, nil)
}

// Remove はコンテナを消す（動いていれば止めて消す）。なければ ErrNotFound。
func (c *Client) Remove(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id), url.Values{"force": {"1"}}, nil, nil)
}

// Wait はコンテナが止まるまで待ち、終了コードを返す。
func (c *Client) Wait(ctx context.Context, id string) (int, error) {
	var out struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	if err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait", url.Values{"condition": {"not-running"}}, nil, &out); err != nil {
		return 0, err
	}
	if out.Error != nil && out.Error.Message != "" {
		return out.StatusCode, fmt.Errorf("docker: wait: %s", out.Error.Message)
	}
	return out.StatusCode, nil
}

// Logs はコンテナのログ（標準出力と標準エラー）の末尾 tail 行を返す。maxBytes を超える分は読まない。
func (c *Client) Logs(ctx context.Context, id string, tail, maxBytes int) (string, error) {
	resp, err := c.send(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs",
		url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {strconv.Itoa(tail)}}, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return demux(io.LimitReader(resp.Body, int64(maxBytes)+8*1024))
}

// demux は、TTY のないコンテナのログの多重化された流れ（8 バイトの見出しと中身の繰り返し）から中身を取り出す。
// 最後の枠が途中で切れていたら、読めたところまでを返す。
func demux(r io.Reader) (string, error) {
	var out strings.Builder
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return out.String(), nil
			}
			return out.String(), err
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		if _, err := io.CopyN(&out, r, n); err != nil {
			if errors.Is(err, io.EOF) {
				return out.String(), nil
			}
			return out.String(), err
		}
	}
}

// ImageExists はイメージがあるか。ref（例 radsec-edge/radsecproxy:1.11.2-1-deb13u1）は / を含むのでエスケープしない
// （呼び出し側が決まった値だけを渡す）。
func (c *Client) ImageExists(ctx context.Context, ref string) (bool, error) {
	err := c.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// NetworkExists はネットワークがあるか。
func (c *Client) NetworkExists(ctx context.Context, name string) (bool, error) {
	err := c.do(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
