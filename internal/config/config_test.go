package config

import (
	"strings"
	"testing"
	"time"
)

func setBase(t *testing.T) {
	t.Helper()
	t.Setenv("EDGE_URN_PREFIX", "example")
	t.Setenv("EDGE_DNS_DOMAIN", "radsec.example.net")
	t.Setenv("EDGE_UPSTREAM_SECRET", "upsecret-1234")
	t.Setenv("EDGE_GUI_ADDR", "127.0.0.1:8447")
	t.Setenv("EDGE_DEV_USER_EMAIL", "dev@example.com")
}

func TestLoadDefaults(t *testing.T) {
	setBase(t)
	t.Setenv("EDGE_UPSTREAM_AUTH", "10.0.0.10:1812")
	t.Setenv("EDGE_UPSTREAM_ACCT", "[::ffff:10.0.0.10]:1813")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeStandalone || c.DataDir != "/data" || c.TenantsDir != "/var/lib/radsec-edge/tenants" {
		t.Errorf("defaults: %+v", c)
	}
	if c.CRLInterval != 5*time.Minute || c.CRLWarn != 72*time.Hour || c.ReconcileInterval != time.Minute {
		t.Errorf("durations: %+v", c)
	}
	if c.Upstream.Auth.String() != "10.0.0.10:1812" || c.Upstream.Acct.String() != "10.0.0.10:1813" {
		t.Errorf("upstream: %v %v", c.Upstream.Auth, c.Upstream.Acct)
	}
	if !c.DevMode() {
		t.Error("DevMode = false")
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		env, value, want string
	}{
		{"EDGE_MODE", "managed", "not implemented"},
		{"EDGE_MODE", "x", "EDGE_MODE"},
		{"EDGE_URN_PREFIX", "ex:ample", "EDGE_URN_PREFIX"},
		{"EDGE_DNS_DOMAIN", "*.example.net", "EDGE_DNS_DOMAIN"},
		{"EDGE_UPSTREAM_SECRET", "short", "EDGE_UPSTREAM_SECRET"},
		{"EDGE_UPSTREAM_SECRET", "has space in it", "EDGE_UPSTREAM_SECRET"},
		{"EDGE_UPSTREAM_SECRET", "has\"quote1", "EDGE_UPSTREAM_SECRET"},
		{"EDGE_UPSTREAM_AUTH", "upstream:1812", "host names are not allowed"},
		{"EDGE_UPSTREAM_AUTH", "0.0.0.0:1812", "EDGE_UPSTREAM_AUTH"},
		{"EDGE_UPSTREAM_AUTH", "10.0.0.1", "EDGE_UPSTREAM_AUTH"},
		{"EDGE_CRL_BASE_URL", "ftp://x", "EDGE_CRL_BASE_URL"},
		{"EDGE_CRL_INTERVAL", "1s", "EDGE_CRL_INTERVAL"},
		{"EDGE_GUI_ADDR", ":8447", "loopback"},
		{"EDGE_ACCESS_AUD", "aud", "cannot be used with"},
		{"EDGE_DATA_DIR", "data", "EDGE_DATA_DIR"},
	}
	for _, tc := range cases {
		t.Run(tc.env+"="+tc.value, func(t *testing.T) {
			setBase(t)
			t.Setenv(tc.env, tc.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load() = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadAccess(t *testing.T) {
	setBase(t)
	t.Setenv("EDGE_DEV_USER_EMAIL", "")
	t.Setenv("EDGE_GUI_ADDR", ":8447")
	t.Setenv("EDGE_ACCESS_TEAM_DOMAIN", "Example.cloudflareaccess.com")
	t.Setenv("EDGE_ACCESS_AUD", "a, b")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessTeamDomain != "example.cloudflareaccess.com" || len(c.AccessAUDs) != 2 || c.DevMode() {
		t.Errorf("access: %+v", c)
	}
	t.Setenv("EDGE_ACCESS_AUD", "")
	if _, err := Load(); err == nil {
		t.Error("Load() without AUD = nil")
	}
}

func TestLoadAgent(t *testing.T) {
	a, err := LoadAgent()
	if err != nil {
		t.Fatal(err)
	}
	if a.Network != "radsec-edge-tenants" || a.SocketGID != 10083 || a.DockerSocket != "/var/run/docker.sock" {
		t.Errorf("defaults: %+v", a)
	}
	t.Setenv("EDGE_AGENT_NETWORK", "bad name")
	if _, err := LoadAgent(); err == nil {
		t.Error("LoadAgent() with a bad network = nil")
	}
}
