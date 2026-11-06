package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const testConfig = `
[unifi]
host = "%HOST%"
user = "testuser"
password = "testpassword"
insecure = true

[output]
groups = [ { name="Blocked", type="ipv4" } ]
`

func TestLoadConfigReadsInsecure(t *testing.T) {
	config, err := loadConfig(writeConfig(t, strings.ReplaceAll(testConfig, "%HOST%", "https://localhost")))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Unifi.Insecure {
		t.Error("expected insecure to be decoded as true")
	}
}

func TestLoadConfigRejectsCleartextHost(t *testing.T) {
	_, err := loadConfig(writeConfig(t, strings.ReplaceAll(testConfig, "%HOST%", "http://localhost")))
	if err == nil {
		t.Error("expected an http:// host to be rejected")
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := map[string]bool{
		"8.8.8.8":              true,
		"2606:4700:4700::1111": true,
		"0.0.0.0":              false,
		"::":                   false,
		"127.0.0.1":            false,
		"::1":                  false,
		"10.0.0.1":             false,
		"192.168.1.1":          false,
		"fd00::1":              false,
		"169.254.1.1":          false,
		"fe80::1":              false,
		"224.0.0.1":            false,
	}
	for addr, want := range tests {
		if got := isPublicIP(net.ParseIP(addr)); got != want {
			t.Errorf("isPublicIP(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestCreateHostList(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Dns.Example\r\nother.example\n"))
	}))
	defer good.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server exploded", http.StatusInternalServerError)
	}))
	defer broken.Close()

	hosts, err := createHostList([]string{good.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(hosts, "dns.example") || !slices.Contains(hosts, "other.example") {
		t.Errorf("unexpected hosts: %v", hosts)
	}

	// One bad list must fail the run, not produce a partial result
	if _, err := createHostList([]string{good.URL, broken.URL}); err == nil {
		t.Error("expected an HTTP error status to fail")
	}
	if _, err := createHostList([]string{good.URL, filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("expected a missing file to fail")
	}
}

func TestFindGroup(t *testing.T) {
	groups := []UnifiFirewallGroup{{Name: "Blocked"}}

	if group, err := findGroup(groups, "Blocked"); err != nil || group == nil {
		t.Errorf("expected group to be found, got %v, %v", group, err)
	}
	if group, err := findGroup(groups, ""); err != nil || group != nil {
		t.Errorf("expected an unconfigured group to be skipped, got %v, %v", group, err)
	}
	if _, err := findGroup(groups, "Missing"); err == nil {
		t.Error("expected a missing group to fail")
	}
}

func TestUpdateGroupRefusesToEmpty(t *testing.T) {
	if err := updateGroup("https://unused", &UnifiFirewallGroup{Name: "Blocked"}, nil); err == nil {
		t.Error("expected an empty address list to fail")
	}
	if err := updateGroup("https://unused", nil, nil); err != nil {
		t.Errorf("expected an unconfigured group to be skipped: %v", err)
	}
}

// fakeController serves just enough of the Unifi API for run() and records
// the members of every firewall group update it receives.
func fakeController(t *testing.T, groupName string) (*httptest.Server, *[][]string) {
	t.Helper()
	updates := &[][]string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/auth/login":
			w.Header().Set("X-CSRF-Token", "csrf")
			http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session"})
			w.Write([]byte(`{}`))
		case r.Header.Get("X-CSRF-Token") != "csrf" || r.Header.Get("Cookie") != "TOKEN=session":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(UnifiFirewallGroupResponse{
				Data: []UnifiFirewallGroup{{ID: "abc", Name: groupName}},
			})
		case r.Method == http.MethodPut:
			var group UnifiFirewallGroup
			json.NewDecoder(r.Body).Decode(&group)
			*updates = append(*updates, group.GroupMembers)
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(server.Close)
	CSRFToken, CookieToken = "", ""
	return server, updates
}

func runConfig(t *testing.T, host string, list string) string {
	t.Helper()
	listPath := filepath.Join(t.TempDir(), "hosts.list")
	if err := os.WriteFile(listPath, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	config := strings.ReplaceAll(testConfig, "%HOST%", host)
	return writeConfig(t, "[input]\nlists = [ \""+listPath+"\" ]\n"+config)
}

func TestRunUpdatesGroup(t *testing.T) {
	server, updates := fakeController(t, "Blocked")

	// IP literals resolve without touching the network
	if err := run(runConfig(t, server.URL, "8.8.8.8\n1.1.1.1\n192.168.1.1\n")); err != nil {
		t.Fatal(err)
	}
	if len(*updates) != 1 || !slices.Equal((*updates)[0], []string{"1.1.1.1", "8.8.8.8"}) {
		t.Errorf("unexpected updates: %v", *updates)
	}
}

func TestRunLeavesGroupAloneOnFailure(t *testing.T) {
	tests := map[string]struct {
		group string
		list  string
	}{
		"missing group":        {group: "Other", list: "8.8.8.8\n"},
		"nothing resolved":     {group: "Blocked", list: "\n"},
		"only local addresses": {group: "Blocked", list: "192.168.1.1\n"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server, updates := fakeController(t, test.group)
			if err := run(runConfig(t, server.URL, test.list)); err == nil {
				t.Error("expected run to fail")
			}
			if len(*updates) != 0 {
				t.Errorf("group was modified: %v", *updates)
			}
		})
	}
}
