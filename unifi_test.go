package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateUnifiHTTPClient_Insecure(t *testing.T) {
	client := createUnifiHTTPClient(true)
	if client == nil {
		t.Fatal("createUnifiHTTPClient(true) returned nil")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Expected client.Transport to be *http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("Expected client.Transport.TLSClientConfig to be non-nil for insecure client")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true for insecure client")
	}
}

func TestCreateUnifiHTTPClient_Secure(t *testing.T) {
	client := createUnifiHTTPClient(false)
	if client == nil {
		t.Fatal("createUnifiHTTPClient(false) returned nil")
	}
	// For a secure client, TLSClientConfig might be nil or InsecureSkipVerify might be false by default.
	// If it's nil, it uses the default secure transport.
	// If it's not nil, InsecureSkipVerify should be false.
	if transport, ok := client.Transport.(*http.Transport); ok {
		if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify to be false or TLSClientConfig to be nil for secure client")
		}
	} else if client.Transport != nil {
		// If a custom transport is set but it's not *http.Transport, this test might need adjustment
		// based on how the secure client is configured. For now, we assume default or *http.Transport.
		t.Logf("Client transport is not *http.Transport, it is %T. Assuming secure by default.", client.Transport)
	}
	// If client.Transport is nil, it implies http.DefaultTransport is used, which is secure.
}

func TestInitUnifiClient(t *testing.T) {
	// Test with insecure = true
	InitUnifiClient(true)
	if UnifiHTTPClient == nil {
		t.Fatal("UnifiHTTPClient is nil after InitUnifiClient(true)")
	}
	transport, ok := UnifiHTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Expected UnifiHTTPClient.Transport to be *http.Transport, got %T", UnifiHTTPClient.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("Expected UnifiHTTPClient.Transport.TLSClientConfig to be non-nil for insecure client")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected UnifiHTTPClient.InsecureSkipVerify to be true after InitUnifiClient(true)")
	}

	// Reset global client for next test case (or ensure tests are isolated)
	UnifiHTTPClient = nil

	// Test with insecure = false
	InitUnifiClient(false)
	if UnifiHTTPClient == nil {
		t.Fatal("UnifiHTTPClient is nil after InitUnifiClient(false)")
	}
	if transport, ok := UnifiHTTPClient.Transport.(*http.Transport); ok {
		if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected UnifiHTTPClient.InsecureSkipVerify to be false or TLSClientConfig to be nil after InitUnifiClient(false)")
		}
	} else if UnifiHTTPClient.Transport != nil {
		t.Logf("UnifiHTTPClient transport is not *http.Transport, it is %T. Assuming secure by default.", UnifiHTTPClient.Transport)
	}
}

func newLoginServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	CSRFToken, CookieToken = "", ""
	return server
}

func loginOK(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session"})
	w.Write([]byte(`{"username":"admin"}`))
}

func TestLoginSelfSignedCertificate(t *testing.T) {
	server := newLoginServer(t, loginOK)

	InitUnifiClient(false)
	if _, err := UnifiLogin("u", "p", server.URL); err == nil {
		t.Error("expected a verifying client to reject a self-signed certificate")
	}

	InitUnifiClient(true)
	if _, err := UnifiLogin("u", "p", server.URL); err != nil {
		t.Errorf("expected insecure client to accept a self-signed certificate: %v", err)
	}
}

func TestLoginRejectsErrorStatus(t *testing.T) {
	server := newLoginServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"bad credentials"}`))
	})

	InitUnifiClient(true)
	_, err := UnifiLogin("u", "p", server.URL)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected a 401 error, got %v", err)
	}
}

func TestLoginRequiresSessionToken(t *testing.T) {
	server := newLoginServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})

	InitUnifiClient(true)
	if _, err := UnifiLogin("u", "p", server.URL); err == nil {
		t.Error("expected an error when no session token is returned")
	}
}

func TestLoginDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	target := newLoginServer(t, func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		loginOK(w, r)
	})
	server := newLoginServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})

	InitUnifiClient(true)
	if _, err := UnifiLogin("u", "p", server.URL); err == nil {
		t.Error("expected a redirect response to be an error")
	}
	if redirected {
		t.Error("credentials were re-sent to the redirect target")
	}
}
