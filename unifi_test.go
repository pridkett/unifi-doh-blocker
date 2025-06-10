package main

import (
	"net/http"
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

// Mock or minimal implementation for createUnifiHTTPClient to satisfy the tests
// This should ideally be the actual function from unifi.go, but for isolated testing
// of the test file itself, we might need a local version if unifi.go isn't fully available
// or to avoid side effects. For this exercise, we assume unifi.go's function is used.
// If unifi.go's createUnifiHTTPClient is not as expected, these tests might fail.
// For example, if it returns a client with a custom transport that isn't *http.Transport.

// Helper function to ensure UnifiHTTPClient is reset if tests run in parallel or affect global state.
// This is a simplistic approach; proper test setup/teardown might be needed for complex scenarios.
func resetGlobalClient() {
	UnifiHTTPClient = nil
}
