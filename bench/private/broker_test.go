package privatefixture

import (
	"bytes"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestPublicLauncherPinsOnlyPublicBrokerMetadata(t *testing.T) {
	tlsAddr := &net.TCPAddr{IP: net.ParseIP("172.18.0.1"), Port: 45678}
	plainAddr := &net.TCPAddr{IP: net.ParseIP("172.18.0.1"), Port: 45679}
	ca, helper := []byte("public-ca-bytes"), []byte("synthetic-helper-bytes")
	loader := []byte("#!/bin/sh\nexec synthetic-loader \"$@\"\n")
	launcher, err := buildPublicLauncher(loader, tlsAddr, plainAddr, ca, helper)
	if err != nil {
		t.Fatal(err)
	}
	expected := "#!/bin/sh\nset -- 'https://172.18.0.1:45678' 'http://172.18.0.1:45679/ca.pem' '" + Hash(ca) + "' '" + Hash(helper) + "' '" + strconv.Itoa(len(helper)) + "' \"$@\"\nexec synthetic-loader \"$@\"\n"
	if string(launcher) != expected || bytes.Contains(launcher, ca) || bytes.Contains(launcher, helper) {
		t.Fatal("launcher changed loader source or exported non-metadata bytes")
	}
}

func TestPublicLauncherRefusesInvalidLoaderAndAddresses(t *testing.T) {
	tlsAddr := &net.TCPAddr{IP: net.ParseIP("172.18.0.1"), Port: 45678}
	plainAddr := &net.TCPAddr{IP: net.ParseIP("172.18.0.1"), Port: 45679}
	loader := []byte("#!/bin/sh\ntrue\n")
	for _, test := range []struct {
		name       string
		loader     []byte
		tls, plain *net.TCPAddr
	}{
		{"shebang", []byte("invalid"), tlsAddr, plainAddr},
		{"nul", []byte("#!/bin/sh\n\x00"), tlsAddr, plainAddr},
		{"oversize", []byte("#!/bin/sh\n" + strings.Repeat("x", maxPublicLauncher-10)), tlsAddr, plainAddr},
		{"different address", loader, tlsAddr, &net.TCPAddr{IP: net.ParseIP("172.18.0.2"), Port: 45679}},
		{"same port", loader, tlsAddr, tlsAddr},
		{"nonprivate", loader, &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 45678}, plainAddr},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildPublicLauncher(test.loader, test.tls, test.plain, []byte("ca"), []byte("helper")); err == nil {
				t.Fatal("invalid launcher inputs were accepted")
			}
		})
	}
}

func TestPublicBootstrapRoutesAreReadOnlyAndCredentialFree(t *testing.T) {
	ca, launcher := []byte("public-ca"), []byte("public-launcher")
	handler := publicBootstrapHandler(ca, launcher)
	for _, test := range []struct {
		method, target, auth string
		status               int
		body                 []byte
	}{
		{"GET", "/l", "", 200, launcher},
		{"GET", "/ca.pem", "", 200, ca},
		{"GET", "/l", "Bearer synthetic", 403, nil},
		{"GET", "/l?", "", 403, nil},
		{"GET", "/l?data=x", "", 403, nil},
		{"GET", "/%6c", "", 403, nil},
		{"POST", "/l", "", 403, nil},
		{"GET", "/v1/bootstrap/helper", "", 403, nil},
	} {
		request := httptest.NewRequest(test.method, test.target, nil)
		if test.auth != "" {
			request.Header.Set("Authorization", test.auth)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || test.body != nil && (!bytes.Equal(response.Body.Bytes(), test.body) ||
			response.Header().Get("Content-Length") != strconv.Itoa(len(test.body))) {
			t.Fatalf("unexpected public bootstrap response for %s %s: %d", test.method, test.target, response.Code)
		}
	}
}
