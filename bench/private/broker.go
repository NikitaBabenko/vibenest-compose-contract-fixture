package privatefixture

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const maxPublicLauncher = 8192

func buildPublicLauncher(loader []byte, tlsAddr, plainAddr *net.TCPAddr, ca, helper []byte) ([]byte, error) {
	const shebang = "#!/bin/sh\n"
	if !bytes.HasPrefix(loader, []byte(shebang)) || len(loader) <= len(shebang) ||
		len(loader) > maxPublicLauncher || bytes.IndexAny(loader, "\x00\r") >= 0 ||
		tlsAddr == nil || plainAddr == nil || tlsAddr.IP.To4() == nil || !tlsAddr.IP.IsPrivate() ||
		!tlsAddr.IP.Equal(plainAddr.IP) || tlsAddr.Zone != "" || plainAddr.Zone != "" || tlsAddr.Port <= 0 || tlsAddr.Port > 65535 ||
		plainAddr.Port <= 0 || plainAddr.Port > 65535 || tlsAddr.Port == plainAddr.Port ||
		len(ca) == 0 || len(ca) > maxPublicLauncher || len(helper) == 0 || len(helper) > MaxHelper {
		return nil, ErrDenied
	}
	prefix := fmt.Sprintf("%sset -- 'https://%s' 'http://%s/ca.pem' '%s' '%s' '%d' \"$@\"\n",
		shebang, tlsAddr.String(), plainAddr.String(), Hash(ca), Hash(helper), len(helper))
	launcher := append([]byte(prefix), loader[len(shebang):]...)
	if len(launcher) > maxPublicLauncher {
		return nil, ErrDenied
	}
	return launcher, nil
}

func publicBootstrapHandler(ca, launcher []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.Header.Get("Authorization") != "" {
			http.Error(w, "denied", 403)
			return
		}
		var body []byte
		switch r.URL.Path {
		case "/ca.pem":
			w.Header().Set("Content-Type", "application/x-pem-file")
			body = ca
		case "/l":
			w.Header().Set("Content-Type", "application/octet-stream")
			body = launcher
		default:
			http.Error(w, "denied", 403)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
}

// RunBroker runs only on the explicitly disposable Actions host. Commands and
// capabilities travel over the parent-owned stdin/stdout pipes, never HTTP admin.
// stdout is NOT a public log stream; the runner must not tee it into evidence.
func RunBroker(helperPath, listenIP string, control io.Reader, replies io.Writer) error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("VN_PRIVATE_DISPOSABLE") != "1" {
		return ErrDenied
	}
	helper, err := os.ReadFile(helperPath)
	if err != nil || len(helper) == 0 || len(helper) > MaxHelper {
		return ErrDenied
	}
	loader, err := os.ReadFile("bench/private-loader.sh")
	if err != nil {
		return ErrDenied
	}
	ip := net.ParseIP(listenIP)
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		return ErrDenied
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ErrDenied
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return ErrDenied
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "disposable-fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{ip}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return ErrDenied
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return ErrDenied
	}
	store, err := NewStore(secret, time.Now)
	if err != nil {
		return ErrDenied
	}
	bridge := NewBridge(store)
	plainListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip})
	if err != nil {
		return ErrDenied
	}
	defer plainListener.Close()
	tlsListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip})
	if err != nil {
		return ErrDenied
	}
	defer tlsListener.Close()
	plainAddr := plainListener.Addr().(*net.TCPAddr)
	tlsAddr := tlsListener.Addr().(*net.TCPAddr)
	launcher, err := buildPublicLauncher(loader, tlsAddr, plainAddr, ca, helper)
	if err != nil {
		return ErrDenied
	}
	server := func(h http.Handler) *http.Server {
		return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	}
	plain := server(publicBootstrapHandler(ca, launcher))
	defer plain.Close()
	tlsServer := server(bridge.Handler())
	defer tlsServer.Close()
	go plain.Serve(plainListener)
	go tlsServer.Serve(tls.NewListener(tlsListener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}))
	out := json.NewEncoder(replies)
	if out.Encode(map[string]any{
		"origin": "https://" + tlsAddr.String(), "caURL": "http://" + plainAddr.String() + "/ca.pem",
		"caDigest": Hash(ca), "helperDigest": Hash(helper), "helperSize": len(helper),
		"launcherURL": "http://" + plainAddr.String() + "/l", "launcherDigest": Hash(launcher),
		"launcherSize": len(launcher), "publicLoaderDigest": Hash(loader),
	}) != nil {
		return ErrDenied
	}
	scanner := bufio.NewScanner(control)
	scanner.Buffer(make([]byte, 4096), 12<<20)
	for scanner.Scan() {
		data := scanner.Bytes()
		var request map[string]json.RawMessage
		response := map[string]any{"ok": false}
		if !strictJSON(data) || json.Unmarshal(data, &request) != nil {
			if out.Encode(response) != nil {
				return ErrDenied
			}
			continue
		}
		var op string
		_ = json.Unmarshal(request["op"], &op)
		switch op {
		case "issue":
			if _, ok := exactObject(data, "op", "scope", "settings", "retainedScope"); !ok || !exactScope(request["scope"]) {
				break
			}
			var scope Scope
			_ = json.Unmarshal(request["scope"], &scope)
			if scope.HelperDigest != Hash(helper) || scope.SettingsDigest != Hash(request["settings"]) || scope.Deployment != "" {
				break
			}
			slots := map[string]Slot{"helper": {helper, Hash(helper), 3}, "settings": {request["settings"], Hash(request["settings"]), 2}}
			if string(request["retainedScope"]) != "null" {
				if !exactScope(request["retainedScope"]) {
					break
				}
				var retained Scope
				_ = json.Unmarshal(request["retainedScope"], &retained)
				if retained.Application != scope.Application || retained.Project != scope.Project || retained.SourceSHA != scope.SourceSHA {
					break
				}
				runtime, err := store.Open(retained)
				if err != nil {
					break
				}
				slots["runtime"] = Slot{runtime, Hash(runtime), 2}
			}
			delivery, err := store.Issue(scope, 10*time.Minute, slots, true)
			if err != nil {
				break
			}
			submission, err := store.Issue(scope, 10*time.Minute, nil, false)
			if err != nil {
				store.Revoke(delivery)
				break
			}
			if bridge.Pair(delivery, submission) != nil {
				store.Revoke(delivery)
				store.Revoke(submission)
				break
			}
			response = map[string]any{"ok": true, "delivery": delivery, "submission": submission}
		case "bind":
			if _, ok := exactObject(data, "op", "delivery", "submission", "deployment"); !ok {
				break
			}
			var d, s, id string
			_ = json.Unmarshal(request["delivery"], &d)
			_ = json.Unmarshal(request["submission"], &s)
			_ = json.Unmarshal(request["deployment"], &id)
			if store.Bind(d, id) != nil || store.Bind(s, id) != nil {
				store.Revoke(d)
				store.Revoke(s)
				break
			}
			response["ok"] = true
		case "open", "release", "refusal":
			if _, ok := exactObject(data, "op", "scope"); !ok || !exactScope(request["scope"]) {
				break
			}
			var scope Scope
			_ = json.Unmarshal(request["scope"], &scope)
			if op == "open" {
				value, err := store.Open(scope)
				if err != nil {
					break
				}
				response = map[string]any{"ok": true, "artifact": json.RawMessage(value)}
			} else if op == "refusal" {
				value, err := store.Refusal(scope)
				if err != nil {
					break
				}
				response = map[string]any{"ok": true, "refusal": value}
			} else {
				response["ok"] = bridge.ReleaseFixture(scope) == nil
			}
		case "revoke":
			if _, ok := exactObject(data, "op", "capability"); !ok {
				break
			}
			var capability string
			_ = json.Unmarshal(request["capability"], &capability)
			store.Revoke(capability)
			response["ok"] = true
		}
		if out.Encode(response) != nil {
			return ErrDenied
		}
	}
	if scanner.Err() != nil {
		return ErrDenied
	}
	return nil
}
