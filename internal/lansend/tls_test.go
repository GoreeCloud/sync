package lansend

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTLSOneTimeEncryptedRoundTripAndSecretPin(t *testing.T) {
	dir := privateDir(t)
	reader, writer := io.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		receipt, err := ReceiveOnceWithTransport(ctx, "127.0.0.1:0", dir, false, true, writer, nil, nil)
		_ = writer.Close()
		if err == nil && (receipt.Status != "received" || receipt.Filename != "tls.txt") {
			err = fmt.Errorf("invalid receipt: %+v", receipt)
		}
		done <- err
	}()
	var announce struct {
		Listen     string `json:"listen"`
		PairingKey string `json:"pairingKey"`
	}
	if err := json.NewDecoder(reader).Decode(&announce); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(announce.Listen, "https://127.0.0.1:") {
		t.Fatalf("TLS not announced: %q", announce.Listen)
	}
	source := filepath.Join(privateDir(t), "tls.txt")
	if err := os.WriteFile(source, []byte("confidential HTTPS metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	other, _ := NewKey()
	if _, err := SendFile(ctx, announce.Listen, EncodeKey(other), source); err == nil {
		t.Fatal("TLS accepted another secret's certificate pin")
	}
	if _, err := os.Lstat(filepath.Join(dir, "tls.txt")); err == nil {
		t.Fatal("wrong-key TLS attempt wrote the file")
	}
	if _, err := SendFile(ctx, announce.Listen, announce.PairingKey, source); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("secure one-shot receiver did not terminate")
	}
	got, err := os.ReadFile(filepath.Join(dir, "tls.txt"))
	if err != nil || string(got) != "confidential HTTPS metadata" {
		t.Fatalf("encrypted transfer failed: bytes=%q, err=%v", got, err)
	}
}

func TestTLSServerWithUnrelatedCertificateRejected(t *testing.T) {
	timesCalled := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		timesCalled++
		w.WriteHeader(201)
	}))
	defer server.Close()
	key, _ := NewKey()
	src := filepath.Join(privateDir(t), "unrelated.txt")
	if err := os.WriteFile(src, []byte("no upload"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := SendFile(context.Background(), server.URL+"/send", EncodeKey(key), src)
	if err == nil || !strings.Contains(err.Error(), "certificate does not match") {
		t.Fatalf("untrusted TLS peer accepted: %v", err)
	}
	if timesCalled != 0 {
		t.Fatal("upload request reached untrusted TLS server")
	}
}

func TestTLSSessionCertBoundToIPAndProtocolVersion(t *testing.T) {
	key, _ := NewKey()
	if _, err := ServerTLSConfig(key, net.IPv4zero); err == nil {
		t.Fatal("accepted unspecified server IP")
	}
	if _, err := ClientTLSConfig(key, net.IPv4zero); err == nil {
		t.Fatal("accepted unspecified client IP")
	}
	config, err := ServerTLSConfig(key, net.ParseIP("127.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })}
	go server.Serve(tls.NewListener(listener, config))
	defer server.Close()
	keyConfig, err := ClientTLSConfig(key, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: keyConfig}, Timeout: 3 * time.Second}
	if _, err := client.Get("https://" + listener.Addr().String() + "/send"); err == nil || !strings.Contains(err.Error(), "IP certificate mismatch") {
		t.Fatalf("accepted TLS certificate for wrong interface: %v", err)
	}
}

func TestLANRequiresTLSOutsideLoopback(t *testing.T) {
	_, err := ReceiveOnceWithTransport(context.Background(), "192.168.1.55:0", privateDir(t), true, false, io.Discard, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requires -receive-tls") {
		t.Fatalf("plaintext LAN receiver accepted: %v", err)
	}
	_, err = ReceiveOnceWithTransport(context.Background(), "0.0.0.0:0", privateDir(t), true, true, io.Discard, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "specific private interface") {
		t.Fatalf("wildcard TLS listener accepted: %v", err)
	}
}
