package localsend

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEndToEndSecureSend(t *testing.T) {
	root := t.TempDir()
	identity, err := LoadOrCreateIdentity(filepath.Join(root, "certs"), "Receiver")
	if err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(root, "inbox")
	if err = os.Mkdir(inbox, 0700); err != nil {
		t.Fatal(err)
	}
	approved := false
	receiver, err := NewReceiver(identity, inbox, func(tr TransferRequest) bool {
		approved = true
		return tr.TotalBytes == 5 && len(tr.Names) == 1 && tr.Names[0] == "hello.txt"
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(receiver.Handler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{identity.Certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "hello.txt")
	if err = os.WriteFile(file, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	peer := Peer{IP: net.ParseIP(host), Info: identity.Info(port)}
	if err = Send(context.Background(), peer, identity.Info(DefaultPort), file); err != nil {
		t.Fatal(err)
	}
	if !approved {
		t.Fatal("receiver was not asked to approve transfer")
	}
	files, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !strings.HasPrefix(files[0].Name(), "hello-") {
		t.Fatalf("unexpected received files: %v", files)
	}
	b, err := os.ReadFile(filepath.Join(inbox, files[0].Name()))
	if err != nil || string(b) != "hello" {
		t.Fatalf("received file corrupt: %q %v", b, err)
	}
}
func TestCertificatePinRejectsSubstitution(t *testing.T) {
	root := t.TempDir()
	identity, err := LoadOrCreateIdentity(filepath.Join(root, "cert"), "Receiver")
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewReceiver(identity, root, func(TransferRequest) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(receiver.Handler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{identity.Certificate}}
	server.StartTLS()
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	file := filepath.Join(root, "data.txt")
	if err = os.WriteFile(file, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	peer := Peer{IP: net.ParseIP(host), Info: identity.Info(port)}
	peer.Info.Fingerprint = strings.Repeat("a", 64)
	if err = Send(context.Background(), peer, identity.Info(DefaultPort), file); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected TLS fingerprint rejection, got %v", err)
	}
}
func TestSafeName(t *testing.T) {
	for _, s := range []string{"../escape", "a/b", "..", "", "bad\nname"} {
		if safeName(s) == nil {
			t.Errorf("accepted unsafe path %q", s)
		}
	}
	if safeName("family photo.jpg") != nil {
		t.Fatal("rejected safe filename")
	}
}
func TestIdentityIsStable(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateIdentity(dir, "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateIdentity(dir, "second")
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatal("fingerprint changed after restart")
	}
}
