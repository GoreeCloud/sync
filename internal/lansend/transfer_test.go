package lansend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/GoreeCloud/sync/internal/deviceid"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestEndToEndPrivateLoopback(t *testing.T) {
	dir := privateDir(t)
	receiver, key, err := NewReceiver(dir)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(receiver)
	defer server.Close()
	src := filepath.Join(privateDir(t), "private.txt")
	data := []byte("only trusted recipient may read this")
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := SendFile(context.Background(), server.URL+"/send", key, src)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "received" || result.Filename != "private.txt" || result.Bytes != len(data) {
		t.Fatalf("bad receipt %+v", result)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "private.txt"))
	if err != nil || !bytes.Equal(data, saved) {
		t.Fatalf("wrong received contents %q err=%v", saved, err)
	}
	st, _ := os.Stat(filepath.Join(dir, "private.txt"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("received file not private")
	}
	select {
	case <-receiver.Done():
	default:
		t.Fatal("successful transfer did not notify receiver")
	}
	if _, err := SendFile(context.Background(), server.URL+"/send", key, src); err == nil || !strings.Contains(err.Error(), "410") {
		t.Fatalf("single-use protection failed: %v", err)
	}
}
func TestWrongKeyTamperAndNoOverwrite(t *testing.T) {
	dir := privateDir(t)
	r, key, err := NewReceiver(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r)
	defer srv.Close()
	src := filepath.Join(privateDir(t), "document.txt")
	os.WriteFile(src, []byte("replacement"), 0600)
	os.WriteFile(filepath.Join(dir, "document.txt"), []byte("original"), 0600)
	wrong, _ := NewKey()
	if _, err := SendFile(context.Background(), srv.URL+"/send", EncodeKey(wrong), src); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong key not rejected: %v", err)
	}
	if _, err := SendFile(context.Background(), srv.URL+"/send", key, src); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("existing file not protected: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "document.txt"))
	if string(got) != "original" {
		t.Fatalf("receiver overwrote data: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gcsend-stage-stale")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected leftover staging")
	}
	keyArray, _ := DecodeKey(key)
	envelope, _ := Seal(keyArray, "new.txt", []byte("test"))
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	for i, tc := range []struct {
		body     []byte
		mac      string
		expected int
	}{{tampered, MACHeader(keyArray, envelope), 401}, {tampered, MACHeader(keyArray, tampered), 400}} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/send", bytes.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-GC-LAN-MAC", tc.mac)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.expected {
			t.Errorf("tamper test %d got %d want %d", i, resp.StatusCode, tc.expected)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("tampered transfer created file")
	}
}
func TestReceiverRejectsUnsafeRequests(t *testing.T) {
	dir := privateDir(t)
	r, key, _ := NewReceiver(dir)
	srv := httptest.NewServer(r)
	defer srv.Close()
	k, _ := DecodeKey(key)
	envelope, _ := Seal(k, "good.txt", []byte("ok"))
	for _, tc := range []struct {
		method, path, typ, mac string
		want                   int
	}{
		{"GET", "/send", "application/octet-stream", MACHeader(k, envelope), 404},
		{"POST", "/wrong", "application/octet-stream", MACHeader(k, envelope), 404},
		{"POST", "/send", "text/plain", MACHeader(k, envelope), 415},
		{"POST", "/send", "application/octet-stream", "incorrect", 401},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, bytes.NewReader(envelope))
		req.Header.Set("Content-Type", tc.typ)
		req.Header.Set("X-GC-LAN-MAC", tc.mac)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s %s got %d want %d", tc.method, tc.path, resp.StatusCode, tc.want)
		}
	}
	hugeReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/send", bytes.NewReader([]byte("x")))
	hugeReq.ContentLength = MaxEnvelopeBytes + 1
	hugeReq.Header.Set("Content-Type", "application/octet-stream")
	// Go's transport may reject a forged body length before sending; oversized
	// payloads are tested directly through httptest.ResponseRecorder instead.
	hugeReq = httptest.NewRequest(http.MethodPost, "http://127.0.0.1/send", bytes.NewReader([]byte("x")))
	hugeReq.ContentLength = MaxEnvelopeBytes + 1
	hugeReq.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, hugeReq)
	if w.Code != 413 {
		t.Fatalf("oversized request returned %d", w.Code)
	}
}
func TestSenderRejectsBadAcknowledgment(t *testing.T) {
	src := filepath.Join(privateDir(t), "a.txt")
	os.WriteFile(src, []byte("data"), 0600)
	key, _ := NewKey()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"status":"received","filename":"a.txt","bytes":4}`)
	}))
	defer fake.Close()
	if _, err := SendFile(context.Background(), fake.URL+"/send", EncodeKey(key), src); err == nil || !strings.Contains(err.Error(), "acknowledgment") {
		t.Fatalf("accepted forged success response: %v", err)
	}
}
func TestReceiveOnceSingleFileAndShutdown(t *testing.T) {
	dir := privateDir(t)
	reader, writer := io.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		receipt, err := ReceiveOnce(ctx, "127.0.0.1:0", dir, false, writer)
		writer.Close()
		if err == nil && (receipt.Status != "received" || receipt.Filename != "once.txt") {
			err = fmt.Errorf("wrong receipt: %+v", receipt)
		}
		done <- err
	}()
	var announcement struct {
		Listen     string `json:"listen"`
		PairingKey string `json:"pairingKey"`
	}
	if err := json.NewDecoder(reader).Decode(&announcement); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(announcement.Listen, "http://127.0.0.1:") || len(announcement.PairingKey) != 43 {
		t.Fatalf("invalid receiver announcement %+v", announcement)
	}
	src := filepath.Join(privateDir(t), "once.txt")
	os.WriteFile(src, []byte("delivered"), 0600)
	if _, err := SendFile(ctx, announcement.Listen, announcement.PairingKey, src); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("receiver did not exit after one transfer")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "once.txt"))
	if string(got) != "delivered" {
		t.Fatal("transfer did not persist")
	}
}
func TestReceiverBindRequiresExplicitOptIn(t *testing.T) {
	dir := privateDir(t)
	for _, tc := range []struct {
		address string
		allow   bool
	}{{"0.0.0.0:0", false}, {"8.8.8.8:80", true}, {"localhost:10", true}, {"127.0.0.1:-1", false}} {
		_, err := ReceiveOnce(context.Background(), tc.address, dir, tc.allow, io.Discard)
		if err == nil {
			t.Errorf("accepted dangerous receiver listener %q allow=%v", tc.address, tc.allow)
		}
	}
}
func TestSymlinkAndPrivateDestinationProtection(t *testing.T) {
	dir := privateDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewReceiver(dir); err == nil {
		t.Fatal("accepted world-readable receiver directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := SaveNew(dir, "../secret", []byte("x")); err == nil {
		t.Fatal("accepted traversal")
	}
	if err := SaveNew(dir, "good.txt", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := SaveNew(dir, "good.txt", []byte("overwrite")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	link := filepath.Join(privateDir(t), "linked")
	if err := os.Symlink(dir, link); err == nil {
		if _, _, err := NewReceiver(link); err == nil {
			t.Fatal("followed symlink destination")
		}
	}
}

// The receiver's plaintext HTTP response must not reveal encrypted metadata.
func TestReceiverDoesNotEchoFilenameOverHTTP(t *testing.T) {
	dir := privateDir(t)
	receiver, encoded, err := NewReceiver(dir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := DecodeKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(key, "top-secret-filename.txt", []byte("confidential bytes"))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/send", bytes.NewReader(envelope))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-GC-LAN-MAC", MACHeader(key, envelope))
	w := httptest.NewRecorder()
	receiver.ServeHTTP(w, request)
	if w.Code != http.StatusCreated {
		t.Fatalf("transfer not accepted: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "top-secret") || strings.Contains(w.Body.String(), "confidential") {
		t.Fatalf("plaintext metadata leaked in response: %q", w.Body.String())
	}
	if !VerifyAck(key, MACHeader(key, envelope), w.Header().Get("X-GC-LAN-ACK")) {
		t.Fatal("receiver did not authenticate receipt")
	}
}

func TestReceiverProofAuthenticationBeforeCiphertext(t *testing.T) {
	identityDir := filepath.Join(privateDir(t), "identity")
	public, err := deviceid.Initialize(identityDir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deviceid.Load(identityDir)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := deviceid.ParsePublic(public.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	r, key, err := NewReceiverWithIdentity(privateDir(t), identity)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(r)
	defer server.Close()
	senderDir := privateDir(t)
	file := filepath.Join(senderDir, "proof.txt")
	if err := os.WriteFile(file, []byte("identity authenticated"), 0600); err != nil {
		t.Fatal(err)
	}
	// The proof binds the random per-request nonce, trusted Ed25519 public key,
	// and this receiver instance's fresh one-time transfer key.
	wrongKey, _ := NewKey()
	if _, err := SendFileWithPinnedReceiver(context.Background(), server.URL+"/send", EncodeKey(wrongKey), file, pub); err == nil || !strings.Contains(err.Error(), "identity not authenticated") {
		t.Fatalf("accepted wrong session key: %v", err)
	}
	otherDir := filepath.Join(privateDir(t), "other")
	otherPublic, _ := deviceid.Initialize(otherDir)
	other, _ := deviceid.ParsePublic(otherPublic.PublicKey)
	if _, err := SendFileWithPinnedReceiver(context.Background(), server.URL+"/send", key, file, other); err == nil || !strings.Contains(err.Error(), "identity not authenticated") {
		t.Fatalf("accepted wrong device identity: %v", err)
	}
	select {
	case <-r.Done():
		t.Fatal("file transferred after invalid receiver proof")
	default:
	}
	result, err := SendFileWithPinnedReceiver(context.Background(), server.URL+"/send", key, file, pub)
	if err != nil || result.Filename != "proof.txt" {
		t.Fatalf("legitimate trust rejected: %+v %v", result, err)
	}
	found, err := os.ReadFile(filepath.Join(r.dir, "proof.txt"))
	if err != nil || string(found) != "identity authenticated" {
		t.Fatalf("invalid file: %s %v", found, err)
	}
}
func TestPinnedReceiverDoesNotFallBackToUnpaired(t *testing.T) {
	r, key, err := NewReceiver(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(r)
	defer server.Close()
	senderDir := privateDir(t)
	file := filepath.Join(senderDir, "secure.txt")
	os.WriteFile(file, []byte("secret"), 0600)
	identityDir := filepath.Join(privateDir(t), "key")
	pub, _ := deviceid.Initialize(identityDir)
	pubKey, _ := deviceid.ParsePublic(pub.PublicKey)
	if _, err := SendFileWithPinnedReceiver(context.Background(), server.URL+"/send", key, file, pubKey); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("silently fell back to unverified transfer: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "secure.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file uploaded despite missing proof")
	}
}
func TestReceiverProofEndpointRejectsInvalidChallenges(t *testing.T) {
	private := filepath.Join(privateDir(t), "identity")
	deviceid.Initialize(private)
	identity, _ := deviceid.Load(private)
	r, _, err := NewReceiverWithIdentity(privateDir(t), identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, url string
		want        int
	}{
		{"GET", "/identity", 400},
		{"GET", "/identity?challenge=short", 400},
		{"GET", "/identity?challenge=short&extra=1", 400},
		{"POST", "/identity", 404},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, "http://127.0.0.1"+tc.url, nil)
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("%s returned %d expected %d", tc.url, w.Code, tc.want)
		}
	}
}

func TestMutualDeviceAuthenticationAndNoDowngrade(t *testing.T) {
	// All identities and data are synthetic and all HTTP stays on loopback.
	senderDir := filepath.Join(privateDir(t), "sender")
	receiverDir := filepath.Join(privateDir(t), "receiver")
	attackerDir := filepath.Join(privateDir(t), "attacker")
	senderPublic, err := deviceid.Initialize(senderDir)
	if err != nil {
		t.Fatal(err)
	}
	receiverPublic, err := deviceid.Initialize(receiverDir)
	if err != nil {
		t.Fatal(err)
	}
	deviceid.Initialize(attackerDir)
	sender, _ := deviceid.Load(senderDir)
	receiver, _ := deviceid.Load(receiverDir)
	attacker, _ := deviceid.Load(attackerDir)
	pubSender, _ := deviceid.ParsePublic(senderPublic.PublicKey)
	pubReceiver, _ := deviceid.ParsePublic(receiverPublic.PublicKey)
	r, key, err := NewReceiverWithMutualAuth(privateDir(t), receiver, pubSender)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(r)
	defer server.Close()
	file := filepath.Join(privateDir(t), "mutual.txt")
	os.WriteFile(file, []byte("mutually authenticated"), 0600)
	if _, err := SendFileWithPinnedReceiver(context.Background(), server.URL+"/send", key, file, pubReceiver); err == nil || !strings.Contains(err.Error(), "policy mismatch") {
		t.Fatalf("one-sided sender unexpectedly succeeded: %v", err)
	}
	if _, err := SendFile(context.Background(), server.URL+"/send", key, file); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("unverified sender unexpectedly succeeded: %v", err)
	}
	if _, err := SendFileWithMutualAuth(context.Background(), server.URL+"/send", key, file, pubReceiver, attacker); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("untrusted sender unexpectedly succeeded: %v", err)
	}
	select {
	case <-r.Done():
		t.Fatal("receiver completed without valid sender proof")
	default:
	}
	result, err := SendFileWithMutualAuth(context.Background(), server.URL+"/send", key, file, pubReceiver, sender)
	if err != nil || result.Filename != "mutual.txt" {
		t.Fatalf("mutual verification refused valid peers: %+v %v", result, err)
	}
	body, err := os.ReadFile(filepath.Join(r.dir, "mutual.txt"))
	if err != nil || string(body) != "mutually authenticated" {
		t.Fatalf("file incorrect: %s %v", body, err)
	}
}
func TestSenderMutualAuthenticationRequiresReceiverPolicy(t *testing.T) {
	root := filepath.Join(privateDir(t), "id")
	pub, err := deviceid.Initialize(root)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := deviceid.Load(root)
	pinned, _ := deviceid.ParsePublic(pub.PublicKey)
	r, key, err := NewReceiverWithIdentity(privateDir(t), identity)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(r)
	defer server.Close()
	file := filepath.Join(privateDir(t), "data.txt")
	os.WriteFile(file, []byte("data"), 0600)
	if _, err := SendFileWithMutualAuth(context.Background(), server.URL+"/send", key, file, pinned, identity); err == nil || !strings.Contains(err.Error(), "policy mismatch") {
		t.Fatalf("mutual sender silently downgraded: %v", err)
	}
	select {
	case <-r.Done():
		t.Fatal("unpaired receiver accepted mutual-mode sender")
	default:
	}
	if _, _, err := NewReceiverWithMutualAuth(privateDir(t), nil, pinned); err == nil {
		t.Fatal("mutual receiver accepted no identity")
	}
}
func TestMutualReceiverForgeriesRejectedBeforeSaving(t *testing.T) {
	root := filepath.Join(privateDir(t), "receiver")
	deviceid.Initialize(root)
	identity, _ := deviceid.Load(root)
	allowedRoot := filepath.Join(privateDir(t), "allowed")
	allowedPub, _ := deviceid.Initialize(allowedRoot)
	allowedKey, _ := deviceid.ParsePublic(allowedPub.PublicKey)
	receiver, keyText, err := NewReceiverWithMutualAuth(privateDir(t), identity, allowedKey)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := DecodeKey(keyText)
	envelope, _ := Seal(key, "forged.txt", []byte("must not be saved"))
	mac := MACHeader(key, envelope)
	// Retrieve a real receiver ticket; knowing the one-time transfer key and
	// ticket must still be insufficient to forge the trusted sender signature.
	challenge := make([]byte, 32)
	rand.Read(challenge)
	query := "/identity?challenge=" + base64.RawURLEncoding.EncodeToString(challenge)
	proofReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+query, nil)
	w := httptest.NewRecorder()
	receiver.ServeHTTP(w, proofReq)
	if w.Code != 200 {
		t.Fatalf("challenge status %d", w.Code)
	}
	var proof struct {
		SenderTicket string `json:"senderTicket"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	if len(proof.SenderTicket) != 86 {
		t.Fatal("expected ticket")
	}
	forged := make([]byte, 64)
	rand.Read(forged)
	for _, tc := range []struct{ ticket, sig string }{
		{proof.SenderTicket, base64.RawURLEncoding.EncodeToString(forged)},
		{"invalid", base64.RawURLEncoding.EncodeToString(forged)},
	} {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/send", bytes.NewReader(envelope))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-GC-LAN-MAC", mac)
		req.Header.Set("X-GC-Sender-Fingerprint", allowedPub.Fingerprint)
		req.Header.Set("X-GC-Sender-Ticket", tc.ticket)
		req.Header.Set("X-GC-Sender-Signature", tc.sig)
		reply := httptest.NewRecorder()
		receiver.ServeHTTP(reply, req)
		if reply.Code != 403 {
			t.Fatalf("forgery got HTTP %d, want 403", reply.Code)
		}
	}
	if _, err := os.Stat(filepath.Join(receiver.dir, "forged.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("forgery created file")
	}
}
