package lansend

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestEnvelopeConfidentialityAndAuthentication(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("private message: hello GoreeCloud")
	one, err := Seal(key, "photo-secret.png", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Seal(key, "photo-secret.png", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one, two) || bytes.Contains(one, plaintext) || bytes.Contains(one, []byte("photo-secret.png")) {
		t.Fatal("ciphertext leaks data or nonce was reused")
	}
	name, recovered, err := Open(key, one)
	if err != nil || name != "photo-secret.png" || !bytes.Equal(plaintext, recovered) {
		t.Fatalf("round trip: name=%q err=%v", name, err)
	}
	one[len(one)-1] ^= 0x10
	if _, _, err := Open(key, one); err == nil {
		t.Fatal("tampered AEAD accepted")
	}
	wrong, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(wrong, two); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, _, err := Open(key, []byte("GCSL1")); err == nil {
		t.Fatal("truncated envelope accepted")
	}
}
func TestKeyAndMAC(t *testing.T) {
	key, _ := NewKey()
	encoded := EncodeKey(key)
	if len(encoded) != 43 {
		t.Fatalf("unexpected pairing key length: %d", len(encoded))
	}
	decoded, err := DecodeKey(encoded)
	if err != nil || decoded != key {
		t.Fatal("key roundtrip failed")
	}
	for _, invalid := range []string{"", "aaa", "!", base64.RawURLEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := DecodeKey(invalid); err == nil {
			t.Errorf("accepted invalid key %q", invalid)
		}
	}
	body := []byte("ciphertext")
	tag := MACHeader(key, body)
	if !VerifyMAC(key, body, tag) {
		t.Fatal("correct request MAC rejected")
	}
	if VerifyMAC(key, []byte("ciphertexu"), tag) || VerifyMAC(key, body, "bad!") {
		t.Fatal("bad request MAC accepted")
	}
	ack := AckHeader(key, tag)
	if !VerifyAck(key, tag, ack) || VerifyAck(key, "other", ack) {
		t.Fatal("incorrect authenticated receipt behavior")
	}
}
func TestFilenameSafetyAndBounds(t *testing.T) {
	bad := []string{"", ".", "..", "../x", "dir/file", "back\\slash", "colon:name", "a\x00b", "white ", "a.", "CON", "nul.txt", "com1.log", "LPT9", "bad\xff"}
	for _, name := range bad {
		if ValidFilename(name) {
			t.Errorf("unsafe name accepted %q", name)
		}
	}
	for _, name := range []string{"photo.jpg", "space in name.txt", ".env", "日本語.txt", "number.123"} {
		if !ValidFilename(name) {
			t.Errorf("safe name rejected %q", name)
		}
	}
	key, _ := NewKey()
	for _, name := range bad {
		if _, err := Seal(key, name, []byte("x")); err == nil {
			t.Errorf("sealed unsafe name %q", name)
		}
	}
	if _, err := Seal(key, "x", make([]byte, MaxFileBytes+1)); err == nil {
		t.Fatal("oversized file accepted")
	}
	empty, err := Seal(key, "empty.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	n, decoded, err := Open(key, empty)
	if err != nil || n != "empty.txt" || len(decoded) != 0 {
		t.Fatalf("zero-byte transfer failed: %v", err)
	}
}
func TestLANURLRestrictions(t *testing.T) {
	valid := []string{"http://127.0.0.1:8788/send", "https://192.168.1.5:1234/send", "https://10.0.0.2:8788/send", "http://[::1]:8788/send", "https://[fd00::1]:8788/send"}
	for _, url := range valid {
		if _, err := ValidateURL(url); err != nil {
			t.Errorf("rejected valid private destination %s: %v", url, err)
		}
	}
	invalid := []string{"http://192.168.1.5:1234/send", "http://10.0.0.2:8788/send", "http://[fd00::1]:8788/send", "http://example.com:8788/send", "http://8.8.8.8:80/send", "http://0.0.0.0:9999/send", "http://127.0.0.1/send", "http://127.0.0.1:0/send", "http://127.0.0.1:99999/send", "http://127.0.0.1:80/other", "http://127.0.0.1:80/send?token=abc", "http://username:password@127.0.0.1:80/send", "http://127.0.0.1:80/send#secret", "file:///tmp/send", "http://127.0.0.1:80/send/../send"}
	for _, url := range invalid {
		if _, err := ValidateURL(url); err == nil {
			t.Errorf("accepted unsafe destination %s", url)
		}
	}
	if _, err := DecodeKey(strings.Repeat("A", 100)); err == nil {
		t.Fatal("accepted oversized secret")
	}
}
func TestUniqueKeys(t *testing.T) {
	a, _ := NewKey()
	b, _ := NewKey()
	if a == b {
		t.Fatal("random pairing secret reused")
	}
	allzero := make([]byte, 32)
	if bytes.Equal(a[:], allzero) || bytes.Equal(b[:], allzero) {
		t.Fatal("unexpected zero random key")
	}
	_ = rand.Reader
}
