// Package lansend implements a manually started, one-file, one-time encrypted
// LAN transfer. It intentionally provides no discovery, persistent pairing,
// continuous syncing, or public-internet service.
package lansend

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxFileBytes = 20 << 20
const maxNameBytes = 240
const MaxEnvelopeBytes = MaxFileBytes + maxNameBytes + 2 + 5 + 12 + 16
const magic = "GCSL1"

func NewKey() ([32]byte, error) {
	var key [32]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	return key, err
}
func EncodeKey(key [32]byte) string { return base64.RawURLEncoding.EncodeToString(key[:]) }
func DecodeKey(encoded string) ([32]byte, error) {
	var key [32]byte
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != len(key) {
		return key, errors.New("pairing key must be a base64url-encoded 256-bit secret")
	}
	copy(key[:], raw)
	return key, nil
}
func derive(key [32]byte, label string) [32]byte {
	h := sha256.New()
	h.Write([]byte("GoreeCloud Sync LAN v1 | " + label + " | "))
	h.Write(key[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
func macBytes(key [32]byte, label string, data []byte) []byte {
	derived := derive(key, label)
	h := hmac.New(sha256.New, derived[:])
	h.Write(data)
	return h.Sum(nil)
}
func VerifyMAC(key [32]byte, envelope []byte, encoded string) bool {
	supplied, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(supplied) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(supplied, macBytes(key, "request", envelope)) == 1
}
func MACHeader(key [32]byte, envelope []byte) string {
	return base64.RawURLEncoding.EncodeToString(macBytes(key, "request", envelope))
}
func AckHeader(key [32]byte, requestMAC string) string {
	return base64.RawURLEncoding.EncodeToString(macBytes(key, "ack", []byte(requestMAC)))
}
func VerifyAck(key [32]byte, requestMAC, ack string) bool {
	actual, err := base64.RawURLEncoding.DecodeString(ack)
	expected := macBytes(key, "ack", []byte(requestMAC))
	return err == nil && len(actual) == sha256.Size && subtle.ConstantTimeCompare(actual, expected) == 1
}

func ValidFilename(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > maxNameBytes || !utf8.ValidString(name) || strings.TrimSpace(name) != name || strings.ContainsAny(name, "/\\:") || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return false
		}
	}
	// Avoid device names when files later move to Windows; never create these.
	stem := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" {
		return false
	}
	if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9' {
		return false
	}
	return true
}

// Seal encrypts filename AND file bytes. The pairing key is not placed on wire.
// Unique random nonces and a single-use receiver protect against nonce reuse.
func Seal(key [32]byte, filename string, data []byte) ([]byte, error) {
	if !ValidFilename(filename) {
		return nil, errors.New("unsafe filename")
	}
	if len(data) > MaxFileBytes {
		return nil, errors.New("file exceeds 20 MiB LAN Send limit")
	}
	plain := make([]byte, 2+len(filename)+len(data))
	binary.BigEndian.PutUint16(plain[:2], uint16(len(filename)))
	copy(plain[2:], filename)
	copy(plain[2+len(filename):], data)
	derived := derive(key, "encryption")
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	envelope := append([]byte(magic), nonce...)
	return aead.Seal(envelope, nonce, plain, []byte(magic)), nil
}
func Open(key [32]byte, envelope []byte) (string, []byte, error) {
	if len(envelope) < len(magic)+12+16+3 || len(envelope) > MaxEnvelopeBytes || !bytes.HasPrefix(envelope, []byte(magic)) {
		return "", nil, errors.New("invalid ciphertext envelope")
	}
	derived := derive(key, "encryption")
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		return "", nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}
	start := len(magic) + aead.NonceSize()
	plain, err := aead.Open(nil, envelope[len(magic):start], envelope[start:], []byte(magic))
	if err != nil {
		return "", nil, errors.New("file authentication failed")
	}
	if len(plain) < 3 {
		return "", nil, errors.New("encrypted payload truncated")
	}
	nameLen := int(binary.BigEndian.Uint16(plain[:2]))
	if nameLen < 1 || 2+nameLen > len(plain) || len(plain)-2-nameLen > MaxFileBytes {
		return "", nil, errors.New("invalid encrypted file payload")
	}
	name := string(plain[2 : 2+nameLen])
	if !ValidFilename(name) {
		return "", nil, errors.New("unsafe encrypted filename")
	}
	return name, plain[2+nameLen:], nil
}

// ValidateURL deliberately disallows public destinations, URL credentials,
// redirects, DNS, and non-IP hosts in this early LAN prototype.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/send" || u.RawPath != "" {
		return nil, errors.New("expected http:// or https://<private-ip>:<port>/send with no credentials, query or fragment")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || port == "" {
		return nil, errors.New("LAN Send URL must contain an IP address and port")
	}
	ip := net.ParseIP(host)
	number, pErr := strconv.Atoi(port)
	if pErr != nil || number < 1 || number > 65535 || ip == nil || (!ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()) {
		return nil, fmt.Errorf("LAN Send accepts only loopback or private/link-local IP destinations")
	}
	if u.Scheme == "http" && !ip.IsLoopback() {
		return nil, errors.New("non-loopback LAN Send requires session-pinned HTTPS")
	}
	return u, nil
}
