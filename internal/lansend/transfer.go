package lansend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/GoreeCloud/sync/internal/deviceid"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Receipt struct {
	Status   string `json:"status"`
	Filename string `json:"filename"`
	Bytes    int    `json:"bytes"`
}

// SaveNew verifies the received name and size, then uses the platform-specific
// private no-overwrite destination writer. It never intentionally replaces an
// existing path. Linux/Android anchor staging to an open directory handle.
func SaveNew(root, name string, data []byte) error {
	if !ValidFilename(name) || len(data) > MaxFileBytes {
		return errors.New("invalid received file")
	}
	audit, err := AuditReceiverDirectory(root)
	if err != nil {
		return err
	}
	if audit.StageResidueCount > 0 {
		return errors.New("receiver crash staging artifact(s) require manual review before another transfer")
	}
	return saveNewPrivate(root, name, data)
}

// Receiver accepts precisely one authenticated ciphertext upload. It has no
// shared or persistent pairing state: each run gets a fresh random key.
type Receiver struct {
	identity       *deviceid.Identity
	requiredSender ed25519.PublicKey
	proofLimit     chan struct{}
	key            [32]byte
	dir            string
	limit          chan struct{}
	done           chan Receipt
	mu             sync.Mutex
	used           bool
}

func NewReceiver(dir string) (*Receiver, string, error) {
	return NewReceiverWithIdentity(dir, nil)
}

// NewReceiverWithIdentity optionally enables an authenticated public-key
// challenge endpoint. One-time transfer encryption remains independent.
func NewReceiverWithIdentity(dir string, identity *deviceid.Identity) (*Receiver, string, error) {
	return NewReceiverWithMutualAuth(dir, identity, nil)
}

// NewReceiverWithMutualAuth pins an expected sender and demands a signed
// upload proof in addition to the existing shared one-time transfer secret.
func NewReceiverWithMutualAuth(dir string, identity *deviceid.Identity, trustedSender ed25519.PublicKey) (*Receiver, string, error) {
	if trustedSender != nil && (identity == nil || len(trustedSender) != ed25519.PublicKeySize) {
		return nil, "", errors.New("mutual authentication requires receiver identity and valid pinned sender key")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", err
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, "", errors.New("receiver directory must be real and private (0700)")
	}
	// Crash residue may contain plaintext. Never start a network receiver
	// until the owner has manually inspected/reconciled staged files.
	audit, err := AuditReceiverDirectory(dir)
	if err != nil {
		return nil, "", err
	}
	if audit.StageResidueCount != 0 {
		return nil, "", fmt.Errorf("receiver has %d crash staging artifact(s); inspect with -audit-receive-dir and reconcile manually", audit.StageResidueCount)
	}
	key, err := NewKey()
	if err != nil {
		return nil, "", err
	}
	return &Receiver{identity: identity, requiredSender: append(ed25519.PublicKey(nil), trustedSender...), proofLimit: make(chan struct{}, 1), key: key, dir: dir, limit: make(chan struct{}, 1), done: make(chan Receipt, 1)}, EncodeKey(key), nil
}
func (r *Receiver) Done() <-chan Receipt { return r.done }
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if req.URL.Path == "/identity" {
		r.serveIdentity(w, req)
		return
	}
	if req.URL.Path != "/send" || req.Method != http.MethodPost {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if req.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
		return
	}
	select {
	case r.limit <- struct{}{}:
		defer func() { <-r.limit }()
	default:
		http.Error(w, "receiver busy", http.StatusTooManyRequests)
		return
	}
	r.mu.Lock()
	if r.used {
		r.mu.Unlock()
		http.Error(w, "receiver already used", http.StatusGone)
		return
	}
	r.mu.Unlock()
	if req.ContentLength > MaxEnvelopeBytes {
		http.Error(w, "ciphertext too large", http.StatusRequestEntityTooLarge)
		return
	}
	// A strict bound applies even if Content-Length is absent or deceptive.
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxEnvelopeBytes+1))
	if err != nil || len(body) > MaxEnvelopeBytes {
		http.Error(w, "invalid ciphertext", http.StatusRequestEntityTooLarge)
		return
	}
	mac := req.Header.Get("X-GC-LAN-MAC")
	if !VerifyMAC(r.key, body, mac) {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if r.requiredSender != nil {
		ticket := req.Header.Get("X-GC-Sender-Ticket")
		signatureText := req.Header.Get("X-GC-Sender-Signature")
		if req.Header.Get("X-GC-Sender-Fingerprint") != deviceid.Fingerprint(r.requiredSender) || !r.validSenderTicket(ticket) {
			http.Error(w, "sender identity not authenticated", http.StatusForbidden)
			return
		}
		signature, decodeErr := base64.RawURLEncoding.DecodeString(signatureText)
		if decodeErr != nil || !deviceid.VerifySenderProof(r.requiredSender, ticket, r.key, mac, signature) {
			http.Error(w, "sender identity not authenticated", http.StatusForbidden)
			return
		}
	}
	name, plain, err := Open(r.key, body)
	if err != nil {
		http.Error(w, "invalid encrypted file", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used {
		http.Error(w, "receiver already used", http.StatusGone)
		return
	}
	if err := SaveNew(r.dir, name, plain); err != nil {
		if errors.Is(err, os.ErrExist) {
			http.Error(w, "destination file already exists", http.StatusConflict)
		} else {
			http.Error(w, "could not save file", http.StatusInternalServerError)
		}
		return
	}
	r.used = true
	receipt := Receipt{Status: "received", Filename: name, Bytes: len(plain)}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-GC-LAN-ACK", AckHeader(r.key, mac))
	w.WriteHeader(http.StatusCreated)
	// Never echo the filename over the plaintext HTTP response. The sender
	// knows it locally and checks the keyed acknowledgment above.
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "received"})
	r.done <- receipt
}

// serveIdentity proves control of this device's Ed25519 key AND the precise
// ephemeral pairing key, without disclosing either secret. It does not make
// plaintext HTTP private or prevent an on-path relay.
func (r *Receiver) serveIdentity(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet || r.identity == nil {
		http.NotFound(w, req)
		return
	}
	select {
	case r.proofLimit <- struct{}{}:
		defer func() { <-r.proofLimit }()
	default:
		http.Error(w, "proof endpoint busy", http.StatusTooManyRequests)
		return
	}
	query := req.URL.Query()
	values := query["challenge"]
	if len(query) != 1 || len(values) != 1 || len(values[0]) != 43 {
		http.Error(w, "invalid challenge", http.StatusBadRequest)
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(decoded) != 32 {
		http.Error(w, "invalid challenge", http.StatusBadRequest)
		return
	}
	var nonce [32]byte
	copy(nonce[:], decoded)
	sig := r.identity.SignReceiverProof(nonce, r.key)
	result := map[string]any{
		"version": 1, "fingerprint": r.identity.Public().Fingerprint,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}
	if r.requiredSender != nil {
		var ticketNonce [32]byte
		if _, err := rand.Read(ticketNonce[:]); err != nil {
			http.Error(w, "random source unavailable", 500)
			return
		}
		mac := macBytes(r.key, "sender-ticket", ticketNonce[:])
		ticket := append(ticketNonce[:], mac...)
		result["requireSender"] = true
		result["senderTicket"] = base64.RawURLEncoding.EncodeToString(ticket)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// The ticket is a receiver-MACed 256-bit nonce. It is valid for only this
// receiver process and is cryptographically bound to its one-time key.
func (r *Receiver) validSenderTicket(ticket string) bool {
	return validSenderTicketForKey(r.key, ticket)
}
func validSenderTicketForKey(key [32]byte, ticket string) bool {
	if len(ticket) != 86 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil || len(raw) != 64 {
		return false
	}
	expected := macBytes(key, "sender-ticket", raw[:32])
	return subtle.ConstantTimeCompare(expected, raw[32:]) == 1
}

// verifyPinnedReceiver must complete before uploading any ciphertext. The
// signed challenge is bound to the receiver's fresh one-time key. A signature
// does not protect URL routing after this check; use a trusted network only.
type receiverIdentityProof struct {
	RequireSender bool   `json:"requireSender"`
	SenderTicket  string `json:"senderTicket"`
}

func verifyPinnedReceiver(ctx context.Context, client *http.Client, endpoint *url.URL, key [32]byte, pub ed25519.PublicKey) (receiverIdentityProof, error) {
	var out receiverIdentityProof
	if len(pub) != ed25519.PublicKeySize {
		return out, errors.New("invalid pinned device public key")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return out, err
	}
	identityURL := *endpoint
	identityURL.Path = "/identity"
	identityURL.RawQuery = "challenge=" + base64.RawURLEncoding.EncodeToString(nonce[:])
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, identityURL.String(), nil)
	if err != nil {
		return out, err
	}
	response, err := client.Do(request)
	if err != nil {
		return out, fmt.Errorf("trusted receiver identity proof unavailable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return out, fmt.Errorf("trusted receiver identity proof refused (HTTP %d)", response.StatusCode)
	}
	var result struct {
		Version       int    `json:"version"`
		Fingerprint   string `json:"fingerprint"`
		Signature     string `json:"signature"`
		RequireSender bool   `json:"requireSender"`
		SenderTicket  string `json:"senderTicket"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&result); err != nil {
		return out, fmt.Errorf("invalid receiver identity response: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(result.Signature)
	if err != nil || result.Version != 1 || result.Fingerprint != deviceid.Fingerprint(pub) || !deviceid.VerifyReceiverProof(pub, nonce, key, signature) {
		return out, errors.New("receiver device identity not authenticated; encrypted upload refused")
	}
	if result.RequireSender && len(result.SenderTicket) != 86 {
		return out, errors.New("receiver required sender proof but did not provide a valid ticket")
	}
	if !result.RequireSender && result.SenderTicket != "" {
		return out, errors.New("unexpected sender challenge in receiver proof")
	}
	return receiverIdentityProof{RequireSender: result.RequireSender, SenderTicket: result.SenderTicket}, nil
}

// SendFile reads a bounded, regular file from disk and checks its identity and
// size before encrypted upload. It never follows HTTP redirects or a proxy.
func SendFile(ctx context.Context, endpoint, encodedKey, source string) (Receipt, error) {
	return SendFileWithPinnedReceiver(ctx, endpoint, encodedKey, source, nil)
}

// SendFileWithPinnedReceiver additionally requires a fresh proof by the
// previously pinned Ed25519 receiver key when public is non-nil.
func SendFileWithPinnedReceiver(ctx context.Context, endpoint, encodedKey, source string, public ed25519.PublicKey) (Receipt, error) {
	return sendFileAuthenticated(ctx, endpoint, encodedKey, source, public, nil)
}

// SendFileWithMutualAuth requires both the receiver's pinned proof and the
// receiver's request for a signature by the local sending device identity.
func SendFileWithMutualAuth(ctx context.Context, endpoint, encodedKey, source string, public ed25519.PublicKey, own *deviceid.Identity) (Receipt, error) {
	if own == nil || len(public) != ed25519.PublicKeySize {
		return Receipt{}, errors.New("mutual authentication requires local identity and pinned receiver")
	}
	return sendFileAuthenticated(ctx, endpoint, encodedKey, source, public, own)
}
func sendFileAuthenticated(ctx context.Context, endpoint, encodedKey, source string, public ed25519.PublicKey, own *deviceid.Identity) (Receipt, error) {
	var out Receipt
	u, err := ValidateURL(endpoint)
	if err != nil {
		return out, err
	}
	key, err := DecodeKey(encodedKey)
	if err != nil {
		return out, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: 30 * time.Second}
	if u.Scheme == "https" {
		host, _, _ := net.SplitHostPort(u.Host) // ValidateURL has already checked this.
		transport.TLSClientConfig, err = ClientTLSConfig(key, net.ParseIP(host))
		if err != nil {
			return out, err
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("redirects not allowed") }}
	var proof receiverIdentityProof
	if public != nil {
		proof, err = verifyPinnedReceiver(ctx, client, u, key, public)
		if err != nil {
			return out, err
		}
		if proof.RequireSender != (own != nil) {
			return out, errors.New("receiver sender-authentication policy mismatch; refusing upload")
		}
		if proof.RequireSender && !validSenderTicketForKey(key, proof.SenderTicket) {
			return out, errors.New("receiver sender-authentication ticket invalid for this one-time transfer key")
		}
	} else if own != nil {
		return out, errors.New("mutual sender identity requires a pinned receiver")
	}
	data, err := readStableSenderSource(source)
	if err != nil {
		return out, err
	}
	envelope, err := Seal(key, filepath.Base(source), data)
	if err != nil {
		return out, err
	}
	mac := MACHeader(key, envelope)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(envelope))
	if err != nil {
		return out, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-GC-LAN-MAC", mac)
	if own != nil {
		signature := own.SignSenderProof(proof.SenderTicket, key, mac)
		request.Header.Set("X-GC-Sender-Fingerprint", own.Public().Fingerprint)
		request.Header.Set("X-GC-Sender-Ticket", proof.SenderTicket)
		request.Header.Set("X-GC-Sender-Signature", base64.RawURLEncoding.EncodeToString(signature))
	}
	response, err := client.Do(request)
	if err != nil {
		return out, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return out, fmt.Errorf("transfer refused (HTTP %d): %s", response.StatusCode, strings.TrimSpace(string(msg)))
	}
	if !VerifyAck(key, mac, response.Header.Get("X-GC-LAN-ACK")) {
		return out, errors.New("receiver success acknowledgment authentication failed")
	}
	if response.ContentLength > 4096 {
		return out, errors.New("receiver response too large")
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&status); err != nil {
		return out, err
	}
	if status.Status != "received" {
		return out, errors.New("receiver status mismatch")
	}
	// The authenticated ACK binds success to this specific encrypted request;
	// do not require or trust a plaintext filename echoed over the network.
	return Receipt{Status: "received", Filename: filepath.Base(source), Bytes: len(data)}, nil
}

// ReceiveOnce binds only after explicit command invocation and exits after one
// valid transfer or cancellation. Non-loopback binding requires allowLAN.
func ReceiveOnce(ctx context.Context, address, dir string, allowLAN bool, announce io.Writer) (Receipt, error) {
	return ReceiveOnceWithIdentity(ctx, address, dir, allowLAN, announce, nil)
}

// ReceiveOnceWithIdentity adds optional persistent receiver proof while
// keeping the listener one-shot and disabled for LAN without explicit opt-in.
func ReceiveOnceWithIdentity(ctx context.Context, address, dir string, allowLAN bool, announce io.Writer, identity *deviceid.Identity) (Receipt, error) {
	return ReceiveOnceWithMutualAuth(ctx, address, dir, allowLAN, announce, identity, nil)
}

// ReceiveOnceWithMutualAuth refuses clients unless their Ed25519 key matches
// the manually pinned expected sender. The receiver still exits after one file.
func ReceiveOnceWithMutualAuth(ctx context.Context, address, dir string, allowLAN bool, announce io.Writer, identity *deviceid.Identity, trustedSender ed25519.PublicKey) (Receipt, error) {
	return ReceiveOnceWithTransport(ctx, address, dir, allowLAN, false, announce, identity, trustedSender)
}

// ReceiveOnceWithTransport enables TLS 1.3 pinned by the one-time pairing key.
// Non-loopback LAN receivers MUST enable secureTransport, even if allowLAN is true.
func ReceiveOnceWithTransport(ctx context.Context, address, dir string, allowLAN, secureTransport bool, announce io.Writer, identity *deviceid.Identity, trustedSender ed25519.PublicKey) (Receipt, error) {
	var empty Receipt
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return empty, err
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return empty, errors.New("invalid receive port")
	}
	ip := net.ParseIP(host)
	if ip == nil || (!ip.IsLoopback() && !allowLAN) {
		return empty, errors.New("non-loopback receiver requires -allow-lan and a literal IP address")
	}
	if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
		return empty, errors.New("public listener addresses are unsupported")
	}
	if !ip.IsLoopback() && !secureTransport {
		return empty, errors.New("non-loopback Nearby Send requires -receive-tls")
	}
	if ip.IsUnspecified() {
		return empty, errors.New("bind a specific private interface; wildcard listeners cannot be announced safely")
	}
	receiver, key, err := NewReceiverWithMutualAuth(dir, identity, trustedSender)
	if err != nil {
		return empty, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return empty, err
	}
	defer listener.Close()
	server := &http.Server{Handler: receiver, ReadTimeout: 60 * time.Second, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	scheme := "http://"
	if secureTransport {
		tlsConfig, tlsErr := ServerTLSConfig(receiver.key, ip)
		if tlsErr != nil {
			return empty, fmt.Errorf("secure receiver setup failed: %w", tlsErr)
		}
		listener = tls.NewListener(listener, tlsConfig)
		scheme = "https://"
	}
	errorsCh := make(chan error, 1)
	go func() { errorsCh <- server.Serve(listener) }()
	// The secret is printed locally and never sent to the peer over HTTP.
	payload := struct {
		Listen            string `json:"listen"`
		PairingKey        string `json:"pairingKey"`
		DeviceFingerprint string `json:"deviceFingerprint,omitempty"`
		RequireSender     bool   `json:"requireSender,omitempty"`
	}{Listen: scheme + listener.Addr().String() + "/send", PairingKey: key}
	if identity != nil {
		payload.DeviceFingerprint = identity.Public().Fingerprint
	}
	if trustedSender != nil {
		payload.RequireSender = true
	}
	if err := json.NewEncoder(announce).Encode(payload); err != nil {
		server.Close()
		return empty, err
	}
	var receipt Receipt
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case receipt = <-receiver.Done():
		err = nil
	case serveErr := <-errorsCh:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			err = serveErr
		} else {
			err = errors.New("receiver stopped before accepting a file")
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
		// A stalled unauthenticated HTTP request must not keep the receiver
		// listener alive past shutdown. This intentionally drops connections.
		_ = server.Close()
	}
	return receipt, err
}
