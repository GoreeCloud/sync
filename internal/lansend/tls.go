package lansend

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// sessionTLSKey derives a purpose-separated, ephemeral TLS signing identity
// from the receiver's fresh, high-entropy one-time pairing secret. The private
// key is never stored or transmitted. Possession of this key does not confer a
// persistent trusted-device identity (that is a separate Ed25519 ceremony).
func sessionTLSKey(key [32]byte) ed25519.PrivateKey {
	seed := derive(key, "ephemeral-tls-certificate-ed25519")
	return ed25519.NewKeyFromSeed(seed[:])
}

// ServerTLSConfig creates an in-memory, self-signed TLS 1.3 certificate for
// the explicit literal listening IP. A random serial is used; the public key
// is reproducible from the one-time secret so the sender can pin it exactly.
func ServerTLSConfig(key [32]byte, ip net.IP) (*tls.Config, error) {
	if ip == nil || ip.IsUnspecified() {
		return nil, errors.New("TLS receiver requires a literal bound interface IP")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-2 * time.Minute),
		NotAfter:              now.Add(1 * time.Hour),
		IPAddresses:           []net.IP{ip},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	private := sessionTLSKey(key)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: private}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}, nil
}

// ClientTLSConfig implements explicit certificate-public-key pinning rather
// than using the public WebPKI. Verification is tied to the 256-bit session
// secret entered via stdin: an unrelated self-signed certificate is rejected.
// InsecureSkipVerify disables ONLY the default CA path; VerifyConnection
// performs mandatory, strict peer verification on every connection.
func ClientTLSConfig(key [32]byte, targetIP net.IP) (*tls.Config, error) {
	if targetIP == nil || targetIP.IsUnspecified() {
		return nil, errors.New("TLS destination requires a literal private IP")
	}
	pub := sessionTLSKey(key).Public().(ed25519.PublicKey)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true, // Mandatory VerifyConnection callback below.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.Version < tls.VersionTLS13 || len(cs.PeerCertificates) != 1 {
				return errors.New("TLS peer did not present one authenticated session certificate")
			}
			leaf := cs.PeerCertificates[0]
			peer, ok := leaf.PublicKey.(ed25519.PublicKey)
			if !ok || !bytes.Equal(pub, peer) {
				return errors.New("TLS server certificate does not match the pairing key")
			}
			if err := leaf.VerifyHostname(targetIP.String()); err != nil {
				return fmt.Errorf("TLS server IP certificate mismatch: %w", err)
			}
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errors.New("TLS session certificate is expired or not yet valid")
			}
			if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
				return fmt.Errorf("TLS session certificate signature invalid: %w", err)
			}
			return nil
		},
	}, nil
}
