package localsend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Identity struct {
	Alias       string
	Certificate tls.Certificate
	Fingerprint string
}

func LoadOrCreateIdentity(dir, alias string) (Identity, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Identity{}, err
	}
	certPath := filepath.Join(dir, "device.crt")
	keyPath := filepath.Join(dir, "device.key")
	certBytes, certerr := os.ReadFile(certPath)
	keyBytes, keyerr := os.ReadFile(keyPath)
	if certerr == nil && keyerr == nil {
		c, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return Identity{}, err
		}
		sum := sha256.Sum256(c.Certificate[0])
		return Identity{alias, c, hex.EncodeToString(sum[:])}, nil
	}
	if !os.IsNotExist(certerr) || !os.IsNotExist(keyerr) {
		return Identity{}, os.ErrInvalid
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Identity{}, err
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "GoreeCloud Sync"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return Identity{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Identity{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err = os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return Identity{}, err
	}
	if err = os.WriteFile(certPath, certPEM, 0600); err != nil {
		return Identity{}, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Identity{}, err
	}
	sum := sha256.Sum256(der)
	return Identity{alias, c, hex.EncodeToString(sum[:])}, nil
}
func (i Identity) Info(port int) DeviceInfo {
	return DeviceInfo{Alias: i.Alias, Version: Version, DeviceType: "desktop", Fingerprint: i.Fingerprint, Port: port, Protocol: "https"}
}
