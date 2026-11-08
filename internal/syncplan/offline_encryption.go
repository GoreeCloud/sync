package syncplan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/GoreeCloud/sync/internal/deviceid"
)

// ConfidentialOfflineInventoryVersion is a private transport envelope around
// the *already signed* canonical inventory. Its key is a separate out-of-band
// shared secret; device Ed25519 trust must still be checked after decryption.
const ConfidentialOfflineInventoryVersion = 2
const confidentialInventoryLegacyVersion = 1
const confidentialInventoryAlgorithm = "AES-256-GCM"
const confidentialInventoryAADV1 = "GoreeCloud Sync encrypted offline inventory v1"
const confidentialInventoryAADV2 = "GoreeCloud Sync encrypted offline inventory v2 padded"
const confidentialInventoryPadBucket = 64 << 10
const maxEncryptedInventoryBytes = 24 << 20

type confidentialOfflineInventory struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// NewPrivateInventoryKeyFile creates an independent 256-bit symmetric exchange
// key, never writing the key to stdout. Users must exchange it confidentially.
func NewPrivateInventoryKeyFile(filename string) error {
	if err := privateTicketParent(filename); err != nil {
		return err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate inventory encryption key: %w", err)
	}
	defer clear(secret[:])
	return privateNoOverwriteFile(filename, []byte(hex.EncodeToString(secret[:])+"\n"))
}

func readPrivateInventoryKey(filename string) ([32]byte, error) {
	var secret [32]byte
	if err := privateTicketParent(filename); err != nil {
		return secret, err
	}
	st, err := os.Lstat(filename)
	if err != nil {
		return secret, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() != 65 {
		return secret, errors.New("inventory key must be a private 0600 64-hex file with newline")
	}
	f, err := openProtectedRegularFile(filename)
	if err != nil {
		return secret, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) || !uniquePrivateFileLink(opened) {
		return secret, errors.New("inventory key changed, has hardlinks, or is unsafe")
	}
	encoded, err := io.ReadAll(io.LimitReader(f, 66))
	if err != nil || len(encoded) != 65 || encoded[64] != '\n' {
		return secret, errors.New("malformed inventory key")
	}
	decoded, err := hex.DecodeString(string(encoded[:64]))
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != string(encoded[:64]) {
		return secret, errors.New("inventory key must be lowercase hex")
	}
	copy(secret[:], decoded)
	clear(decoded)
	clear(encoded)
	return secret, nil
}

// ExportEncryptedChallengedOfflineInventory signs in memory, then encrypts the
// entire signed inventory without ever writing an intermediate plaintext file.
func ExportEncryptedChallengedOfflineInventory(root, destination string, excludes []string, own *deviceid.Identity, challenge, keyFile string) (OfflineInventory, error) {
	var empty OfflineInventory
	if keyFile == "" || destination == keyFile {
		return empty, errors.New("distinct private inventory key file required")
	}
	if err := ensureOutsideScanRoot(root, destination); err != nil {
		return empty, err
	}
	if err := ensureOutsideScanRoot(root, keyFile); err != nil {
		return empty, fmt.Errorf("inventory key must be stored outside scanned folder: %w", err)
	}
	secret, err := readPrivateInventoryKey(keyFile)
	if err != nil {
		return empty, err
	}
	defer clear(secret[:])
	signed, plaintext, err := buildSignedOfflineInventory(root, excludes, own, challenge)
	if err != nil {
		return empty, err
	}
	defer clear(plaintext)
	block, err := aes.NewCipher(secret[:])
	if err != nil {
		return empty, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return empty, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return empty, err
	}
	// The signed plaintext length is authenticated but not visible in the
	// outer envelope. Random padding rounds the encrypted payload to 64 KiB
	// buckets; it limits (but does not eliminate) file-count side channels.
	paddedLength := ((len(plaintext) + 4 + confidentialInventoryPadBucket - 1) / confidentialInventoryPadBucket) * confidentialInventoryPadBucket
	padded := make([]byte, paddedLength)
	defer clear(padded)
	binary.BigEndian.PutUint32(padded[:4], uint32(len(plaintext)))
	copy(padded[4:], plaintext)
	if _, err = rand.Read(padded[4+len(plaintext):]); err != nil {
		return empty, fmt.Errorf("generate encrypted inventory padding: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, padded, []byte(confidentialInventoryAADV2))
	envelope := confidentialOfflineInventory{Version: ConfidentialOfflineInventoryVersion, Algorithm: confidentialInventoryAlgorithm, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext)}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return empty, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxEncryptedInventoryBytes {
		return empty, errors.New("encrypted inventory too large")
	}
	if err = privateNoOverwriteFile(destination, encoded); err != nil {
		return empty, err
	}
	return signed, nil
}

func readOfflineBytes(filename string, max int64) ([]byte, error) {
	st, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max || st.Size() < 32 {
		return nil, errors.New("not a bounded regular inventory file")
	}
	f, err := openProtectedRegularFile(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("inventory file changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || len(data) > int(max) {
		return nil, errors.New("encrypted inventory too large or unreadable")
	}
	return data, nil
}

// ReadEncryptedOfflineInventory refuses plaintext files, verifies AES-GCM,
// and then verifies the original signed claims against the pinned peer key.
func ReadEncryptedOfflineInventory(filename, fingerprint string, pinned ed25519.PublicKey, keyFile string) (OfflineInventory, error) {
	var empty OfflineInventory
	if keyFile == "" || fingerprint != deviceid.Fingerprint(pinned) {
		return empty, errors.New("inventory key and pinned peer required")
	}
	secret, err := readPrivateInventoryKey(keyFile)
	if err != nil {
		return empty, err
	}
	defer clear(secret[:])
	encoded, err := readOfflineBytes(filename, maxEncryptedInventoryBytes)
	if err != nil {
		return empty, err
	}
	var envelope confidentialOfflineInventory
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&envelope); err != nil {
		return empty, fmt.Errorf("invalid encrypted inventory envelope: %w", err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return empty, errors.New("trailing encrypted inventory data")
	}
	if (envelope.Version != ConfidentialOfflineInventoryVersion && envelope.Version != confidentialInventoryLegacyVersion) || envelope.Algorithm != confidentialInventoryAlgorithm {
		return empty, errors.New("unsupported encrypted inventory envelope")
	}
	canonical, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil || !bytes.Equal(bytes.TrimSpace(encoded), canonical) {
		return empty, errors.New("encrypted inventory envelope must be canonical JSON without duplicated fields")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil || base64.RawURLEncoding.EncodeToString(nonce) != envelope.Nonce || len(nonce) != 12 {
		return empty, errors.New("invalid encrypted inventory nonce")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || base64.RawURLEncoding.EncodeToString(ciphertext) != envelope.Ciphertext || len(ciphertext) < 16 || len(ciphertext) > MaxBaselineBytes+16 {
		return empty, errors.New("invalid encrypted inventory ciphertext")
	}
	block, err := aes.NewCipher(secret[:])
	if err != nil {
		return empty, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return empty, err
	}
	aad := confidentialInventoryAADV2
	if envelope.Version == confidentialInventoryLegacyVersion {
		aad = confidentialInventoryAADV1
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return empty, errors.New("encrypted inventory authentication failed")
	}
	defer clear(plaintext)
	if envelope.Version == ConfidentialOfflineInventoryVersion {
		if len(plaintext) == 0 || len(plaintext)%confidentialInventoryPadBucket != 0 || len(plaintext) < 4 {
			return empty, errors.New("invalid encrypted inventory padding size")
		}
		actual := uint64(binary.BigEndian.Uint32(plaintext[:4]))
		if actual < 32 || actual > uint64(MaxBaselineBytes) || actual > uint64(len(plaintext)-4) || len(plaintext)-int(actual)-4 >= confidentialInventoryPadBucket {
			return empty, errors.New("invalid authenticated encrypted inventory length")
		}
		plaintext = plaintext[4 : 4+int(actual)]
	}
	return verifyOfflineInventoryData(plaintext, fingerprint, pinned)
}

// CompareVerifiedEncryptedOfflineInventory performs decryption, signature and
// optional challenge verification before a read-only local folder comparison.
func CompareVerifiedEncryptedOfflineInventory(root string, excludes []string, filename, fingerprint string, pinned ed25519.PublicKey, challenge, keyFile string) (OfflineComparison, error) {
	if keyFile == "" {
		return OfflineComparison{}, errors.New("encrypted inventory comparison requires key")
	}
	if err := ensureOutsideScanRoot(root, keyFile); err != nil {
		return OfflineComparison{}, fmt.Errorf("inventory key must be stored outside compared folder: %w", err)
	}
	if challenge != "" {
		if err := validateOfflineChallenge(challenge); err != nil {
			return OfflineComparison{}, err
		}
	}
	return compareVerifiedOfflineInventory(root, excludes, filename, fingerprint, pinned, challenge, keyFile)
}

// clear minimizes how long secret material remains in reachable buffers.
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
