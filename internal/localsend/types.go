package localsend

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"strings"
)

const (
	DefaultPort            = 53317
	MaxTransferBytes int64 = 10 << 30
	Version                = "2.0"
)

type DeviceInfo struct {
	Alias       string `json:"alias"`
	Version     string `json:"version"`
	DeviceModel string `json:"deviceModel,omitempty"`
	DeviceType  string `json:"deviceType,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Download    bool   `json:"download"`
	Announce    bool   `json:"announce,omitempty"`
}

type Peer struct {
	IP   net.IP
	Info DeviceInfo
}

type FileMeta struct {
	ID       string `json:"id"`
	FileName string `json:"fileName"`
	Size     int64  `json:"size"`
	FileType string `json:"fileType,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

type PrepareRequest struct {
	Info  DeviceInfo          `json:"info"`
	Files map[string]FileMeta `json:"files"`
}

type PrepareResponse struct {
	SessionID string            `json:"sessionId"`
	Files     map[string]string `json:"files"`
}

type TransferRequest struct {
	Sender     DeviceInfo
	Names      []string
	TotalBytes int64
}

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func safeName(s string) error {
	if s == "" || s == "." || s == ".." || len(s) > 255 || filepath.Base(s) != s ||
		strings.ContainsAny(s, "/\\\x00\r\n") {
		return errors.New("unsafe file name")
	}
	if strings.ContainsAny(s, ":*?\"<>|") || strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
		return errors.New("unsafe portable file name")
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return errors.New("control character in file name")
		}
	}
	return nil
}
