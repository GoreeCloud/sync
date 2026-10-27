package localsend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Send(ctx context.Context, p Peer, me DeviceInfo, filePath string) error {
	ip := p.IP
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return errors.New("only directly connected local-network peers are supported")
	}
	if p.Info.Protocol != "https" || p.Info.Port < 1 || p.Info.Port > 65535 {
		return errors.New("secure LocalSend peer and port required")
	}
	fingerprint := strings.ToLower(strings.ReplaceAll(p.Info.Fingerprint, ":", ""))
	if len(fingerprint) != 64 {
		return errors.New("missing HTTPS certificate fingerprint")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return err
	}
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() > MaxTransferBytes {
		return errors.New("regular file exceeds transfer limit")
	}
	name := filepath.Base(filePath)
	if err = safeName(name); err != nil {
		return err
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, f); err != nil {
		return err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	id, err := randomToken()
	if err != nil {
		return err
	}
	fileType := mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
	if fileType == "" {
		fileType = "application/octet-stream"
	}
	request := PrepareRequest{Info: me, Files: map[string]FileMeta{
		id: {ID: id, FileName: name, Size: stat.Size(), FileType: fileType, SHA256: hex.EncodeToString(digest.Sum(nil))},
	}}
	// The advertised certificate hash is the only authority for LocalSend self-signed TLS.
	// InsecureSkipVerify disables PKI trust only; pin verification below is mandatory.
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("peer sent no TLS certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(fingerprint)) != 1 {
				return errors.New("peer certificate fingerprint changed")
			}
			return nil
		},
	}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 0, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	base := "https://" + net.JoinHostPort(ip.String(), fmt.Sprintf("%d", p.Info.Port))
	b, err := json.Marshal(request)
	if err != nil {
		return err
	}
	setupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	prepReq, err := http.NewRequestWithContext(setupCtx, http.MethodPost, base+"/api/localsend/v2/prepare-upload", bytes.NewReader(b))
	if err != nil {
		return err
	}
	prepReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(prepReq)
	if err != nil {
		return fmt.Errorf("prepare send: %w", err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return fmt.Errorf("receiver declined or could not prepare (HTTP %d)", resp.StatusCode)
	}
	var accepted PrepareResponse
	err = json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&accepted)
	resp.Body.Close()
	if err != nil {
		return err
	}
	token := accepted.Files[id]
	if accepted.SessionID == "" || token == "" {
		return errors.New("receiver omitted session or file token")
	}
	q := url.Values{"sessionId": {accepted.SessionID}, "fileId": {id}, "token": {token}}
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/localsend/v2/upload?"+q.Encode(), f)
	if err != nil {
		return err
	}
	putReq.ContentLength = stat.Size()
	putReq.Header.Set("Content-Type", "application/octet-stream")
	result, err := client.Do(putReq)
	if err != nil {
		return fmt.Errorf("file send interrupted: %w", err)
	}
	defer result.Body.Close()
	if result.StatusCode != 200 {
		return fmt.Errorf("file transfer failed (HTTP %d)", result.StatusCode)
	}
	return nil
}
