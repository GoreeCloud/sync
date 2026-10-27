package localsend

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type receivedFile struct {
	meta  FileMeta
	token string
	used  bool
}
type uploadSession struct {
	files   map[string]*receivedFile
	expires time.Time
}
type Receiver struct {
	Identity Identity
	Inbox    string
	Approve  func(TransferRequest) bool
	mu       sync.Mutex
	sessions map[string]*uploadSession
}

func NewReceiver(identity Identity, inbox string, approve func(TransferRequest) bool) (*Receiver, error) {
	if inbox == "" {
		return nil, errors.New("select an inbox directory before receiving")
	}
	info, err := os.Stat(inbox)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("inbox is not a directory")
	}
	return &Receiver{Identity: identity, Inbox: inbox, Approve: approve, sessions: make(map[string]*uploadSession)}, nil
}
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/localsend/v2/info", r.info)
	mux.HandleFunc("/api/localsend/v2/register", r.register)
	mux.HandleFunc("/api/localsend/v2/prepare-upload", r.prepare)
	mux.HandleFunc("/api/localsend/v2/upload", r.upload)
	mux.HandleFunc("/api/localsend/v2/cancel", r.cancel)
	return mux
}
func (r *Receiver) Serve(ctx context.Context, address string) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{r.Identity.Certificate}, MinVersion: tls.VersionTLS12})
	server := &http.Server{Handler: r.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err = server.Serve(tlsLn)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func (r *Receiver) info(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	replyJSON(w, r.Identity.Info(DefaultPort))
}
func (r *Receiver) register(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	var peer DeviceInfo
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 16<<10)).Decode(&peer); err != nil {
		http.Error(w, "bad metadata", 400)
		return
	}
	replyJSON(w, r.Identity.Info(DefaultPort))
}
func (r *Receiver) prepare(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	var p PrepareRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 64<<10)).Decode(&p); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if len(p.Files) == 0 || len(p.Files) > 64 {
		http.Error(w, "invalid file count", 400)
		return
	}
	info := TransferRequest{Sender: p.Info}
	var total int64
	for id, f := range p.Files {
		if id == "" || id != f.ID || safeName(f.FileName) != nil || f.Size < 0 || f.Size > MaxTransferBytes {
			http.Error(w, "invalid file metadata", 400)
			return
		}
		if total > MaxTransferBytes-f.Size {
			http.Error(w, "batch exceeds size limit", 400)
			return
		}
		total += f.Size
		info.Names = append(info.Names, f.FileName)
	}
	info.TotalBytes = total
	if r.Approve == nil || !r.Approve(info) {
		http.Error(w, "transfer declined", 403)
		return
	}
	sessionID, err := randomToken()
	if err != nil {
		http.Error(w, "server unavailable", 500)
		return
	}
	resp := PrepareResponse{SessionID: sessionID, Files: make(map[string]string)}
	sess := &uploadSession{files: make(map[string]*receivedFile), expires: time.Now().Add(15 * time.Minute)}
	for id, f := range p.Files {
		token, err := randomToken()
		if err != nil {
			http.Error(w, "server unavailable", 500)
			return
		}
		resp.Files[id] = token
		sess.files[id] = &receivedFile{meta: f, token: token}
	}
	r.mu.Lock()
	for k, s := range r.sessions {
		if time.Now().After(s.expires) {
			delete(r.sessions, k)
		}
	}
	r.sessions[sessionID] = sess
	r.mu.Unlock()
	replyJSON(w, resp)
}
func (r *Receiver) upload(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	sid, id, token := req.URL.Query().Get("sessionId"), req.URL.Query().Get("fileId"), req.URL.Query().Get("token")
	r.mu.Lock()
	s := r.sessions[sid]
	var f *receivedFile
	if s != nil && time.Now().Before(s.expires) {
		f = s.files[id]
	}
	if f == nil || f.used || subtle.ConstantTimeCompare([]byte(token), []byte(f.token)) != 1 {
		r.mu.Unlock()
		http.Error(w, "invalid session or token", 403)
		return
	}
	f.used = true
	r.mu.Unlock()
	if req.ContentLength >= 0 && req.ContentLength != f.meta.Size {
		http.Error(w, "size mismatch", 400)
		return
	}
	tmp, err := os.CreateTemp(r.Inbox, ".goreecloud-sync-*.part")
	if err != nil {
		http.Error(w, "cannot create temp file", 500)
		return
	}
	tempName := tmp.Name()
	defer os.Remove(tempName)
	_ = tmp.Chmod(0600)
	hash := sha256.New()
	n, copyErr := io.CopyN(io.MultiWriter(tmp, hash), req.Body, f.meta.Size)
	var extra [1]byte
	more, readErr := req.Body.Read(extra[:])
	closeErr := tmp.Close()
	if copyErr != nil || n != f.meta.Size || more != 0 || readErr != io.EOF || closeErr != nil {
		http.Error(w, "incomplete upload", 400)
		return
	}
	if want := strings.ToLower(f.meta.SHA256); want != "" {
		actual := hex.EncodeToString(hash.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(want), []byte(actual)) != 1 {
			http.Error(w, "checksum mismatch", 422)
			return
		}
	}
	// Hard-linking creates the destination exclusively: never overwrite existing data.
	suffix, err := randomToken()
	if err != nil {
		http.Error(w, "cannot name file", 500)
		return
	}
	ext := filepath.Ext(f.meta.FileName)
	stem := strings.TrimSuffix(f.meta.FileName, ext)
	target := filepath.Join(r.Inbox, fmt.Sprintf("%s-%s%s", stem, suffix[:12], ext))
	if err := os.Link(tempName, target); err != nil {
		http.Error(w, "cannot commit file", 500)
		return
	}
	w.WriteHeader(http.StatusOK)
}
func (r *Receiver) cancel(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.mu.Lock()
	delete(r.sessions, req.URL.Query().Get("sessionId"))
	r.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}
func replyJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
