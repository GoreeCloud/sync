package localsend

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "testing"
)

func TestReceiverRequiresExplicitConsent(t *testing.T) {
    root := t.TempDir()
    identity, err := LoadOrCreateIdentity(filepath.Join(root, "identity"), "Test")
    if err != nil { t.Fatal(err) }
    inbox := filepath.Join(root, "inbox")
    if err := os.Mkdir(inbox, 0700); err != nil { t.Fatal(err) }
    r, err := NewReceiver(identity, inbox, nil)
    if err != nil { t.Fatal(err) }
    request := PrepareRequest{Info: identity.Info(DefaultPort), Files: map[string]FileMeta{
        "one": {ID: "one", FileName: "photo.jpg", Size: 1},
    }}
    payload, err := json.Marshal(request)
    if err != nil { t.Fatal(err) }
    req := httptest.NewRequest(http.MethodPost, "/api/localsend/v2/prepare-upload", bytes.NewReader(payload))
    response := httptest.NewRecorder()
    r.Handler().ServeHTTP(response, req)
    if response.Code != http.StatusForbidden {
        t.Fatalf("expected HTTP 403, got %d", response.Code)
    }
    files, err := os.ReadDir(inbox)
    if err != nil { t.Fatal(err) }
    if len(files) != 0 { t.Fatalf("declined transfer wrote %d files", len(files)) }
}

func TestReceiverRejectsTraversalMetadata(t *testing.T) {
    root := t.TempDir()
    identity, err := LoadOrCreateIdentity(filepath.Join(root, "identity"), "Test")
    if err != nil { t.Fatal(err) }
    r, err := NewReceiver(identity, root, func(TransferRequest) bool {
        t.Error("unsafe metadata reached approval dialog")
        return true
    })
    if err != nil { t.Fatal(err) }
    payload, err := json.Marshal(PrepareRequest{Files: map[string]FileMeta{
        "one": {ID: "one", FileName: "../escape", Size: 1},
    }})
    if err != nil { t.Fatal(err) }
    req := httptest.NewRequest(http.MethodPost, "/api/localsend/v2/prepare-upload", bytes.NewReader(payload))
    response := httptest.NewRecorder()
    r.Handler().ServeHTTP(response, req)
    if response.Code != http.StatusBadRequest {
        t.Fatalf("expected HTTP 400, got %d", response.Code)
    }
}
