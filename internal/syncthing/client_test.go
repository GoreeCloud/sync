package syncthing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientReadOnlyEndpoints(t *testing.T) {
	paths := map[string]any{
		"/rest/system/status":  Status{MyID: "TEST-DEVICE", Uptime: 60},
		"/rest/config/devices": []Device{{DeviceID: "PEER", Name: "Family laptop"}},
		"/rest/config/folders": []Folder{{ID: "family", Label: "Family", Path: "/test/family"}},
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-secret" {
			http.Error(w, "unauthorized", 403)
			return
		}
		v, ok := paths[r.URL.Path]
		if !ok || r.Method != http.MethodGet {
			http.Error(w, "not found", 404)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}))
	defer s.Close()
	c, err := NewClient(s.URL, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	status, err := c.Status(context.Background())
	if err != nil || status.MyID != "TEST-DEVICE" {
		t.Fatalf("status %v %v", status, err)
	}
	devices, err := c.Devices(context.Background())
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices %v %v", devices, err)
	}
	folders, err := c.Folders(context.Background())
	if err != nil || len(folders) != 1 {
		t.Fatalf("folders %v %v", folders, err)
	}
}
func TestRemoteAPIRejected(t *testing.T) {
	for _, u := range []string{"http://example.com:8384", "http://192.168.1.20:8384", "http://127.0.0.1:8384/path", "file:///etc/passwd"} {
		if _, e := NewClient(u, "key"); e == nil {
			t.Errorf("accepted remote/malformed URL %q", u)
		}
	}
	if _, e := NewClient("http://127.0.0.1:8384", ""); e == nil || !strings.Contains(e.Error(), "key") {
		t.Fatalf("missing key was accepted: %v", e)
	}
}
