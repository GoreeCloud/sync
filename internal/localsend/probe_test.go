package localsend

import (
 "context"
 "crypto/tls"
 "encoding/json"
 "net"
 "net/http"
 "net/http/httptest"
 "path/filepath"
 "strconv"
 "strings"
 "testing"
)

func probeServer(t *testing.T, handler http.Handler) (*httptest.Server, net.IP, int, Identity) {
 t.Helper()
 identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "cert"), "Receiver")
 if err != nil { t.Fatal(err) }
 server := httptest.NewUnstartedServer(handler)
 server.TLS = &tls.Config{Certificates: []tls.Certificate{identity.Certificate}, MinVersion: tls.VersionTLS12}
 server.StartTLS()
 t.Cleanup(server.Close)
 host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
 if err != nil { t.Fatal(err) }
 port, err := strconv.Atoi(portText)
 if err != nil { t.Fatal(err) }
 return server, net.ParseIP(host), port, identity
}

func TestProbeUsesCertificateNotAnnouncementFingerprint(t *testing.T) {
 handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if r.Method != http.MethodPost || r.URL.Path != "/api/localsend/v2/register" {
   http.Error(w, "incorrect endpoint", 404); return
  }
  _ = json.NewEncoder(w).Encode(DeviceInfo{Alias: "Verified endpoint", Protocol: "https", Fingerprint: strings.Repeat("f",64)})
 })
 _, ip, port, actual := probeServer(t, handler)
 peer, err := Probe(context.Background(), ip, port, actual.Info(DefaultPort))
 if err != nil { t.Fatal(err) }
 if peer.Info.Fingerprint != actual.Fingerprint { t.Fatal("trusted unverified advertised fingerprint") }
 if peer.Info.Alias != "Verified endpoint" || peer.Info.Port != port || peer.Info.Protocol != "https" { t.Fatalf("unexpected peer %+v", peer) }
}

func TestProbeRejectsDowngradeAndRedirect(t *testing.T) {
 for _, tc := range []struct{name string; handler http.Handler}{
  {"downgrade", http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
    _ = json.NewEncoder(w).Encode(DeviceInfo{Alias: "bad", Protocol:"http"})
  })},
  {"redirect", http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
    http.Redirect(w,r,"http://example.com",http.StatusFound)
  })},
  {"oversize", http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
    _,_ = w.Write([]byte(strings.Repeat("x",17000)))
  })},
 }{
  t.Run(tc.name,func(t *testing.T){
   _,ip,port,id := probeServer(t,tc.handler)
   if _,err := Probe(context.Background(),ip,port,id.Info(DefaultPort));err==nil { t.Fatal("unsafe registration accepted") }
  })
 }
}

func TestProbeRejectsNonlocalIP(t *testing.T) {
 if _,err := Probe(context.Background(),net.ParseIP("198.51.100.2"),DefaultPort,DeviceInfo{});err==nil { t.Fatal("accepted public destination") }
}
