package localsend

import (
  "bytes"
  "context"
  "crypto/sha256"
  "crypto/tls"
  "encoding/hex"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "net"
  "net/http"
  "strconv"
  "time"
)

// Probe obtains the actual peer certificate's SHA-256 fingerprint during TLS.
// No identity trust is implied until the user verifies it out of band.
func Probe(ctx context.Context, ip net.IP, port int, me DeviceInfo) (Peer, error) {
  if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
    return Peer{}, errors.New("peer is not a local address")
  }
  if port < 1 || port > 65535 { return Peer{}, errors.New("invalid port") }
  transport := &http.Transport{
    Proxy: nil, DisableKeepAlives: true,
    TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
  }
  defer transport.CloseIdleConnections()
  client := &http.Client{Transport: transport, Timeout: 4 * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
  me.Announce = false
  payload, err := json.Marshal(me)
  if err != nil { return Peer{}, err }
  uri := "https://" + net.JoinHostPort(ip.String(), strconv.Itoa(port)) + "/api/localsend/v2/register"
  req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(payload))
  if err != nil { return Peer{}, err }
  req.Header.Set("Content-Type", "application/json")
  res, err := client.Do(req)
  if err != nil { return Peer{}, err }
  defer res.Body.Close()
  if res.StatusCode != http.StatusOK { return Peer{}, fmt.Errorf("peer registration: HTTP %d", res.StatusCode) }
  if res.TLS == nil || len(res.TLS.PeerCertificates) == 0 { return Peer{}, errors.New("missing TLS certificate") }
  body, err := io.ReadAll(io.LimitReader(res.Body, 16<<10+1))
  if err != nil || len(body) > 16<<10 { return Peer{}, errors.New("oversized peer response") }
  var info DeviceInfo
  if err := json.Unmarshal(body, &info); err != nil { return Peer{}, err }
  if info.Alias == "" || (info.Protocol != "" && info.Protocol != "https") { return Peer{}, errors.New("invalid peer identity") }
  h := sha256.Sum256(res.TLS.PeerCertificates[0].Raw)
  info.Fingerprint = hex.EncodeToString(h[:])
  info.Port = port
  info.Protocol = "https"
  return Peer{IP: append(net.IP(nil), ip...), Info: info}, nil
}
