package main

import (
 "bytes"
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestRunReportsCountsWithoutSensitiveFields(t *testing.T) {
 srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Header.Get("X-API-Key")!="secret" { http.Error(w,"denied",403); return }
  switch r.URL.Path {
  case "/rest/system/status": _,_=w.Write([]byte(`{"myID":"PRIVATE-IDENTIFIER","uptime":99}`))
  case "/rest/config/devices": _,_=w.Write([]byte(`[{"deviceID":"PRIVATE-PEER","paused":true},{"deviceID":"OTHER"}]`))
  case "/rest/config/folders": _,_=w.Write([]byte(`[{"id":"photos","path":"/secret/path","paused":false}]`))
  default: http.NotFound(w,r)
  }
 }))
 defer srv.Close()
 var out bytes.Buffer
 if err:=run(context.Background(),srv.URL,"secret",&out);err!=nil { t.Fatal(err) }
 var result struct {
  Online bool `json:"online"`
  DeviceCount int `json:"deviceCount"`
  FolderCount int `json:"folderCount"`
  PausedDevices int `json:"pausedDevices"`
 }
 if err:=json.Unmarshal(out.Bytes(),&result);err!=nil { t.Fatal(err) }
 if !result.Online || result.DeviceCount!=2 || result.FolderCount!=1 || result.PausedDevices!=1 {
  t.Fatalf("unexpected diagnostic result: %+v",result)
 }
 for _,secret := range []string{"PRIVATE-IDENTIFIER","PRIVATE-PEER","/secret/path","secret"} {
  if strings.Contains(out.String(),secret){t.Fatalf("leaked sensitive information %q",secret)}
 }
}

func TestRunRejectsRemoteEngine(t *testing.T) {
 var out bytes.Buffer
 if err:=run(context.Background(),"https://example.com:8384","secret",&out);err==nil{
  t.Fatal("unexpected acceptance of nonlocal engine")
 }
 if out.Len()!=0 {t.Fatal("wrote success output after error")}
}

func TestRunRequiresAPIKey(t *testing.T) {
 var out bytes.Buffer
 if err:=run(context.Background(),"http://127.0.0.1:8384","",&out);err==nil{
  t.Fatal("missing API key accepted")
 }
}
