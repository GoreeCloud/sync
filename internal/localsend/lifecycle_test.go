package localsend

import (
 "context"
 "net"
 "os"
 "strings"
 "path/filepath"
 "testing"
 "time"
)

func TestStartStopReceivingReleasesPort(t *testing.T) {
 root := t.TempDir()
 id, err := LoadOrCreateIdentity(filepath.Join(root,"id"),"Test")
 if err != nil { t.Fatal(err) }
 inbox := filepath.Join(root,"inbox")
 if err := os.Mkdir(inbox,0700); err != nil { t.Fatal(err) }
 r, err := NewReceiver(id,inbox,func(TransferRequest) bool { return true })
 if err != nil { t.Fatal(err) }
 running, err := StartReceiving(context.Background(),r,"127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 if _,err := StartReceiving(context.Background(),r,running.Address().String());err==nil {
  t.Fatal("second receiver occupied same port")
 }
 ctx,cancel := context.WithTimeout(context.Background(),5*time.Second)
 defer cancel()
 if err := running.Stop(ctx);err!=nil { t.Fatal(err) }
 if err := running.Stop(ctx);err!=nil { t.Fatal(err) }
 ln,err := net.Listen("tcp",running.Address().String())
 if err!=nil { t.Fatalf("port not released: %v",err) }
 _ = ln.Close()
}

func TestStartReceivingRejectsCanceledContext(t *testing.T) {
 ctx,stop := context.WithCancel(context.Background())
 stop()
 if _,err := StartReceiving(ctx,&Receiver{},"127.0.0.1:0");err==nil {
  t.Fatal("accepted canceled startup")
 }
}

func TestStartReceivingRequiresReceiver(t *testing.T) {
 if _,err := StartReceiving(context.Background(),nil,"127.0.0.1:0");err==nil {
  t.Fatal("accepted nil receiver")
 }
}

func TestStartReceivingSupportsEncryptedTransfer(t *testing.T) {
 root := t.TempDir()
 identity,err := LoadOrCreateIdentity(filepath.Join(root,"id"),"Test")
 if err!=nil {t.Fatal(err)}
 inbox:=filepath.Join(root,"inbox")
 if err:=os.Mkdir(inbox,0700);err!=nil {t.Fatal(err)}
 receiver,err := NewReceiver(identity,inbox,func(offer TransferRequest) bool {
  return offer.TotalBytes==5 && len(offer.Names)==1 && offer.Names[0]=="hello.txt"
 })
 if err!=nil {t.Fatal(err)}
 running,err := StartReceiving(context.Background(),receiver,"127.0.0.1:0")
 if err!=nil {t.Fatal(err)}
 defer func(){
  ctx,stop := context.WithTimeout(context.Background(),5*time.Second)
  defer stop()
  if err:=running.Stop(ctx);err!=nil {t.Error(err)}
 }()
 file:=filepath.Join(root,"hello.txt")
 if err:=os.WriteFile(file,[]byte("hello"),0600);err!=nil {t.Fatal(err)}
 addr,ok := running.Address().(*net.TCPAddr)
 if !ok { t.Fatal("expected TCP listener") }
 peer:=Peer{IP:net.ParseIP("127.0.0.1"),Info:identity.Info(addr.Port)}
 if err:=Send(context.Background(),peer,identity.Info(DefaultPort),file);err!=nil {t.Fatal(err)}
 received,err:=os.ReadDir(inbox)
 if err!=nil {t.Fatal(err)}
 if len(received)!=1 || !strings.HasPrefix(received[0].Name(),"hello-"){
  t.Fatalf("unexpected inbox files: %v",received)
 }
 data,err:=os.ReadFile(filepath.Join(inbox,received[0].Name()))
 if err!=nil || string(data)!="hello" { t.Fatalf("corrupt transfer: %q %v",data,err) }
}
