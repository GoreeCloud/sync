package localsend

import (
 "context"
 "net"
 "os"
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
