// GoreeCloud Sync local engine diagnostics (read-only).
package main

import (
 "context"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "time"

 "github.com/GoreeCloud/sync/internal/syncthing"
)

// run is intentionally read-only and emits no device IDs, paths or credentials.
func run(ctx context.Context, endpoint, key string, output io.Writer) error {
 if endpoint == "" { endpoint = "http://127.0.0.1:8384" }
 client, err := syncthing.NewClient(endpoint,key)
 if err != nil { return err }
 report, err := client.Snapshot(ctx)
 if err != nil { return err }
 return json.NewEncoder(output).Encode(report)
}

func main() {
 ctx,cancel := context.WithTimeout(context.Background(),12*time.Second)
 defer cancel()
 if err := run(ctx,os.Getenv("GCSYNC_API_URL"),os.Getenv("GCSYNC_API_KEY"),os.Stdout);err!=nil {
  fmt.Fprintln(os.Stderr,"GoreeCloud Sync check failed:",err)
  os.Exit(1)
 }
}
