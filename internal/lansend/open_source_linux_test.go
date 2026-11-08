//go:build linux || android

package lansend

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSenderSourceRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := privateDir(t)
	fifo := filepath.Join(dir, "socket-like.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openSenderSource(fifo)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted FIFO as sender source")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sender blocked opening FIFO")
	}
	if st, err := os.Lstat(fifo); err != nil || st.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("source FIFO unexpectedly mutated")
	}
}
