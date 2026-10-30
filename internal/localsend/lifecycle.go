package localsend

import (
 "context"
 "errors"
 "net"
 "sync"
)

// RunningReceiver owns a single HTTPS listener and its lifetime.
type RunningReceiver struct {
 address net.Addr
 cancel context.CancelFunc
 done chan struct{}
 mu sync.Mutex
 err error
}

// StartReceiving binds the requested address before reporting that receiving is enabled.
func StartReceiving(ctx context.Context, receiver *Receiver, address string) (*RunningReceiver, error) {
 if receiver == nil { return nil, errors.New("receiver is required") }
 if ctx == nil { return nil, errors.New("context is required") }
 if err := ctx.Err(); err != nil { return nil, err }
 ln, err := net.Listen("tcp", address)
 if err != nil { return nil, err }
 runCtx, cancel := context.WithCancel(ctx)
 running := &RunningReceiver{address: ln.Addr(), cancel: cancel, done: make(chan struct{})}
 go func() {
  e := receiver.ServeListener(runCtx, ln)
  running.mu.Lock()
  running.err = e
  running.mu.Unlock()
  cancel()
  close(running.done)
 }()
 return running, nil
}

func (r *RunningReceiver) Address() net.Addr {
 if r == nil { return nil }
 return r.address
}

// Done is closed when the listening server terminates.
func (r *RunningReceiver) Done() <-chan struct{} {
 if r == nil {
  ch := make(chan struct{})
  close(ch)
  return ch
 }
 return r.done
}

// Err is meaningful after Done closes. Graceful stop returns nil.
func (r *RunningReceiver) Err() error {
 if r == nil { return nil }
 <-r.done
 r.mu.Lock()
 defer r.mu.Unlock()
 return r.err
}

// Stop is idempotent and releases the listener even if a server request is active.
func (r *RunningReceiver) Stop(ctx context.Context) error {
 if r == nil { return nil }
 if ctx == nil { return errors.New("context is required") }
 r.cancel()
 select {
 case <-r.done: return r.Err()
 case <-ctx.Done(): return ctx.Err()
 }
}
