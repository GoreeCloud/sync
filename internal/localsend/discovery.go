package localsend

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

func Discover(ctx context.Context, me DeviceInfo) ([]Peer, error) {
	addr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 167), Port: DefaultPort}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err = conn.SetReadBuffer(64 << 10); err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	me.Announce = true
	b, err := json.Marshal(me)
	if err != nil {
		return nil, err
	}
	sender, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, err
	}
	_, err = sender.Write(b)
	sender.Close()
	if err != nil {
		return nil, err
	}
	peers := map[string]Peer{}
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var buf [4096]byte
		n, remote, e := conn.ReadFromUDP(buf[:])
		if ne, ok := e.(net.Error); ok && ne.Timeout() {
			break
		}
		if e != nil {
			return nil, e
		}
		var peer DeviceInfo
		if json.Unmarshal(buf[:n], &peer) != nil || peer.Fingerprint == "" || peer.Fingerprint == me.Fingerprint {
			continue
		}
		if remote == nil || remote.IP == nil {
			continue
		}
		if peer.Port == 0 {
			peer.Port = DefaultPort
		}
		// Multicast is not authenticated. Never use its fingerprint as a TLS pin.
		if peer.Protocol != "https" || peer.Port < 1 || peer.Port > 65535 ||
			!(remote.IP.IsPrivate() || remote.IP.IsLoopback() || remote.IP.IsLinkLocalUnicast()) {
			continue
		}
		if len(peers) >= 32 { continue }
		peers[remote.IP.String()+":"+strconv.Itoa(peer.Port)] = Peer{IP: remote.IP, Info: peer}
	}
	// Probe HTTPS certificates before any candidate reaches the sender UI.
	// Limit concurrent attempts to avoid hostile LAN traffic exhausting resources.
	probeCtx, stop := context.WithTimeout(ctx, 8*time.Second)
	defer stop()
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4)
	found := make(chan Peer, len(peers))
	for _, candidate := range peers {
		select {
		case semaphore <- struct{}{}:
		case <-probeCtx.Done():
			break
		}
		wg.Add(1)
		go func(p Peer) {
			defer wg.Done()
			defer func(){ <-semaphore }()
			observed, err := Probe(probeCtx, p.IP, p.Info.Port, me)
			if err == nil && observed.Info.Fingerprint != me.Fingerprint { found <- observed }
		}(candidate)
	}
	wg.Wait()
	close(found)
	result := make([]Peer, 0, len(found))
	for p := range found { result = append(result, p) }
	if err := ctx.Err(); err != nil { return nil, err }
	sort.Slice(result, func(i, j int) bool { return result[i].Info.Alias < result[j].Info.Alias })
	return result, nil
}

var ErrNoPeer = errors.New("no peer selected")
