package localsend

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
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
		peers[peer.Fingerprint] = Peer{IP: remote.IP, Info: peer}
	}
	result := make([]Peer, 0, len(peers))
	for _, p := range peers {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Info.Alias < result[j].Info.Alias })
	return result, nil
}

var ErrNoPeer = errors.New("no peer selected")
