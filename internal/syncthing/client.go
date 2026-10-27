package syncthing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	endpoint   string
	key        string
	httpClient *http.Client
}

type Status struct {
	MyID       string `json:"myID"`
	Uptime     int64  `json:"uptime"`
	Goroutines int    `json:"goroutines"`
}

type Device struct {
	DeviceID string `json:"deviceID"`
	Name     string `json:"name"`
	Paused   bool   `json:"paused"`
}

type Folder struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Path   string `json:"path"`
	Type   string `json:"type"`
	Paused bool   `json:"paused"`
}

func NewClient(endpoint, key string) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("Syncthing URL must use HTTP or HTTPS")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("Syncthing URL must contain only the scheme and local address")
	}
	host := u.Hostname()
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("Syncthing API must bind to loopback only")
		}
	}
	if u.Port() == "" {
		return nil, errors.New("Syncthing API port is required")
	}
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("Syncthing API key is required")
	}
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"), key: key,
		httpClient: &http.Client{Timeout: 6 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}
func (c *Client) get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.key)
	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Syncthing connection: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("Syncthing API returned HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(dst)
}
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.get(ctx, "/rest/system/status", &s)
	return s, err
}
func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var d []Device
	err := c.get(ctx, "/rest/config/devices", &d)
	return d, err
}
func (c *Client) Folders(ctx context.Context) ([]Folder, error) {
	var f []Folder
	err := c.get(ctx, "/rest/config/folders", &f)
	return f, err
}
