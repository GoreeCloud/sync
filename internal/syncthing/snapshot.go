package syncthing

import (
 "context"
 "fmt"
 "time"
)

// Summary deliberately exposes aggregate engine health only, not file paths,
// device IDs or secrets.
type Summary struct {
 Online bool `json:"online"`
 UptimeSeconds int64 `json:"uptimeSeconds"`
 DeviceCount int `json:"deviceCount"`
 FolderCount int `json:"folderCount"`
 PausedDevices int `json:"pausedDevices"`
 PausedFolders int `json:"pausedFolders"`
}

// Snapshot queries the existing local Syncthing engine without mutations.
func (c *Client) Snapshot(ctx context.Context) (Summary, error) {
 ctx, cancel := context.WithTimeout(ctx,10*time.Second)
 defer cancel()
 state, err := c.Status(ctx)
 if err != nil { return Summary{}, fmt.Errorf("engine status: %w",err) }
 devices, err := c.Devices(ctx)
 if err != nil { return Summary{}, fmt.Errorf("engine devices: %w",err) }
 folders, err := c.Folders(ctx)
 if err != nil { return Summary{}, fmt.Errorf("engine folders: %w",err) }
 result := Summary{Online:true,UptimeSeconds:state.Uptime,DeviceCount:len(devices),FolderCount:len(folders)}
 for _,d := range devices { if d.Paused { result.PausedDevices++ } }
 for _,f := range folders { if f.Paused { result.PausedFolders++ } }
 return result,nil
}
