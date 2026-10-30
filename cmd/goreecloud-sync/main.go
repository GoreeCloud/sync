package main

import (
	"context"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/GoreeCloud/sync/internal/localsend"
	"github.com/GoreeCloud/sync/internal/syncthing"
)

type gcTheme struct{}

func (gcTheme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (gcTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (gcTheme) Size(n fyne.ThemeSizeName) float32       { return theme.DefaultTheme().Size(n) }
func (gcTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	dark := v == theme.VariantDark
	switch n {
	case theme.ColorNameBackground:
		if dark {
			return color.RGBA{16, 19, 30, 255}
		}
		return color.RGBA{236, 240, 248, 255}
	case theme.ColorNamePrimary:
		if dark {
			return color.RGBA{216, 210, 255, 255}
		}
		return color.RGBA{65, 50, 179, 255}
	case theme.ColorNameInputBackground:
		if dark {
			return color.RGBA{37, 43, 61, 255}
		}
		return color.RGBA{249, 250, 253, 255}
	}
	return theme.DefaultTheme().Color(n, v)
}

func main() {
	a := app.NewWithID("com.goreecloud.sync")
	a.Settings().SetTheme(gcTheme{})
	w := a.NewWindow("GoreeCloud Sync")
	w.Resize(fyne.NewSize(950, 680))
	w.SetMaster()
	home, err := os.UserConfigDir()
	if err != nil {
		home = os.TempDir()
	}
	alias, err := os.Hostname()
	if err != nil || alias == "" {
		alias = "GoreeCloud device"
	}
	identity, err := localsend.LoadOrCreateIdentity(filepath.Join(home, "goreecloud-sync"), alias)
	if err != nil {
		dialog.ShowError(err, w)
		w.ShowAndRun()
		return
	}

	title := widget.NewLabelWithStyle("GoreeCloud Sync", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	subtitle := widget.NewLabel("Private by design • Always-on synchronization + instant nearby transfers")
	status := widget.NewLabel("Ready. Connect an existing local Syncthing engine or send a file.")
	logArea := widget.NewMultiLineEntry()
	logArea.SetPlaceHolder("Transfer and connection events appear here")
	logArea.Disable()
	appendLog := func(s string) {
		fyne.Do(func() {
			t := time.Now().Format("15:04:05") + "  " + s
			existing := logArea.Text
			if len(existing) > 9000 {
				existing = existing[len(existing)-7000:]
			}
			logArea.SetText(existing + t + "\n")
			status.SetText(s)
		})
	}
	overview := container.NewVBox(
		widget.NewCard("YOUR PRIVATE CONNECTIONS", "Two workflows, one application", widget.NewLabel(
			"Continuous Sync manages persistent folders through an installed Syncthing service. Nearby Send transfers a selected file directly to a LocalSend-compatible device.")),
		widget.NewCard("SECURITY", "Controlled and local by default", widget.NewLabel(
			"Syncthing control is loopback-only. Nearby receiving is off until you choose a destination, and every incoming transfer requires approval.")),
		widget.NewLabelWithStyle("Activity", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		logArea,
	)

	syncURL := widget.NewEntry()
	syncURL.SetText("http://127.0.0.1:8384")
	syncKey := widget.NewPasswordEntry()
	syncKey.SetPlaceHolder("Syncthing API key (kept in memory only)")
	syncStatus := widget.NewLabel("Disconnected")
	deviceRows := container.NewVBox(widget.NewLabel("Connect to load Syncthing devices."))
	folderRows := container.NewVBox(widget.NewLabel("Connect to load synchronized folders."))
	connect := widget.NewButtonWithIcon("Connect to Syncthing", theme.ViewRefreshIcon(), func() {
		url, key := syncURL.Text, syncKey.Text
		go func() {
			c, e := syncthing.NewClient(url, key)
			if e != nil {
				appendLog("Syncthing: " + e.Error())
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			s, e := c.Status(ctx)
			if e != nil {
				appendLog("Syncthing: " + e.Error())
				return
			}
			devices, de := c.Devices(ctx)
			folders, fe := c.Folders(ctx)
			fyne.Do(func() {
				syncStatus.SetText(fmt.Sprintf("Connected • Device %s • Uptime %s", short(s.MyID), (time.Duration(s.Uptime) * time.Second).Truncate(time.Second)))
				deviceRows.Objects = nil
				if de != nil {
					deviceRows.Add(widget.NewLabel("Devices unavailable: " + de.Error()))
				}
				for _, d := range devices {
					deviceRows.Add(widget.NewLabel(fmt.Sprintf("%s   %s", name(d.Name, d.DeviceID), paused(d.Paused))))
				}
				if de == nil && len(devices) == 0 {
					deviceRows.Add(widget.NewLabel("No trusted devices configured."))
				}
				folderRows.Objects = nil
				if fe != nil {
					folderRows.Add(widget.NewLabel("Folders unavailable: " + fe.Error()))
				}
				for _, f := range folders {
					folderRows.Add(widget.NewLabel(fmt.Sprintf("%s • %s • %s", name(f.Label, f.ID), f.Type, paused(f.Paused))))
				}
				if fe == nil && len(folders) == 0 {
					folderRows.Add(widget.NewLabel("No folders configured in Syncthing."))
				}
				deviceRows.Refresh()
				folderRows.Refresh()
			})
			appendLog(fmt.Sprintf("Connected to local Syncthing • %d device(s), %d folder(s)", len(devices), len(folders)))
		}()
	})
	syncPage := container.NewVScroll(container.NewVBox(
		widget.NewCard("CONTINUOUS SYNC", "Syncthing engine status", container.NewVBox(
			syncStatus, widget.NewForm(widget.NewFormItem("Local REST URL", syncURL),
				widget.NewFormItem("API key", syncKey)), connect)),
		widget.NewCard("DEVICES", "Trusted synchronization peers", deviceRows),
		widget.NewCard("FOLDERS", "Continuous synchronized locations", folderRows),
		widget.NewLabel("This initial integration is read-only. Configure device trust and folder sharing in Syncthing until native write controls are implemented."),
	))

	fingerprint := widget.NewEntry()
	fingerprint.SetText(identity.Fingerprint)
	fingerprint.Disable()
	receiving := widget.NewLabel("Receiving disabled • Select an inbox to enable it.")
	ctxReceive, cancelReceive := context.WithCancel(context.Background())
	defer cancelReceive()
	var runningReceiver *localsend.RunningReceiver
	var enableReceive *widget.Button
	var stopReceive *widget.Button
	enableReceive = widget.NewButtonWithIcon("Choose inbox and enable receiving", theme.FolderOpenIcon(), func() {
		if runningReceiver != nil { return }
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if uri == nil {
				return
			}
			if uri.Scheme() != "file" {
				dialog.ShowInformation("Unsupported inbox", "Choose a local filesystem directory.", w)
				return
			}
			inbox := uri.Path()
			approval := func(offer localsend.TransferRequest) bool {
				response := make(chan bool, 1)
				fyne.Do(func() {
					dialog.ShowConfirm("Incoming transfer", fmt.Sprintf(
						"%s wants to send %d file(s), %d bytes.\n\n%s\n\nAccept into %s?",
						offer.Sender.Alias, len(offer.Names), offer.TotalBytes, strings.Join(offer.Names, "\n"), inbox),
						func(ok bool) { response <- ok }, w)
				})
				select {
				case yes := <-response:
					return yes
				case <-time.After(90 * time.Second):
					return false
				case <-ctxReceive.Done():
					return false
				}
			}
			receiver, e := localsend.NewReceiver(identity, inbox, approval)
			if e != nil {
				dialog.ShowError(e, w)
				return
			}
			// Port binding completes before the UI reports that receiving is enabled.
			running, e := localsend.StartReceiving(ctxReceive, receiver, fmt.Sprintf(":%d", localsend.DefaultPort))
			if e != nil {
				dialog.ShowError(e, w)
				return
			}
			runningReceiver = running
			enableReceive.Disable()
			stopReceive.Enable()
			receiving.SetText("Receiving enabled • Every offer requires approval • " + inbox)
			appendLog("Nearby receiving enabled on port 53317")
			go func() {
				<-running.Done()
				stoppedErr := running.Err()
				fyne.Do(func() {
					if runningReceiver != running { return }
					runningReceiver = nil
					enableReceive.Enable()
					stopReceive.Disable()
					receiving.SetText("Receiving disabled • Select an inbox to enable it.")
				})
				if stoppedErr != nil { appendLog("Receiver stopped: " + stoppedErr.Error()) } else { appendLog("Nearby receiving stopped") }
			}()
		}, w)
	})
	stopReceive = widget.NewButtonWithIcon("Stop receiving", theme.MediaStopIcon(), func() {
		if runningReceiver == nil { return }
		current := runningReceiver
		stopReceive.Disable()
		receiving.SetText("Stopping nearby receiving…")
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			if err := current.Stop(ctx); err != nil { appendLog("Receiver stop failed: " + err.Error()) }
		}()
	})
	stopReceive.Disable()

	peers := []localsend.Peer{}
	selectPeer := widget.NewSelect(nil, func(string) {})
	selectPeer.PlaceHolder = "Scan to find a nearby device"
	scan := widget.NewButtonWithIcon("Discover on LAN", theme.SearchIcon(), func() {
		go func() {
			found, e := localsend.Discover(context.Background(), identity.Info(localsend.DefaultPort))
			if e != nil {
				appendLog("Discovery unavailable: " + e.Error())
				return
			}
			fyne.Do(func() {
				peers = found
				options := make([]string, 0, len(found))
				for _, p := range found {
					options = append(options, p.Info.Alias+" ("+p.IP.String()+")")
				}
				selectPeer.Options = options
				selectPeer.ClearSelected()
				selectPeer.Refresh()
			})
			appendLog(fmt.Sprintf("Discovered %d nearby device(s)", len(found)))
		}()
	})
	send := widget.NewButtonWithIcon("Choose file and send", theme.MailSendIcon(), func() {
		index := -1
		for i, p := range peers {
			if p.Info.Alias+" ("+p.IP.String()+")" == selectPeer.Selected {
				index = i
				break
			}
		}
		if index < 0 {
			dialog.ShowInformation("Select a device", "Discover and select a peer before sending.", w)
			return
		}
		peer := peers[index]
		if peer.Info.Protocol != "https" {
			dialog.ShowInformation("Secure transfer required", "This first version only sends to HTTPS peers.", w)
			return
		}
		dialog.ShowConfirm("Confirm peer identity",
			"Direct HTTPS transfer to "+peer.Info.Alias+"\nCertificate SHA-256: "+peer.Info.Fingerprint+
				"\n\nVerify the fingerprint with the receiving device before continuing.",
			func(ok bool) {
				if !ok {
					return
				}
				dialog.ShowFileOpen(func(file fyne.URIReadCloser, e error) {
					if e != nil {
						dialog.ShowError(e, w)
						return
					}
					if file == nil {
						return
					}
					uri := file.URI()
					_ = file.Close()
					if uri.Scheme() != "file" {
						dialog.ShowInformation("Unsupported file", "Choose a local filesystem file.", w)
						return
					}
					path := uri.Path()
					go func() {
						appendLog("Sending " + filepath.Base(path) + " to " + peer.Info.Alias + "…")
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
						defer cancel()
						if e := localsend.Send(ctx, peer, identity.Info(localsend.DefaultPort), path); e != nil {
							appendLog("Send failed: " + e.Error())
						} else {
							appendLog("Sent " + filepath.Base(path) + " to " + peer.Info.Alias)
						}
					}()
				}, w)
			}, w)
	})
	nearbyPage := container.NewVScroll(container.NewVBox(
		widget.NewCard("NEARBY SEND", "One-time, direct encrypted transfers", container.NewVBox(
			widget.NewLabel("Your device: "+identity.Alias),
			widget.NewLabel("No cloud relay required. Connect to the same local network."),
			container.NewHBox(scan), selectPeer, send)),
		widget.NewCard("RECEIVE", "Explicit consent for every transfer", container.NewVBox(receiving, container.NewHBox(enableReceive, stopReceive))),
		widget.NewCard("YOUR DEVICE FINGERPRINT", "Share to verify a secure connection", fingerprint),
	))
	settingsPage := container.NewVBox(widget.NewCard("Privacy & engine boundaries", "Default protections", widget.NewLabel(
		"• No telemetry or cloud account.\n• Syncthing API credentials live in memory, not preferences.\n• No remote Syncthing API endpoints.\n• TLS-pinned direct transfers only.\n• Receiver accepts files only after approval.")),
		widget.NewLabel("GoreeCloud UI • Iris accent • Native desktop preview"))

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Home", theme.HomeIcon(), container.NewVScroll(overview)),
		container.NewTabItemWithIcon("Sync", theme.StorageIcon(), syncPage),
		container.NewTabItemWithIcon("Nearby", theme.ComputerIcon(), nearbyPage),
		container.NewTabItemWithIcon("Settings", theme.SettingsIcon(), settingsPage),
	)
	tabs.SetTabLocation(container.TabLocationLeading)
	w.SetContent(container.NewBorder(container.NewVBox(title, subtitle, widget.NewSeparator()), status, nil, nil, tabs))
	w.SetCloseIntercept(func() { cancelReceive(); w.SetCloseIntercept(nil); w.Close() })
	w.ShowAndRun()
}
func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
func name(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
func paused(p bool) string {
	if p {
		return "Paused"
	}
	return "Active"
}
