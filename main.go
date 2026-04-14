//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

// ── Clipboard (Win32) ──────────────────────────────────────────────────────
var (
	clipUser32           = syscall.NewLazyDLL("user32.dll")
	clipKernel32         = syscall.NewLazyDLL("kernel32.dll")
	procOpenClipboard    = clipUser32.NewProc("OpenClipboard")
	procCloseClipboard   = clipUser32.NewProc("CloseClipboard")
	procEmptyClipboard   = clipUser32.NewProc("EmptyClipboard")
	procSetClipboardData = clipUser32.NewProc("SetClipboardData")
	procGlobalAlloc      = clipKernel32.NewProc("GlobalAlloc")
	procGlobalLock       = clipKernel32.NewProc("GlobalLock")
	procGlobalUnlock     = clipKernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

func copyToClipboard(text string) error {
	utf16, err := syscall.UTF16FromString(text)
	if err != nil {
		return fmt.Errorf("UTF16FromString: %w", err)
	}
	size := uintptr(len(utf16) * 2)

	h, _, err := procGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return fmt.Errorf("GlobalAlloc: %w", err)
	}
	ptr, _, err := procGlobalLock.Call(h)
	if ptr == 0 {
		return fmt.Errorf("GlobalLock: %w", err)
	}
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(utf16))
	copy(dst, utf16)
	procGlobalUnlock.Call(h)

	r, _, err := procOpenClipboard.Call(0)
	if r == 0 {
		return fmt.Errorf("OpenClipboard: %w", err)
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()
	r, _, err = procSetClipboardData.Call(cfUnicodeText, h)
	if r == 0 {
		return fmt.Errorf("SetClipboardData: %w", err)
	}
	return nil
}

type mainWindow struct {
	mw       *walk.MainWindow
	detected DetectedPaths

	// Troubleshooter tab
	lblDiagGameDir  *walk.Label
	lblDiagAshita   *walk.Label
	lblDiagLaunch   *walk.Label
	lblDiagLocal    *walk.Label
	diagLog         *walk.TextEdit
	btnTroubleshoot *walk.PushButton
	btnCopyLog      *walk.PushButton
	btnAddWDExcept  *walk.PushButton

	// Summary labels
	sumInstallDirs *walk.Label
	sumAshita      *walk.Label
	sumCGNAT       *walk.Label
	sumNATType     *walk.Label
	sumBitTorrent  *walk.Label

	// Uninstall tab
	lblGameDir   *walk.Label
	lblLaunch    *walk.Label
	lblLocal     *walk.Label
	logView      *walk.TextEdit
	btnUninstall *walk.PushButton
	chkDryRun    *walk.CheckBox
}

func main() {
	mw := &mainWindow{}

	if err := mw.buildUI(); err != nil {
		log.Fatal(err)
	}
	if icon, err := walk.NewIconFromResourceId(1); err == nil {
		mw.mw.SetIcon(icon)
	}
	mw.detected = DetectInstallation()
	mw.refreshAll()
	go func() { mw.mw.Synchronize(mw.onTroubleshootClicked) }()
	mw.mw.Run()
}

func (mw *mainWindow) buildUI() error {
	return MainWindow{
		AssignTo: &mw.mw,
		Title:    "HorizonXI Unofficial Game Installation and Network Troubleshooter",
		MinSize:  Size{Width: 680, Height: 480},
		Size:     Size{Width: 760, Height: 580},
		Layout:   VBox{MarginsZero: true},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					// ── Troubleshooter tab (first) ──────────────────────────
					{
						Title:  "Troubleshooter",
						Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}},
						Children: []Widget{
							GroupBox{
								Title:  "Installation Status",
								Layout: VBox{},
								Children: []Widget{
									Label{AssignTo: &mw.lblDiagGameDir, Text: "Game directory:   (scanning...)"},
									Label{AssignTo: &mw.lblDiagAshita, Text: "Ashita-cli.exe:   (scanning...)"},
									Label{AssignTo: &mw.lblDiagLaunch, Text: "Launcher data:    (scanning...)"},
									Label{AssignTo: &mw.lblDiagLocal, Text: "Local config:     (scanning...)"},
								},
							},
							GroupBox{
								Title:  "Summary",
								Layout: VBox{},
								Children: []Widget{
									Label{AssignTo: &mw.sumInstallDirs, Text: "  Directories — (not yet checked)"},
									Label{AssignTo: &mw.sumAshita,      Text: "  Ashita-cli.exe — (not yet checked)"},
									Label{AssignTo: &mw.sumCGNAT,       Text: "  CGNAT — (not yet checked)"},
									Label{AssignTo: &mw.sumNATType,     Text: "  NAT Type — (not yet checked)"},
									Label{AssignTo: &mw.sumBitTorrent,  Text: "  BitTorrent — (not yet checked)"},
								},
							},
							Label{Text: "Diagnostic Output:"},
							TextEdit{
								AssignTo:      &mw.diagLog,
								ReadOnly:      true,
								VScroll:       true,
								StretchFactor: 1,
							},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{
										AssignTo: &mw.btnTroubleshoot,
										Text:     "Troubleshoot",
										MinSize:  Size{Width: 120, Height: 30},
										OnClicked: func() {
											mw.onTroubleshootClicked()
										},
									},
									PushButton{
										AssignTo: &mw.btnCopyLog,
										Text:     "Copy Log to Clipboard",
										MinSize:  Size{Width: 160, Height: 30},
										OnClicked: func() {
											mw.onCopyLogClicked()
										},
									},
									HSpacer{},
									PushButton{
										AssignTo: &mw.btnAddWDExcept,
										Text:     "Add Windows Defender Exception",
										MinSize:  Size{Width: 220, Height: 30},
										OnClicked: func() {
											mw.onAddWDExceptionClicked()
										},
									},
								},
							},
						},
					},
					// ── Uninstall tab (second) ───────────────────────────────
					{
						Title:  "Uninstall",
						Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}},
						Children: []Widget{
							GroupBox{
								Title:  "Detected Installation",
								Layout: VBox{},
								Children: []Widget{
									Label{AssignTo: &mw.lblGameDir, Text: "Game directory:  (scanning...)"},
									Label{AssignTo: &mw.lblLaunch, Text: "Launcher data:   (scanning...)"},
									Label{AssignTo: &mw.lblLocal, Text: "Local config:    (scanning...)"},
								},
							},
							Label{Text: "Output Log:"},
							TextEdit{
								AssignTo:      &mw.logView,
								ReadOnly:      true,
								VScroll:       true,
								StretchFactor: 1,
							},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									CheckBox{
										AssignTo: &mw.chkDryRun,
										Text:     "Dry run (log only, no changes)",
										Checked:  true,
									},
									HSpacer{},
									PushButton{
										AssignTo: &mw.btnUninstall,
										Text:     "Clean Uninstall",
										MinSize:  Size{Width: 140, Height: 30},
										OnClicked: func() {
											mw.onUninstallClicked()
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}.Create()
}

// refreshAll re-populates both tabs' status labels from mw.detected.
func (mw *mainWindow) refreshAll() {
	mw.populateDiagLabels()
	mw.populateStatusLabels()
}

// populateDiagLabels updates the Troubleshooter tab's status section.
func (mw *mainWindow) populateDiagLabels() {
	if mw.detected.GameDir != "" {
		mw.lblDiagGameDir.SetText("Game directory:   " + mw.detected.GameDir + "  [found]")
	} else {
		mw.lblDiagGameDir.SetText("Game directory:   Not detected")
	}

	switch {
	case mw.detected.GameDir == "":
		mw.lblDiagAshita.SetText("Ashita-cli.exe:   N/A (game directory not found)")
	case mw.detected.AshitaCliFound:
		mw.lblDiagAshita.SetText("Ashita-cli.exe:   Found")
	default:
		mw.lblDiagAshita.SetText("Ashita-cli.exe:   MISSING — game will not launch! (check AV quarantine)")
	}

	mw.lblDiagLaunch.SetText("Launcher data:    " + mw.detected.LauncherAppData + dirStatus(mw.detected.LauncherAppData))
	mw.lblDiagLocal.SetText("Local config:     " + mw.detected.LauncherLocalData + dirStatus(mw.detected.LauncherLocalData))

	mw.btnAddWDExcept.SetEnabled(mw.detected.GameDir != "")
}

// populateStatusLabels updates the Uninstall tab's status section.
func (mw *mainWindow) populateStatusLabels() {
	if mw.detected.GameDir != "" {
		mw.lblGameDir.SetText("Game directory:  " + mw.detected.GameDir)
	} else {
		mw.lblGameDir.SetText("Game directory:  Not found")
	}

	mw.lblLaunch.SetText("Launcher data:   " + mw.detected.LauncherAppData + dirStatus(mw.detected.LauncherAppData))
	mw.lblLocal.SetText("Local config:    " + mw.detected.LauncherLocalData + dirStatus(mw.detected.LauncherLocalData))

	mw.btnUninstall.SetEnabled(mw.detected.GameDir != "")
}

// dirStatus returns a short presence annotation for path labels.
func dirStatus(path string) string {
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "  [not present]"
	}
	return "  [found]"
}

func pathExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// updateInstallSummary refreshes the Summary panel rows that are known
// immediately from the installation scan (no network required).
func (mw *mainWindow) updateInstallSummary() {
	d := mw.detected

	// Directories row
	switch {
	case d.GameDir == "":
		mw.sumInstallDirs.SetText("❌  Directories — game directory not found")
	case pathExists(d.LauncherAppData) && pathExists(d.LauncherLocalData):
		mw.sumInstallDirs.SetText("✅  Directories — game + all launcher data found")
	default:
		mw.sumInstallDirs.SetText("⚠️  Directories — game found, some launcher data missing")
	}

	// Ashita row
	switch {
	case d.GameDir == "":
		mw.sumAshita.SetText("  Ashita-cli.exe — (no game directory)")
	case d.AshitaCliFound:
		mw.sumAshita.SetText("✅  Ashita-cli.exe — found")
	default:
		mw.sumAshita.SetText("❌  Ashita-cli.exe — MISSING (check AV quarantine)")
	}

	// Reset network rows to in-progress state
	mw.sumCGNAT.SetText("  CGNAT — checking…")
	mw.sumNATType.SetText("  NAT Type — checking…")
	mw.sumBitTorrent.SetText("  BitTorrent — checking…")
}

// updateNetSummary refreshes the Summary panel rows that depend on the
// completed network checks.
func (mw *mainWindow) updateNetSummary(ns NetSummary) {
	// CGNAT row
	switch {
	case !ns.HTTPOk:
		mw.sumCGNAT.SetText("⚠️  CGNAT — could not determine (no internet)")
	case ns.CGNAT:
		mw.sumCGNAT.SetText("❌  CGNAT — detected (carrier NAT, game may fail to connect)")
	case ns.DoubleNAT:
		mw.sumCGNAT.SetText("⚠️  Double-NAT — extra NAT layer above your router")
	default:
		mw.sumCGNAT.SetText("✅  No CGNAT — public IPv4")
	}

	// NAT Type row
	switch ns.NATType {
	case "open":
		mw.sumNATType.SetText("✅  NAT Type: Open Internet (no NAT)")
	case "cone":
		mw.sumNATType.SetText("✅  NAT Type: Cone NAT")
	case "cone-partial":
		mw.sumNATType.SetText("⚠️  NAT Type: Cone NAT (symmetric test inconclusive)")
	case "symmetric":
		mw.sumNATType.SetText("❌  NAT Type: Symmetric NAT — P2P issues likely")
	case "blocked":
		mw.sumNATType.SetText("❌  NAT Type: Unknown (UDP blocked)")
	default:
		mw.sumNATType.SetText("⚠️  NAT Type: Unknown")
	}

	// BitTorrent row
	switch {
	case ns.UDPBlocked && !ns.UPnPFound:
		mw.sumBitTorrent.SetText("❌  BitTorrent — severely limited (UDP blocked, no UPnP)")
	case ns.UDPBlocked:
		mw.sumBitTorrent.SetText("⚠️  BitTorrent — degraded (UDP blocked, TCP only)")
	case !ns.UPnPFound && ns.NATType == "symmetric":
		mw.sumBitTorrent.SetText("⚠️  BitTorrent — degraded (symmetric NAT, no UPnP)")
	case !ns.UPnPFound:
		mw.sumBitTorrent.SetText("⚠️  BitTorrent — functional but slower (no UPnP)")
	default:
		mw.sumBitTorrent.SetText("✅  BitTorrent — full speed (UPnP available)")
	}
}

// onTroubleshootClicked re-scans the installation, logs findings to diagLog,
// then runs the async network checks.
func (mw *mainWindow) onTroubleshootClicked() {
	mw.detected = DetectInstallation()
	mw.refreshAll()

	mw.btnTroubleshoot.SetEnabled(false)
	mw.updateInstallSummary()

	log := func(s string) { mw.diagLog.AppendText(maskUser(s) + "\r\n") }

	log("## HorizonXI Troubleshooter Diagnostic")
	log("")
	log("### Installation")
	log("")

	if mw.detected.GameDir != "" {
		log("**Game directory:** `" + mw.detected.GameDir + "`")
	} else {
		log("❌ **Game directory:** not detected — no HorizonXI installation found.")
	}
	log("")

	if mw.detected.GameDir == "" {
		log("**Ashita-cli.exe:** N/A — game directory not found")
	} else {
		ashitaPath := filepath.Join(mw.detected.GameDir, "Game", "Ashita-cli.exe")
		if mw.detected.AshitaCliFound {
			log("✅ **Ashita-cli.exe:** found at `" + ashitaPath + "`")
		} else {
			log("❌ **Ashita-cli.exe:** MISSING at `" + ashitaPath + "`")
			log("> This file is required to launch the game.")
			log("> It may have been quarantined by antivirus software.")
			log("> Add a Windows Defender exception for your game directory, then reinstall the launcher.")
		}
	}
	log("")

	if pathExists(mw.detected.LauncherAppData) {
		log("✅ **Launcher data** (`%APPDATA%`): `" + mw.detected.LauncherAppData + "`")
	} else {
		log("⚠️ **Launcher data** (`%APPDATA%`): not present — `" + mw.detected.LauncherAppData + "`")
	}

	if pathExists(mw.detected.LauncherLocalData) {
		log("✅ **Launcher config** (`%LOCALAPPDATA%`): `" + mw.detected.LauncherLocalData + "`")
	} else {
		log("⚠️ **Launcher config** (`%LOCALAPPDATA%`): not present — `" + mw.detected.LauncherLocalData + "`")
	}
	log("")
	log("---")
	log("")
	log("*Running network checks…*")
	log("")

	// Network checks hit the internet — run async so the UI stays responsive.
	// runNetworkChecks closes logCh when done; the drain goroutine then reads
	// the NetSummary from resultCh and updates the summary panel.
	logCh := make(chan string, 128)
	resultCh := make(chan NetSummary, 1)

	go func() {
		ns := runNetworkChecks(logCh) // closes logCh before returning
		resultCh <- ns
	}()

	go func() {
		for line := range logCh {
			l := line // capture before Synchronize closure
			mw.mw.Synchronize(func() {
				mw.diagLog.AppendText(maskUser(l) + "\r\n")
			})
		}
		ns := <-resultCh
		mw.mw.Synchronize(func() {
			mw.updateNetSummary(ns)
			mw.diagLog.AppendText("\r\nAll checks complete.\r\n")
			mw.btnTroubleshoot.SetEnabled(true)
		})
	}()
}

// onAddWDExceptionClicked confirms then asynchronously adds a Windows Defender
// exclusion for the game directory.
func (mw *mainWindow) onAddWDExceptionClicked() {
	gameDir := mw.detected.GameDir
	if gameDir == "" {
		return
	}

	msg := "This will add your game directory as an exclusion in Windows Defender:\n\n" +
		gameDir + "\n\n" +
		"Windows Defender will stop scanning files in this folder, which helps\n" +
		"prevent game files like Ashita-cli.exe from being quarantined.\n\n" +
		"Note: this only affects Windows Defender — other antivirus software\n" +
		"is not changed. Administrator privileges are required."

	if walk.MsgBox(mw.mw, "Add Windows Defender Exception", msg,
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != win.IDYES {
		return
	}

	mw.btnAddWDExcept.SetEnabled(false)
	logCh := make(chan string, 32)
	go runAddWDException(gameDir, logCh)

	go func() {
		for line := range logCh {
			mw.mw.Synchronize(func() {
				mw.diagLog.AppendText(line + "\r\n")
			})
		}
		mw.mw.Synchronize(func() {
			mw.btnAddWDExcept.SetEnabled(mw.detected.GameDir != "")
		})
	}()
}

// runAddWDException runs Add-MpPreference via PowerShell in a goroutine.
// logCh is closed when done.
func runAddWDException(gameDir string, logCh chan<- string) {
	defer close(logCh)
	send := func(s string) { logCh <- maskUser(s) }

	send(fmt.Sprintf("Adding Windows Defender exclusion for:\n  %s\n", gameDir))

	escaped := strings.ReplaceAll(gameDir, "'", "''")
	cmd := exec.Command(
		"powershell.exe",
		"-NonInteractive", "-NoProfile", "-WindowStyle", "Hidden",
		"-Command", fmt.Sprintf("Add-MpPreference -ExclusionPath '%s'", escaped),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}

	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		send(fmt.Sprintf("[error] %v", err))
		if output != "" {
			send("[detail] " + output)
		}
		send("[info] Try running this app as Administrator (right-click → Run as administrator).")
	} else {
		send("[done] Exclusion added successfully.")
		send("[info] Windows Defender will no longer quarantine files in your game directory.")
		if output != "" {
			send("[info] " + output)
		}
	}
}

// onCopyLogClicked copies the full diagnostic log text to the Windows clipboard.
func (mw *mainWindow) onCopyLogClicked() {
	text := mw.diagLog.Text()
	if text == "" {
		return
	}
	if err := copyToClipboard(text); err != nil {
		walk.MsgBox(mw.mw, "Clipboard Error", "Could not copy to clipboard:\n"+err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	mw.btnCopyLog.SetText("Copied!")
	go func() {
		time.Sleep(2 * time.Second)
		mw.mw.Synchronize(func() {
			mw.btnCopyLog.SetText("Copy Log to Clipboard")
		})
	}()
}

// onUninstallClicked handles the Clean Uninstall button on the Uninstall tab.
func (mw *mainWindow) onUninstallClicked() {
	dryRun := mw.chkDryRun.Checked()

	if !dryRun {
		result := walk.MsgBox(
			mw.mw,
			"Confirm Uninstall",
			"Are you sure you want to completely remove all HorizonXI files from your computer?\n\nBe sure you've backed up anything you might want to keep, like macros and addon config files.",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion,
		)
		if result != win.IDYES {
			return
		}
	}

	mw.btnUninstall.SetEnabled(false)

	logCh := make(chan string, 128)
	go RunUninstall(mw.detected, dryRun, logCh)

	go func() {
		for line := range logCh {
			mw.mw.Synchronize(func() {
				mw.logView.AppendText(line + "\r\n")
			})
		}
		mw.mw.Synchronize(func() {
			if !dryRun {
				mw.detected = DetectInstallation()
				mw.refreshAll()
				mw.logView.AppendText("\r\nStatus refreshed.\r\n")
			} else {
				mw.btnUninstall.SetEnabled(mw.detected.GameDir != "")
			}
		})
	}()
}
