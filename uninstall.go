//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// storageJSON mirrors the fields we need from
// %APPDATA%\HorizonXI-Launcher\storage.json
type storageJSON struct {
	Paths struct {
		InstallPath struct {
			Path string `json:"path"`
		} `json:"installPath"`
	} `json:"paths"`
}

// DetectedPaths holds what was found during the pre-scan.
// An empty string means that path was not found.
type DetectedPaths struct {
	GameDir           string // parent of the "Game" folder, e.g. D:\Games\HorizonXI\
	LauncherAppData   string // %APPDATA%\HorizonXI-Launcher
	LauncherLocalData string // %LOCALAPPDATA%\HorizonXI_Launcher
	AshitaCliFound    bool   // true when Game\Ashita-cli.exe exists inside GameDir
}

var (
	gamePathRe  = regexp.MustCompile(`(?i)([A-Za-z]:\\.+\\)Game`)
	userMaskRe  *regexp.Regexp
	userMaskStr string
)

func init() {
	if u := os.Getenv("USERNAME"); u != "" {
		userMaskRe = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(u))
		userMaskStr = strings.Repeat("X", len(u))
	}
}

// maskUser replaces the current Windows username in s with a run of X's.
func maskUser(s string) string {
	if userMaskRe == nil {
		return s
	}
	return userMaskRe.ReplaceAllLiteralString(s, userMaskStr)
}

// DetectInstallation reads storage.json and resolves all three paths.
// It never returns an error — a missing file or bad JSON simply
// leaves the relevant field empty.
func DetectInstallation() DetectedPaths {
	var d DetectedPaths

	appData := os.Getenv("APPDATA")
	localAppData := os.Getenv("LOCALAPPDATA")

	d.LauncherAppData = appData + `\HorizonXI-Launcher`
	d.LauncherLocalData = localAppData + `\HorizonXI_Launcher`

	cfg, err := readStorageJSON(d.LauncherAppData + `\storage.json`)
	if err == nil {
		d.GameDir = extractGameDir(cfg.Paths.InstallPath.Path)
	}

	if d.GameDir != "" {
		ashitaCli := filepath.Join(d.GameDir, "Game", "Ashita-cli.exe")
		_, err := os.Stat(ashitaCli)
		d.AshitaCliFound = err == nil
	}

	return d
}

func readStorageJSON(path string) (storageJSON, error) {
	var cfg storageJSON
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

// extractGameDir applies the same regex as the PowerShell script:
//
//	$path -match "(?<installpath>\w:\\.+\\)Game"
//
// and returns the captured group (everything up to and including the
// backslash before "Game"), or an empty string if no match.
func extractGameDir(installPath string) string {
	m := gamePathRe.FindStringSubmatch(installPath)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// RunUninstall performs all four uninstall steps, sending log lines to logCh.
// Every step is attempted regardless of whether earlier steps failed,
// mirroring PowerShell's -ErrorAction Ignore.
// When dryRun is true, no files are deleted and no packages are removed —
// actions are only logged.
// logCh is closed when all work is done.
// Call this in a goroutine — it can block for several seconds.
func RunUninstall(paths DetectedPaths, dryRun bool, logCh chan<- string) {
	defer close(logCh)

	if dryRun {
		logCh <- "[DRY RUN] No changes will be made.\r\n"
	}
	logCh <- "Starting clean uninstall...\r\n"

	logCh <- "--- Step 1: Uninstalling via Windows Package Manager ---"
	uninstallPackage(dryRun, logCh)

	logCh <- "\r\n--- Step 2: Removing game directory ---"
	removeDir(paths.GameDir, dryRun, logCh)

	logCh <- "\r\n--- Step 3: Removing launcher data (%APPDATA%) ---"
	removeDir(paths.LauncherAppData, dryRun, logCh)

	logCh <- "\r\n--- Step 4: Removing launcher config (%LOCALAPPDATA%) ---"
	removeDir(paths.LauncherLocalData, dryRun, logCh)

	logCh <- "\r\nDone."
}

// uninstallPackage runs Uninstall-Package via PowerShell with no visible
// console window. When dryRun is true it only logs what it would do.
func uninstallPackage(dryRun bool, logCh chan<- string) {
	send := func(s string) { logCh <- maskUser(s) }

	if dryRun {
		send("[DRY RUN] would run: Uninstall-Package -Name 'HorizonXI-Launcher'")
		return
	}

	cmd := exec.Command(
		"powershell.exe",
		"-NonInteractive", "-NoProfile", "-WindowStyle", "Hidden",
		"-Command", "Uninstall-Package -Name 'HorizonXI-Launcher' -ErrorAction Ignore",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		send(fmt.Sprintf("[skip] Uninstall-Package: %v", err))
	} else if output != "" {
		send(fmt.Sprintf("[done] Uninstall-Package: %s", output))
	} else {
		send("[done] Uninstall-Package completed (or was not installed)")
	}
}

// removeDir removes a directory tree, logging each action to logCh.
// A missing directory or empty path is treated as a non-error,
// mirroring -ErrorAction Ignore.
// When dryRun is true it only logs what it would do.
func removeDir(path string, dryRun bool, logCh chan<- string) {
	send := func(s string) { logCh <- maskUser(s) }

	if path == "" {
		send("[skip] path not detected")
		return
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		send(fmt.Sprintf("[skip] not found: %s", path))
		return
	}
	if dryRun {
		send(fmt.Sprintf("[DRY RUN] would remove: %s", path))
		return
	}
	send(fmt.Sprintf("[removing] %s ...", path))
	if err := os.RemoveAll(path); err != nil {
		send(fmt.Sprintf("[error] could not remove %s: %v", path, err))
	} else {
		send(fmt.Sprintf("[done] removed: %s", path))
	}
}
