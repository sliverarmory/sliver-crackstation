package assets

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sliverarmory/sliver-crackstation/util"
)

const (
	envVarName      = "SLIVER_CRACKSTATION_ROOT_DIR"
	versionFileName = "version"
)

var (
	Revision   string
	LastCommit time.Time
	DirtyBuild bool
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			Revision = kv.Value
		case "vcs.time":
			LastCommit, _ = time.Parse(time.RFC3339, kv.Value)
		case "vcs.modified":
			DirtyBuild = kv.Value == "true"
		}
	}
}

func GetRootAppDir() string {
	value := os.Getenv(envVarName)
	var dir string
	if len(value) == 0 {
		user, _ := user.Current()
		dir = filepath.Join(user.HomeDir, ".sliver-crackstation")
	} else {
		dir = value
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			slog.Error("Cannot write to sliver root dir", "err", err)
			os.Exit(1)
		}
	}
	return dir
}

func GetAppTmpDir() string {
	appDir := GetRootAppDir()
	tmpDir := filepath.Join(appDir, ".tmp")
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		err = os.MkdirAll(tmpDir, 0700)
		if err != nil {
			slog.Error("Cannot write to sliver tmp dir", "err", err)
			os.Exit(1)
		}
	}
	return tmpDir
}

func GetHashcatDir() string {
	appDir := GetRootAppDir()
	hashcatDir := filepath.Join(appDir, "hashcat")
	if _, err := os.Stat(hashcatDir); os.IsNotExist(err) {
		err = os.MkdirAll(hashcatDir, 0700)
		if err != nil {
			slog.Error("Cannot write to sliver hashcat dir", "err", err)
			os.Exit(1)
		}
	}
	return hashcatDir
}

// Setup - Extract or create local assets
func Setup(force bool, echo bool) {
	appDir := GetRootAppDir()
	localVer := assetVersion()
	if force || localVer == "" || localVer != Revision {
		slog.Info("Asset version mismatch", "local", localVer, "expected", Revision)
		if echo {
			fmt.Printf(`
Sliver Crackstation  Copyright (C) 2022  Bishop Fox
This program comes with ABSOLUTELY NO WARRANTY; for details type 'licenses'.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'licenses' for details.`)
			fmt.Printf("\n\nUnpacking assets ...\n")
		}
		err := unpackAssets(appDir)
		if err != nil {
			slog.Error("Failed to unpack assets", "err", err)
			os.Exit(1)
		}
		saveAssetVersion(appDir)
	}
}

func unpackAssets(appDir string) error {
	slog.Info("Unpacking assets", "path", appDir)
	err := unpackHashcat(appDir)
	if err != nil {
		slog.Error("Failed to unpack hashcat", "err", err)
		return err
	}
	return nil
}

func unpackHashcat(appDir string) error {
	hashcatDir := GetHashcatDir()
	if _, err := os.Stat(hashcatDir); !os.IsNotExist(err) {
		slog.Info("Hashcat already exists, removing old version", "path", hashcatDir)
		err = util.ChmodR(hashcatDir, 0600, 0700)
		if err != nil {
			slog.Warn("Failed to chmod hashcat dir", "err", err)
		}
		err = os.RemoveAll(hashcatDir)
		if err != nil {
			slog.Warn("Failed to remove hashcat dir", "err", err)
		}
	}
	// embed fs always uses '/' path separators regardless of GOOS
	hashcatZip, err := assetsFs.ReadFile(path.Join(runtime.GOOS, runtime.GOARCH, "hashcat.zip"))
	if err != nil {
		return err
	}
	_, err = util.UnzipBuf(hashcatZip, hashcatDir)
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		os.Chmod(filepath.Join(hashcatDir, "hashcat"), 0755)
	}
	return nil
}

func assetVersion() string {
	appDir := GetRootAppDir()
	data, err := os.ReadFile(filepath.Join(appDir, versionFileName))
	if err != nil {
		slog.Warn("No version detected", "err", err)
		return ""
	}
	return strings.TrimSpace(string(data))
}

func saveAssetVersion(appDir string) {
	versionFilePath := filepath.Join(appDir, versionFileName)
	fVer, err := os.Create(versionFilePath)
	if err != nil {
		slog.Error("Failed to create version file", "err", err)
		os.Exit(1)
	}
	defer fVer.Close()
	fVer.Write([]byte(Revision))
}
