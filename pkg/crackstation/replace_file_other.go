//go:build !windows

package crackstation

import (
	"os"
	"path/filepath"
)

func replaceFileAtomically(temporaryPath, finalPath string) error {
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return err
	}
	// Persist the directory entry as well as the already-fsynced file so a
	// completed sync survives a sudden restart.
	directory, err := os.Open(filepath.Dir(finalPath))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
