package crackstation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
)

var hashcatTaskMaterializationPrefixes = []string{
	"hashes",
	"potfile",
	"restore-file",
	"rules",
	"markov-hcstat2",
	"keyboard-layout-mapping",
}

// CleanupStaleTaskMaterializations removes task inputs and recovered outputs
// left behind when the previous process could not run its deferred cleanup.
// It is intended to run once during application startup, before task workers.
func (c *Crackstation) CleanupStaleTaskMaterializations(appTmpDir string) error {
	if c == nil || c.dataDir == "" {
		return errors.New("missing crackstation data directory")
	}
	if appTmpDir == "" {
		return errors.New("missing application temporary directory")
	}
	if err := removeStaleMaterializations(filepath.Join(c.dataDir, "tasks"), []string{".recovered-"}); err != nil {
		return fmt.Errorf("clean recovered task outputs: %w", err)
	}
	if err := removeStaleMaterializations(appTmpDir, hashcatTaskMaterializationPrefixes); err != nil {
		return fmt.Errorf("clean hashcat task inputs: %w", err)
	}
	if err := removeStaleMaterializationDirectories(appTmpDir, []string{hashcat.ManagedWorkDirPrefix}); err != nil {
		return fmt.Errorf("clean hashcat task working directories: %w", err)
	}
	return nil
}

func removeStaleMaterializations(directory string, prefixes []string) error {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %q: %w", directory, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !hasNonemptyPrefix(entry.Name(), prefixes) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect %q: %w", filepath.Join(directory, entry.Name()), err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %q: %w", path, err)
		}
	}
	return nil
}

func removeStaleMaterializationDirectories(directory string, prefixes []string) error {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %q: %w", directory, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !hasNonemptyPrefix(entry.Name(), prefixes) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if err := os.RemoveAll(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %q: %w", path, err)
		}
	}
	return nil
}

func hasNonemptyPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && len(name) > len(prefix) && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
