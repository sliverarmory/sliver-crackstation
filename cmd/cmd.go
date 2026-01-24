package cmd

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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/sliverarmory/sliver-crackstation/assets"
	"github.com/sliverarmory/sliver-crackstation/pkg/config"
	"github.com/spf13/cobra"
)

const (
	// ANSI Colors
	Normal    = "\033[0m"
	Black     = "\033[30m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Orange    = "\033[33m"
	Blue      = "\033[34m"
	Purple    = "\033[35m"
	Cyan      = "\033[36m"
	Gray      = "\033[37m"
	Bold      = "\033[1m"
	Clearln   = "\r\x1b[2K"
	UpN       = "\033[%dA"
	DownN     = "\033[%dB"
	Underline = "\033[4m"

	// Info - Display colorful information
	Info = Bold + Cyan + "[*] " + Normal
	// Warn - Warn a user
	Warn = Bold + Red + "[!] " + Normal
	// Debug - Display debug information
	Debug = Bold + Purple + "[-] " + Normal
	// Woot - Display success
	Woot = Bold + Green + "[$] " + Normal
	// Success - Display success
	Success = Bold + Green + "[+] " + Normal
)

const logLevelFlagStr = "log-level"

func init() {
	rootCmd.AddCommand(initConnectCmd())
	rootCmd.AddCommand(initUnpackCmd())
	rootCmd.AddCommand(versionCmd)
	rootCmd.Flags().String(logLevelFlagStr, "", "Log level (debug, info, warn, error)")
}

var logFile *os.File
var logLevelVar slog.LevelVar

func initConsoleLogging(appDir string) *os.File {
	openedFile, err := os.OpenFile(filepath.Join(appDir, "crackstation.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
		os.Exit(1)
	}
	setLoggerOutput(openedFile)
	logFile = openedFile
	return openedFile
}

func enableStdoutLogging() {
	if logFile == nil {
		setLoggerOutput(os.Stdout)
		return
	}
	setLoggerOutput(io.MultiWriter(logFile, os.Stdout))
}

func setLoggerOutput(w io.Writer) {
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		AddSource: true,
		Level:     &logLevelVar,
	})
	slog.SetDefault(slog.New(handler))
}

func configureLogLevel(level string) error {
	if level == "" {
		return nil
	}
	parsed, err := parseLogLevel(level)
	if err != nil {
		return err
	}
	logLevelVar.Set(parsed)
	return nil
}

func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q", level)
	}
}

var rootCmd = &cobra.Command{
	Use:   "sliver-crackstation",
	Short: "GPU accelerated password cracking integration for Sliver C2",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		logLevelFlag, _ := cmd.Flags().GetString(logLevelFlagStr)
		cfg, configPath, err := config.LoadDefault(assets.GetRootAppDir())
		if err != nil {
			if os.IsNotExist(err) {
				_ = cmd.Help()
				return
			}
			fmt.Printf("Failed to read config %s: %v\n", configPath, err)
			os.Exit(1)
		}

		logLevel := logLevelFlag
		if logLevel == "" && cfg != nil && cfg.LogLevel != "" {
			logLevel = cfg.LogLevel
		}
		if err := configureLogLevel(logLevel); err != nil {
			fmt.Printf("Invalid log level: %v\n", err)
			os.Exit(1)
		}

		connectArgs, err := cfg.ConnectArgs()
		if err != nil {
			fmt.Printf("Failed to build connect args: %v\n", err)
			os.Exit(1)
		}

		options, err := parseConnectOptions(connectArgs)
		if err != nil {
			fmt.Printf("Failed to parse connect args: %v\n", err)
			os.Exit(1)
		}
		if logLevel == "" && options.LogLevel != "" {
			if err := configureLogLevel(options.LogLevel); err != nil {
				fmt.Printf("Invalid log level: %v\n", err)
				os.Exit(1)
			}
		}

		if err := runConnectWithOptions(options); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

// Execute - Execute root command
func Execute() {
	initConsoleLogging(assets.GetRootAppDir())
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
