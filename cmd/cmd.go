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
	"log"
	"os"
	"path/filepath"

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

func init() {
	rootCmd.AddCommand(initConnectCmd())
	rootCmd.AddCommand(initUnpackCmd())
	rootCmd.AddCommand(versionCmd)
}

var logFile *os.File

func initConsoleLogging(appDir string) *os.File {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	openedFile, err := os.OpenFile(filepath.Join(appDir, "crackstation.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	log.SetOutput(openedFile)
	logFile = openedFile
	return openedFile
}

func enableStdoutLogging() {
	if logFile == nil {
		log.SetOutput(os.Stdout)
		return
	}
	log.SetOutput(io.MultiWriter(logFile, os.Stdout))
}

var rootCmd = &cobra.Command{
	Use:   "sliver-crackstation",
	Short: "GPU accelerated password cracking integration for Sliver C2",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, configPath, err := config.LoadDefault(assets.GetRootAppDir())
		if err != nil {
			if os.IsNotExist(err) {
				_ = cmd.Help()
				return
			}
			fmt.Printf("Failed to read config %s: %v\n", configPath, err)
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
