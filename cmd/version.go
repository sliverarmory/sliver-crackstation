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
	"runtime/debug"
	"time"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and exit",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			fmt.Fprintln(cmd.OutOrStdout(), "unknown")
			return
		}

		version := info.Main.Version
		if version == "" {
			version = "unknown"
		}

		revision := ""
		buildTime := ""
		modified := ""
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.time":
				buildTime = setting.Value
			case "vcs.modified":
				modified = setting.Value
			}
		}
		if revision == "" {
			revision = "unknown"
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s - %s", version, revision)
		if modified == "true" {
			fmt.Fprint(cmd.OutOrStdout(), " (dirty)")
		}
		if buildTime != "" {
			if parsed, err := time.Parse(time.RFC3339, buildTime); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), " - %s", parsed.Local())
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), " - %s", buildTime)
			}
		}
		fmt.Fprintln(cmd.OutOrStdout())
	},
}
