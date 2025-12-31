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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	sliverClientAssets "github.com/bishopfox/sliver/client/assets"
	"github.com/sliverarmory/sliver-crackstation/assets"
	"github.com/sliverarmory/sliver-crackstation/cmd/tui"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

const (
	nameFlagStr           = "name"
	operatorConfigFlagStr = "config"
)

func initConnectCmd() *cobra.Command {
	connectCmd.Flags().StringP(nameFlagStr, "n", "", "Name of the crackstation (blank = hostname)")
	connectCmd.Flags().StringP(operatorConfigFlagStr, "c", "", "Path to operator config file")
	connectCmd.Flags().Bool(forceFlagStr, false, "Force unpacking of assets")
	return connectCmd
}

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to a Sliver C2 server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		force, err := cmd.Flags().GetBool(forceFlagStr)
		if err != nil {
			log.Printf("Failed to parse --%s flag %s\n", forceFlagStr, err)
			os.Exit(1)
		}
		assets.Setup(force, true)

		configPath, err := cmd.Flags().GetString(operatorConfigFlagStr)
		if err != nil {
			log.Printf("Failed to parse --%s flag %s\n", operatorConfigFlagStr, err)
			os.Exit(1)
		}
		if configPath == "" {
			log.Printf("Missing --%s flag\n", operatorConfigFlagStr)
			os.Exit(1)
		}
		config, err := sliverClientAssets.ReadConfig(configPath)
		if err != nil {
			log.Printf("Failed to read config %s\n", err)
			os.Exit(-1)
		}
		configs := []sliverClientAssets.ClientConfig{*config}

		name, err := cmd.Flags().GetString(nameFlagStr)
		if err != nil {
			log.Printf("Failed to parse --%s flag %s\n", nameFlagStr, err)
			os.Exit(1)
		}
		if name == "" {
			name, err = os.Hostname()
			if err != nil {
				log.Printf("Failed to get hostname: %s", err)
				name = fmt.Sprintf("%s's %s cracker", config.Operator, runtime.GOOS)
			}
		}
		log.Printf("Hello my name is '%s'", name)

		// initialize the hashcat
		hashcatInstance := hashcat.NewHashcat(assets.GetHashcatDir())
		log.Printf("[hashcat] %s", hashcatInstance.Version())
		log.Printf("[hashcat] enumerating hashcat devices ...")
		fmt.Printf("Enumerating hashcat devices ... ")
		err = hashcatInstance.BackendInfo()
		if err != nil {
			fmt.Printf("failure!\n")
			log.Printf("Failed to get hashcat backend info: %s", err)
			os.Exit(-1)
		}

		metal, _ := json.Marshal(hashcatInstance.MetalBackend)
		log.Printf("[hashcat] metal: %s", metal)
		openCL, _ := json.Marshal(hashcatInstance.OpenCLBackend)
		log.Printf("[hashcat] open-cl: %s", openCL)
		cuda, _ := json.Marshal(hashcatInstance.CUDABackend)
		log.Printf("[hashcat] cuda: %s", cuda)

		if len(metal) == 0 && len(openCL) == 0 && len(cuda) == 0 {
			fmt.Printf("no devices!\n")
			log.Printf("No hashcat devices found")
			os.Exit(-1)
		}
		fmt.Printf("done\n")

		fmt.Printf("   CUDA: %d device(s)\n", len(hashcatInstance.CUDABackend))
		fmt.Printf(" OpenCL: %d device(s)\n", len(hashcatInstance.OpenCLBackend))
		fmt.Printf("  Metal: %d device(s)\n", len(hashcatInstance.MetalBackend))

		log.Printf("Initializing crackstation ...")
		dataDir := filepath.Join(assets.GetRootAppDir(), "data")

		cracker, err := crackstation.NewCrackstation(name, dataDir, hashcatInstance)
		if err != nil {
			log.Printf("Failed to initialize crackstation: %s", err)
			os.Exit(-2)
		}

		_, err = cracker.LoadBenchmarkResults()
		if err != nil {
			log.Printf("Could not find benchmark results, starting benchmark ...")
			fmt.Printf("Benchmarking system, please wait ... ")
			err = cracker.Benchmark()
			if err != nil {
				log.Printf("Failed to benchmark: %s", err)
				fmt.Printf("failure!\n")
				fmt.Printf("Failed to benchmark: %s\n", err)
				os.Exit(-3)
			}
			fmt.Printf("done\n")
		}

		for _, config := range configs {
			log.Printf("Subscribing to %s:%d", config.LHost, config.LPort)
			cracker.AddServer(&config)
		}

		_, err = unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
		if err == nil {
			tui.StartTUI(cracker)
		} else {
			cracker.Start()
		}
	},
}
