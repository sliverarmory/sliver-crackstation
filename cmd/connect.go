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
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	sliverClientAssets "github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/sliverarmory/sliver-crackstation/assets"
	"github.com/sliverarmory/sliver-crackstation/cmd/tui"
	"github.com/sliverarmory/sliver-crackstation/pkg/crackstation"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
	"google.golang.org/grpc/keepalive"
)

const (
	nameFlagStr                             = "name"
	operatorConfigFlagStr                   = "config"
	disableTUIFlagStr                       = "disable-tui"
	forceBenchmarkFlagStr                   = "force-benchmark"
	grpcKeepaliveTimeFlagStr                = "grpc-keepalive-time"
	grpcKeepaliveTimeoutFlagStr             = "grpc-keepalive-timeout"
	grpcKeepalivePermitWithoutStreamFlagStr = "grpc-keepalive-permit-without-stream"
)

const minKeepaliveTime = 5 * time.Minute

func initConnectCmd() *cobra.Command {
	connectCmd.Flags().StringP(nameFlagStr, "n", "", "Name of the crackstation (blank = hostname)")
	connectCmd.Flags().StringP(operatorConfigFlagStr, "c", "", "Path to operator config file")
	connectCmd.Flags().Bool(forceFlagStr, false, "Force unpacking of assets")
	connectCmd.Flags().Bool(disableTUIFlagStr, false, "Disable the TUI and log status to stdout")
	connectCmd.Flags().Bool(forceBenchmarkFlagStr, false, "Always run hashcat benchmarks before starting")
	connectCmd.Flags().Duration(grpcKeepaliveTimeFlagStr, minKeepaliveTime, "gRPC keepalive ping interval")
	connectCmd.Flags().Duration(grpcKeepaliveTimeoutFlagStr, 20*time.Second, "gRPC keepalive ping timeout")
	connectCmd.Flags().Bool(grpcKeepalivePermitWithoutStreamFlagStr, false, "Send gRPC keepalive pings when idle")
	connectCmd.Flags().String(logLevelFlagStr, "", "Log level (debug, info, warn, error)")
	return connectCmd
}

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to a Sliver C2 server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		logLevel, _ := cmd.Flags().GetString(logLevelFlagStr)
		if err := configureLogLevel(logLevel); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid log level: %v\n", err)
			os.Exit(1)
		}

		options, err := connectOptionsFromFlags(cmd.Flags())
		if err != nil {
			slog.Error("Failed to parse connect flags", "err", err)
			os.Exit(1)
		}

		if err := runConnectWithOptions(options); err != nil {
			slog.Error("Failed to run connect", "err", err)
			os.Exit(1)
		}
	},
}

type connectOptions struct {
	Name                         string
	OperatorConfig               string
	Force                        bool
	DisableTUI                   bool
	ForceBenchmark               bool
	KeepaliveTime                time.Duration
	KeepaliveTimeout             time.Duration
	KeepalivePermitWithoutStream bool
	LogLevel                     string
}

func connectOptionsFromFlags(flags *pflag.FlagSet) (connectOptions, error) {
	disableTUI, err := flags.GetBool(disableTUIFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	force, err := flags.GetBool(forceFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	configPath, err := flags.GetString(operatorConfigFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	name, err := flags.GetString(nameFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	forceBenchmark, err := flags.GetBool(forceBenchmarkFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	keepaliveTime, err := flags.GetDuration(grpcKeepaliveTimeFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	keepaliveTimeout, err := flags.GetDuration(grpcKeepaliveTimeoutFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	keepalivePermitWithoutStream, err := flags.GetBool(grpcKeepalivePermitWithoutStreamFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	logLevel, err := flags.GetString(logLevelFlagStr)
	if err != nil {
		return connectOptions{}, err
	}

	return connectOptions{
		Name:                         name,
		OperatorConfig:               configPath,
		Force:                        force,
		DisableTUI:                   disableTUI,
		ForceBenchmark:               forceBenchmark,
		KeepaliveTime:                keepaliveTime,
		KeepaliveTimeout:             keepaliveTimeout,
		KeepalivePermitWithoutStream: keepalivePermitWithoutStream,
		LogLevel:                     logLevel,
	}, nil
}

func parseConnectOptions(args []string) (connectOptions, error) {
	flags := pflag.NewFlagSet("connect", pflag.ContinueOnError)
	flags.StringP(nameFlagStr, "n", "", "Name of the crackstation (blank = hostname)")
	flags.StringP(operatorConfigFlagStr, "c", "", "Path to operator config file")
	flags.Bool(forceFlagStr, false, "Force unpacking of assets")
	flags.Bool(disableTUIFlagStr, false, "Disable the TUI and log status to stdout")
	flags.Bool(forceBenchmarkFlagStr, false, "Always run hashcat benchmarks before starting")
	flags.Duration(grpcKeepaliveTimeFlagStr, minKeepaliveTime, "gRPC keepalive ping interval")
	flags.Duration(grpcKeepaliveTimeoutFlagStr, 20*time.Second, "gRPC keepalive ping timeout")
	flags.Bool(grpcKeepalivePermitWithoutStreamFlagStr, false, "Send gRPC keepalive pings when idle")
	flags.String(logLevelFlagStr, "", "Log level (debug, info, warn, error)")
	if err := flags.Parse(args); err != nil {
		return connectOptions{}, err
	}
	return connectOptionsFromFlags(flags)
}

func runConnectWithOptions(options connectOptions) error {
	if options.OperatorConfig == "" {
		return fmt.Errorf("missing --%s flag", operatorConfigFlagStr)
	}

	assets.Setup(options.Force, true)
	if options.KeepaliveTime < minKeepaliveTime {
		slog.Warn("gRPC keepalive time too low; clamping", "requested", options.KeepaliveTime, "minimum", minKeepaliveTime)
		options.KeepaliveTime = minKeepaliveTime
	}
	transport.SetKeepaliveParams(keepalive.ClientParameters{
		Time:                options.KeepaliveTime,
		Timeout:             options.KeepaliveTimeout,
		PermitWithoutStream: options.KeepalivePermitWithoutStream,
	})

	config, err := sliverClientAssets.ReadConfig(options.OperatorConfig)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	configs := []sliverClientAssets.ClientConfig{*config}

	name := options.Name
	if name == "" {
		name, err = os.Hostname()
		if err != nil {
			slog.Warn("Failed to get hostname", "err", err)
			name = fmt.Sprintf("%s's %s cracker", config.Operator, runtime.GOOS)
		}
	}
	slog.Info("Crackstation name resolved", "name", name)

	// initialize the hashcat
	hashcatInstance := hashcat.NewHashcat(assets.GetHashcatDir())
	slog.Info("Hashcat version", "version", hashcatInstance.Version())
	slog.Info("Enumerating hashcat devices")
	fmt.Printf("Enumerating hashcat devices ... ")
	err = hashcatInstance.BackendInfo()
	if err != nil {
		fmt.Printf("failure!\n")
		return fmt.Errorf("failed to get hashcat backend info: %w", err)
	}

	metal, _ := json.Marshal(hashcatInstance.MetalBackend)
	slog.Debug("Hashcat metal backend", "info", string(metal))
	openCL, _ := json.Marshal(hashcatInstance.OpenCLBackend)
	slog.Debug("Hashcat opencl backend", "info", string(openCL))
	cuda, _ := json.Marshal(hashcatInstance.CUDABackend)
	slog.Debug("Hashcat cuda backend", "info", string(cuda))

	if len(metal) == 0 && len(openCL) == 0 && len(cuda) == 0 {
		fmt.Printf("no devices!\n")
		return fmt.Errorf("no hashcat devices found")
	}
	fmt.Printf("done\n")

	fmt.Printf("   CUDA: %d device(s)\n", len(hashcatInstance.CUDABackend))
	fmt.Printf(" OpenCL: %d device(s)\n", len(hashcatInstance.OpenCLBackend))
	fmt.Printf("  Metal: %d device(s)\n", len(hashcatInstance.MetalBackend))

	slog.Info("Initializing crackstation")
	dataDir := filepath.Join(assets.GetRootAppDir(), "data")

	cracker, err := crackstation.NewCrackstation(name, dataDir, hashcatInstance)
	if err != nil {
		return fmt.Errorf("failed to initialize crackstation: %w", err)
	}

	if err := ensureBenchmarks(cracker, options.ForceBenchmark); err != nil {
		return err
	}

	for _, config := range configs {
		slog.Info("Subscribing to server", "host", config.LHost, "port", config.LPort)
		cracker.AddServer(&config)
	}

	hasTTY := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if options.DisableTUI || !hasTTY {
		enableStdoutLogging()
		tui.StartLogOnly(cracker, os.Stdout)
		return nil
	}

	tui.StartTUI(cracker)
	return nil
}

func ensureBenchmarks(cracker *crackstation.Crackstation, force bool) error {
	slog.Info("Checking benchmark cache")
	if !force {
		if _, err := cracker.LoadBenchmarkResults(); err == nil {
			return nil
		}
	}

	slog.Info("Running hashcat benchmark")
	fmt.Printf("Benchmarking system, please wait ... ")
	if err := cracker.EnsureBenchmark(true); err != nil {
		fmt.Printf("failure!\n")
		return fmt.Errorf("failed to benchmark: %w", err)
	}
	fmt.Printf("done\n")
	return nil
}
