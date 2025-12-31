package hashcat

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
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

func NewHashcat(hashcatDir string) *Hashcat {
	if _, err := os.Stat(hashcatDir); os.IsNotExist(err) {
		panic(err)
	}
	if _, err := os.Stat(filepath.Join(hashcatDir, hashcatExe)); os.IsNotExist(err) {
		panic(err)
	}
	return &Hashcat{
		exe:        filepath.Join(hashcatDir, hashcatExe),
		cwd:        hashcatDir,
		hashcatDir: hashcatDir,
	}
}

type Hashcat struct {
	exe        string
	cwd        string
	hashcatDir string

	CUDABackend   []*clientpb.CUDABackendInfo
	MetalBackend  []*clientpb.MetalBackendInfo
	OpenCLBackend []*clientpb.OpenCLBackendInfo
}

func (h *Hashcat) hashcatCmd(args []string) ([]byte, error) {
	log.Printf("[hashcat] %s %s", h.exe, strings.Join(args, " "))
	cmd := exec.Command(h.exe, args...)
	cmd.Dir = h.cwd
	cmd.Env = os.Environ()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Printf("[hashcat] --- env ---\n")
		for _, envVar := range cmd.Env {
			log.Printf("%s\n", envVar)
		}
		log.Printf("[hashcat] --- stdout ---\n%s\n", stdout.String())
		log.Printf("[hashcat] --- stderr ---\n%s\n", stderr.String())
		log.Println(err)
	}
	return stdout.Bytes(), err
}

func (h *Hashcat) BackendInfo() error {
	rawBackendInfo, err := h.hashcatCmd([]string{"--backend-info"})
	if err != nil {
		return err
	}
	lines := strings.Split(string(rawBackendInfo), "\n")
	for index, line := range lines {
		switch strings.TrimSpace(line) {
		case "CUDA Info:":
			h.parseCUDABackendInfo(index+1, lines)
		case "Metal Info:":
			h.parseMetalBackendInfo(index+1, lines)
		case "OpenCL Info:":
			h.parseOpenCLBackendInfo(index+1, lines)
		}
	}
	return nil
}

func (h *Hashcat) parseCUDABackendInfo(index int, lines []string) {
	h.CUDABackend = []*clientpb.CUDABackendInfo{}
	cudaVersion := ""
	for ; index < len(lines); index++ {
		{
			line := strings.TrimSpace(lines[index])
			if line == "" {
				continue
			}
			if strings.Contains(line, "CUDA.Version.:") {
				cudaVersion = strings.TrimSpace(strings.Split(line, ":")[1])
				continue
			}
			if strings.Contains(line, "Backend Device ID") {
				cuda := h.parseCudaDevice(index+1, lines)
				cuda.Version = cudaVersion
				h.CUDABackend = append(h.CUDABackend, cuda)
				continue
			}
			if strings.HasPrefix(line, "OpenCL") || strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "Metal") {
				break
			}
		}
	}
}

func (h *Hashcat) parseCudaDevice(index int, lines []string) *clientpb.CUDABackendInfo {
	cuda := &clientpb.CUDABackendInfo{}
	for ; index < len(lines); index++ {
		if strings.Contains(strings.TrimSpace(lines[index]), "Name") {
			cuda.Name = strings.TrimSpace(strings.Split(lines[index], ":")[1])
		}
		if strings.Contains(lines[index], "Processor(s)") {
			processorCount, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				cuda.Processors = int32(processorCount)
				continue
			}
		}
		if strings.Contains(lines[index], "Clock") {
			if strings.TrimSpace(strings.Split(lines[index], ":")[1]) == "N/A" {
				cuda.Clock = -1
				continue
			}
			clock, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				cuda.Clock = int32(clock)
				continue
			}
		}
		if strings.Contains(lines[index], "Memory.Total") {
			cuda.MemoryTotal = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Memory.Free") {
			cuda.MemoryFree = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "PCI.Addr.BDFe.") {
			break
		}
	}
	return cuda
}

func (h *Hashcat) parseMetalBackendInfo(index int, lines []string) {
	h.MetalBackend = []*clientpb.MetalBackendInfo{}
	metalVersion := ""
	for ; index < len(lines); index++ {
		{
			line := strings.TrimSpace(lines[index])
			if line == "" {
				continue
			}
			if strings.Contains(line, "Metal.Version.:") {
				metalVersion = strings.TrimSpace(strings.Split(line, ":")[1])
				continue
			}
			if strings.Contains(line, "Backend Device ID") {
				metal := h.parseMetalDevice(index+1, lines)
				metal.Version = metalVersion
				h.MetalBackend = append(h.MetalBackend, metal)
				continue
			}
			if strings.HasPrefix(line, "OpenCL") || strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "Metal") {
				break
			}
		}
	}
}

func (h *Hashcat) parseMetalDevice(index int, lines []string) *clientpb.MetalBackendInfo {
	metal := &clientpb.MetalBackendInfo{}
	for ; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) == "" {
			continue
		}
		if strings.Contains(lines[index], "Type...........:") {
			metal.Type = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Vendor.ID......:") {
			vendorID, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				metal.VendorID = int32(vendorID)
				continue
			}
		}
		if strings.Contains(lines[index], "Vendor.........:") {
			metal.Vendor = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Name...........:") {
			metal.Name = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Processor(s)...:") {
			processorCount, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				metal.Processors = int32(processorCount)
				continue
			}
		}
		if strings.Contains(lines[index], "Clock..........:") {
			if strings.TrimSpace(strings.Split(lines[index], ":")[1]) == "N/A" {
				metal.Clock = -1
				continue
			}
			clock, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				metal.Clock = int32(clock)
				continue
			}
		}
		if strings.Contains(lines[index], "Memory.Total...:") {
			metal.MemoryTotal = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Memory.Free....:") {
			metal.MemoryFree = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.HasPrefix(lines[index], "GPU.Properties.:") {
			break
		}
	}
	return metal
}

func (h *Hashcat) parseOpenCLBackendInfo(index int, lines []string) {
	h.OpenCLBackend = []*clientpb.OpenCLBackendInfo{}
	for ; index < len(lines); index++ {
		{
			line := strings.TrimSpace(lines[index])
			if line == "" {
				continue
			}
			if strings.Contains(line, "OpenCL Platform ID") {
				openCLs := h.parseOpenCLPlatform(index+1, lines)
				h.OpenCLBackend = append(h.OpenCLBackend, openCLs...)
				continue
			}
			if strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "Metal") {
				break
			}
		}
	}
}

func (h *Hashcat) parseOpenCLPlatform(index int, lines []string) []*clientpb.OpenCLBackendInfo {
	platform := []*clientpb.OpenCLBackendInfo{}
	for ; index < len(lines); index++ {
		line := strings.TrimSpace(lines[index])
		if line == "" {
			continue
		}
		if strings.Contains(line, "Backend Device ID") {
			platform = append(platform, h.parseOpenCLDevice(index+1, lines))
			continue
		}
		if strings.HasPrefix(line, "OpenCL Platform ID") || strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "Metal") {
			break
		}
	}
	return platform
}

func (h *Hashcat) parseOpenCLDevice(index int, lines []string) *clientpb.OpenCLBackendInfo {
	openCL := &clientpb.OpenCLBackendInfo{}
	for ; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) == "" {
			continue
		}
		if strings.Contains(lines[index], "Type...........:") {
			openCL.Type = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Vendor.ID......:") {
			vendorID, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				openCL.VendorID = int32(vendorID)
				continue
			}
		}
		if strings.Contains(lines[index], "Vendor.........:") {
			openCL.Vendor = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Name...........:") {
			openCL.Name = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Processor(s)...:") {
			processorCount, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				openCL.Processors = int32(processorCount)
				continue
			}
		}
		if strings.Contains(lines[index], "Clock..........:") {
			if strings.TrimSpace(strings.Split(lines[index], ":")[1]) == "N/A" {
				openCL.Clock = -1
				continue
			}
			clock, err := strconv.Atoi(strings.TrimSpace(strings.Split(lines[index], ":")[1]))
			if err == nil {
				openCL.Clock = int32(clock)
				continue
			}
		}
		if strings.Contains(lines[index], "Memory.Total...:") {
			openCL.MemoryTotal = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "Memory.Free....:") {
			openCL.MemoryFree = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.Contains(lines[index], "OpenCL.Version.:") {
			openCL.Version = strings.TrimSpace(strings.Split(lines[index], ":")[1])
			continue
		}
		if strings.HasPrefix(lines[index], "Driver.Version.:") {
			break
		}
	}
	return openCL
}

func (h *Hashcat) Version() string {
	data, err := h.hashcatCmd([]string{"--version"})
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
