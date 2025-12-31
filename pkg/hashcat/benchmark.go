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
	"errors"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

func (h *Hashcat) Benchmark(cmd *clientpb.CrackCommand) (map[int32]uint64, error) {
	if !cmd.Benchmark && !cmd.BenchmarkAll {
		return nil, errors.New("invalid benchmark command")
	}
	data, err := h.Crack(cmd)
	if err != nil {
		return nil, err
	}
	return parseBenchmark(string(data))
}

func parseBenchmark(data string) (map[int32]uint64, error) {
	benchmarks := map[int32]uint64{}
	lines := strings.Split(data, "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, "* Hash-Mode") {
			hashModeR := strings.TrimPrefix(line, "* Hash-Mode")
			hashModeL := strings.Split(hashModeR, "(")[0]
			hashMode, err := strconv.ParseInt(strings.TrimSpace(hashModeL), 10, 32)
			if err != nil {
				return nil, err
			}
			benchmarks[int32(hashMode)] = parseHashModeSpeed(int32(index+1), lines)
		}
	}
	return benchmarks, nil
}

func parseHashModeSpeed(index int32, lines []string) uint64 {
	for _, line := range lines[index:] {
		if strings.Contains(line, "Speed.#1") {
			speedR := strings.Split(line, "(")[0]
			speedL := strings.Split(speedR, ":")[1]
			speedRate := []string{}
			for _, value := range strings.Split(speedL, " ") {
				if value != "" {
					speedRate = append(speedRate, value)
				}
			}
			// log.Printf("speedRate: %#v", speedRate)
			if len(speedRate) != 2 {
				return 0
			}
			speed, err := strconv.ParseFloat(strings.TrimSpace(speedRate[0]), 64)
			if err != nil {
				return 0
			}
			switch strings.TrimSpace(speedRate[1]) {
			case "kH/s":
				return uint64(speed * 1000)
			case "MH/s":
				return uint64(speed * 1000000)
			case "GH/s":
				return uint64(speed * 1000000000)
			default:
				return uint64(speed)
			}
		}
	}
	return 0
}
