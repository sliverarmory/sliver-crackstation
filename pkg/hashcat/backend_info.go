package hashcat

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// HIPBackendInfo mirrors clientpb.HIPBackendInfo in the additive Hashcat 7
// schema. It remains local until a tagged Sliver module contains that message;
// HIPBackendWire serializes it into Crackstation field 103 for rolling
// compatibility with an updated Sliver server.
type HIPBackendInfo struct {
	Type                string
	VendorID            int32
	Vendor              string
	Name                string
	Version             string
	Processors          int32
	Clock               int32
	MemoryTotal         string
	MemoryFree          string
	HIPVersion          string
	BackendDeviceID     uint32
	BackendDeviceAlias  *uint32
	PreferredThreadSize *uint32
	MemoryUnified       *bool
	LocalMemory         string
	CacheSize           string
	PCIAddress          string
}

type machineBackendDocument struct {
	CUDAInfo   *machineRuntimeInfo `json:"CUDAInfo"`
	HIPInfo    *machineRuntimeInfo `json:"HIPInfo"`
	MetalInfo  *machineRuntimeInfo `json:"MetalInfo"`
	OpenCLInfo *machineOpenCLInfo  `json:"OpenCLInfo"`
}

type machineRuntimeInfo struct {
	Version        string                 `json:"Version"`
	BackendDevices []machineBackendDevice `json:"BackendDevices"`
}

type machineOpenCLInfo struct {
	Platforms []machineOpenCLPlatform `json:"Platforms"`
}

type machineOpenCLPlatform struct {
	PlatformID     string                 `json:"PlatformID"`
	Vendor         string                 `json:"Vendor"`
	Name           string                 `json:"Name"`
	Version        string                 `json:"Version"`
	BackendDevices []machineBackendDevice `json:"BackendDevices"`
}

type machineBackendDevice struct {
	DeviceID            string                `json:"DeviceID"`
	Alias               *string               `json:"Alias"`
	Type                string                `json:"Type"`
	VendorID            string                `json:"VendorID"`
	Vendor              string                `json:"Vendor"`
	Name                string                `json:"Name"`
	Version             string                `json:"Version"`
	Processors          string                `json:"Processors"`
	PreferredThreadSize *string               `json:"PreferredThreadSize"`
	Clock               string                `json:"Clock"`
	MemoryTotal         string                `json:"MemoryTotal"`
	MemoryAllocPerBlock string                `json:"MemoryAllocPerBlock"`
	MemoryFree          string                `json:"MemoryFree"`
	MemoryUnified       *string               `json:"MemoryUnified"`
	LocalMemory         string                `json:"LocalMemory"`
	OpenCLVersion       string                `json:"OpenCLVersion"`
	DriverVersion       string                `json:"DriverVersion"`
	PCIAddress          string                `json:"PCIAddrBDFe"`
	OpenCLPCIAddress    string                `json:"PCI.Addr.BDF"`
	PhysicalLocation    string                `json:"PhysicalLocation"`
	RegistryID          *string               `json:"RegistryID"`
	MaxTXRate           string                `json:"MaxTXRate"`
	GPUProperties       *machineGPUProperties `json:"GPUProperties"`
}

type machineGPUProperties struct {
	Headless  *string `json:"headless"`
	LowPower  *string `json:"low_power"`
	Removable *string `json:"removable"`
}

const (
	backendFieldRuntimeVersion      protoreflect.FieldNumber = 10
	backendFieldDeviceID            protoreflect.FieldNumber = 11
	backendFieldAlias               protoreflect.FieldNumber = 12
	backendFieldPreferredThreadSize protoreflect.FieldNumber = 13
	backendFieldMemoryUnified       protoreflect.FieldNumber = 14
	backendFieldLocalMemory         protoreflect.FieldNumber = 15
	backendFieldCacheSize           protoreflect.FieldNumber = 16
	backendFieldPCIAddress          protoreflect.FieldNumber = 17
)

func parseMachineReadableBackendInfo(raw []byte) (
	[]*clientpb.CUDABackendInfo,
	[]*HIPBackendInfo,
	[]*clientpb.MetalBackendInfo,
	[]*clientpb.OpenCLBackendInfo,
	error,
) {
	document := machineBackendDocument{}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("decode hashcat backend JSON: %w", err)
	}

	cuda := []*clientpb.CUDABackendInfo{}
	if document.CUDAInfo != nil {
		for index, device := range document.CUDAInfo.BackendDevices {
			parsed, err := cudaBackendInfo(document.CUDAInfo.Version, device)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode CUDA device %d: %w", index+1, err)
			}
			cuda = append(cuda, parsed)
		}
	}

	hip := []*HIPBackendInfo{}
	if document.HIPInfo != nil {
		for index, device := range document.HIPInfo.BackendDevices {
			parsed, err := hipBackendInfo(document.HIPInfo.Version, device)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode HIP device %d: %w", index+1, err)
			}
			hip = append(hip, parsed)
		}
	}

	metal := []*clientpb.MetalBackendInfo{}
	if document.MetalInfo != nil {
		for index, device := range document.MetalInfo.BackendDevices {
			parsed, err := metalBackendInfo(document.MetalInfo.Version, device)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode Metal device %d: %w", index+1, err)
			}
			metal = append(metal, parsed)
		}
	}

	openCL := []*clientpb.OpenCLBackendInfo{}
	if document.OpenCLInfo != nil {
		for platformIndex, platform := range document.OpenCLInfo.Platforms {
			for deviceIndex, device := range platform.BackendDevices {
				parsed, err := openCLBackendInfo(platform, device)
				if err != nil {
					return nil, nil, nil, nil, fmt.Errorf(
						"decode OpenCL platform %d device %d: %w",
						platformIndex+1,
						deviceIndex+1,
						err,
					)
				}
				openCL = append(openCL, parsed)
			}
		}
	}

	return cuda, hip, metal, openCL, nil
}

type backendCacheKind string

const (
	backendCacheCUDA  backendCacheKind = "CUDA"
	backendCacheHIP   backendCacheKind = "HIP"
	backendCacheMetal backendCacheKind = "Metal"
)

func parseBackendCacheSizes(raw []byte) (map[backendCacheKind]map[uint32]string, error) {
	caches := map[backendCacheKind]map[uint32]string{
		backendCacheCUDA:  {},
		backendCacheHIP:   {},
		backendCacheMetal: {},
	}
	var section backendCacheKind
	var deviceID uint32
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		switch line {
		case "CUDA Info:":
			section = backendCacheCUDA
			deviceID = 0
			continue
		case "HIP Info:":
			section = backendCacheHIP
			deviceID = 0
			continue
		case "Metal Info:":
			section = backendCacheMetal
			deviceID = 0
			continue
		case "OpenCL Info:":
			section = ""
			deviceID = 0
			continue
		}

		const devicePrefix = "Backend Device ID #"
		if strings.HasPrefix(line, devicePrefix) {
			fields := strings.Fields(strings.TrimPrefix(line, devicePrefix))
			if len(fields) == 0 {
				return nil, fmt.Errorf("missing backend device ID in %q", line)
			}
			parsed, err := parseUint32("Backend Device ID", fields[0])
			if err != nil {
				return nil, err
			}
			deviceID = parsed
			continue
		}

		if section == "" || deviceID == 0 || !strings.HasPrefix(line, "Cache.Size") {
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("missing cache-size separator in %q", line)
		}
		caches[section][deviceID] = strings.TrimSpace(value)
	}
	return caches, nil
}

func (h *Hashcat) applyBackendCacheSizes(raw []byte) error {
	caches, err := parseBackendCacheSizes(raw)
	if err != nil {
		return err
	}
	for _, info := range h.CUDABackend {
		reader, err := protocompat.NewReader(info)
		if err != nil {
			return err
		}
		deviceID, err := reader.Uint32(backendFieldDeviceID)
		if err != nil {
			return err
		}
		if cacheSize, ok := caches[backendCacheCUDA][deviceID]; ok {
			if err := protocompat.SetString(info, backendFieldCacheSize, cacheSize); err != nil {
				return err
			}
		}
	}
	for _, info := range h.HIPBackend {
		if cacheSize, ok := caches[backendCacheHIP][info.BackendDeviceID]; ok {
			info.CacheSize = cacheSize
		}
	}
	for _, info := range h.MetalBackend {
		reader, err := protocompat.NewReader(info)
		if err != nil {
			return err
		}
		deviceID, err := reader.Uint32(backendFieldDeviceID)
		if err != nil {
			return err
		}
		if cacheSize, ok := caches[backendCacheMetal][deviceID]; ok {
			if err := protocompat.SetString(info, backendFieldCacheSize, cacheSize); err != nil {
				return err
			}
		}
	}
	return nil
}

func cudaBackendInfo(runtimeVersion string, device machineBackendDevice) (*clientpb.CUDABackendInfo, error) {
	common, err := parseCommonBackendDevice(device)
	if err != nil {
		return nil, err
	}
	info := &clientpb.CUDABackendInfo{
		Type:        common.typ,
		VendorID:    common.vendorID,
		Vendor:      device.Vendor,
		Name:        device.Name,
		Version:     firstNonEmpty(device.Version, runtimeVersion),
		Processors:  common.processors,
		Clock:       common.clock,
		MemoryTotal: device.MemoryTotal,
		MemoryFree:  device.MemoryFree,
		CUDAVersion: runtimeVersion,
	}
	if err := setCommonBackendFields(info, common, device); err != nil {
		return nil, err
	}
	if err := protocompat.SetString(info, backendFieldCacheSize, ""); err != nil {
		return nil, err
	}
	return info, protocompat.SetString(info, backendFieldPCIAddress, device.PCIAddress)
}

func hipBackendInfo(runtimeVersion string, device machineBackendDevice) (*HIPBackendInfo, error) {
	common, err := parseCommonBackendDevice(device)
	if err != nil {
		return nil, err
	}
	return &HIPBackendInfo{
		Type:                common.typ,
		VendorID:            common.vendorID,
		Vendor:              device.Vendor,
		Name:                device.Name,
		Version:             firstNonEmpty(device.Version, runtimeVersion),
		Processors:          common.processors,
		Clock:               common.clock,
		MemoryTotal:         device.MemoryTotal,
		MemoryFree:          device.MemoryFree,
		HIPVersion:          runtimeVersion,
		BackendDeviceID:     common.deviceID,
		BackendDeviceAlias:  common.alias,
		PreferredThreadSize: common.preferredThreadSize,
		MemoryUnified:       common.memoryUnified,
		LocalMemory:         normalizeV71LocalMemory(device.LocalMemory),
		PCIAddress:          device.PCIAddress,
	}, nil
}

func metalBackendInfo(runtimeVersion string, device machineBackendDevice) (*clientpb.MetalBackendInfo, error) {
	common, err := parseCommonBackendDevice(device)
	if err != nil {
		return nil, err
	}
	info := &clientpb.MetalBackendInfo{
		Type:         common.typ,
		VendorID:     common.vendorID,
		Vendor:       device.Vendor,
		Name:         device.Name,
		Version:      firstNonEmpty(device.Version, runtimeVersion),
		Processors:   common.processors,
		Clock:        common.clock,
		MemoryTotal:  device.MemoryTotal,
		MemoryFree:   device.MemoryFree,
		MetalVersion: runtimeVersion,
	}
	if err := setCommonBackendFields(info, common, device); err != nil {
		return nil, err
	}
	if err := protocompat.SetString(info, 16, ""); err != nil {
		return nil, err
	}
	if err := protocompat.SetString(info, 17, device.MemoryAllocPerBlock); err != nil {
		return nil, err
	}
	if err := protocompat.SetString(info, 18, device.PhysicalLocation); err != nil {
		return nil, err
	}
	if device.RegistryID != nil {
		registryID, err := parseUint32("RegistryID", *device.RegistryID)
		if err != nil {
			return nil, err
		}
		if err := protocompat.SetUint32(info, 19, registryID); err != nil {
			return nil, err
		}
	}
	if err := protocompat.SetString(info, 20, device.MaxTXRate); err != nil {
		return nil, err
	}
	if device.GPUProperties != nil {
		properties := []struct {
			number protoreflect.FieldNumber
			name   string
			value  *string
		}{
			{21, "GPUProperties.headless", device.GPUProperties.Headless},
			{22, "GPUProperties.low_power", device.GPUProperties.LowPower},
			{23, "GPUProperties.removable", device.GPUProperties.Removable},
		}
		for _, property := range properties {
			if property.value == nil {
				continue
			}
			value, err := parseBool(property.name, *property.value)
			if err != nil {
				return nil, err
			}
			if err := protocompat.SetBool(info, property.number, value); err != nil {
				return nil, err
			}
		}
	}
	return info, nil
}

func openCLBackendInfo(platform machineOpenCLPlatform, device machineBackendDevice) (*clientpb.OpenCLBackendInfo, error) {
	common, err := parseCommonBackendDevice(device)
	if err != nil {
		return nil, err
	}
	platformID, err := parseUint32("PlatformID", platform.PlatformID)
	if err != nil {
		return nil, err
	}
	info := &clientpb.OpenCLBackendInfo{
		Type:                common.typ,
		VendorID:            common.vendorID,
		Vendor:              device.Vendor,
		Name:                device.Name,
		Version:             device.Version,
		Processors:          common.processors,
		Clock:               common.clock,
		MemoryTotal:         device.MemoryTotal,
		MemoryFree:          device.MemoryFree,
		OpenCLVersion:       device.OpenCLVersion,
		OpenCLDriverVersion: device.DriverVersion,
	}
	// OpenCL shifts the common additive fields by one because tag 11 was
	// already used for the driver version in the original schema.
	if err := protocompat.SetUint32(info, 12, common.deviceID); err != nil {
		return nil, err
	}
	if common.alias != nil {
		if err := protocompat.SetUint32(info, 13, *common.alias); err != nil {
			return nil, err
		}
	}
	if common.preferredThreadSize != nil {
		if err := protocompat.SetUint32(info, 14, *common.preferredThreadSize); err != nil {
			return nil, err
		}
	}
	if common.memoryUnified != nil {
		if err := protocompat.SetBool(info, 15, *common.memoryUnified); err != nil {
			return nil, err
		}
	}
	for _, value := range []struct {
		number protoreflect.FieldNumber
		value  string
	}{
		{16, normalizeV71LocalMemory(device.LocalMemory)},
		{17, device.MemoryAllocPerBlock},
		{18, device.OpenCLPCIAddress},
		{20, platform.Vendor},
		{21, platform.Name},
		{22, platform.Version},
	} {
		if err := protocompat.SetString(info, value.number, value.value); err != nil {
			return nil, err
		}
	}
	if err := protocompat.SetUint32(info, 19, platformID); err != nil {
		return nil, err
	}
	return info, nil
}

type commonBackendDevice struct {
	typ                 string
	vendorID            int32
	processors          int32
	clock               int32
	deviceID            uint32
	alias               *uint32
	preferredThreadSize *uint32
	memoryUnified       *bool
}

func parseCommonBackendDevice(device machineBackendDevice) (commonBackendDevice, error) {
	deviceID, err := parseUint32("DeviceID", device.DeviceID)
	if err != nil {
		return commonBackendDevice{}, err
	}
	vendorID, err := parseInt32("VendorID", device.VendorID, false)
	if err != nil {
		return commonBackendDevice{}, err
	}
	processors, err := parseInt32("Processors", device.Processors, false)
	if err != nil {
		return commonBackendDevice{}, err
	}
	clock, err := parseInt32("Clock", device.Clock, true)
	if err != nil {
		return commonBackendDevice{}, err
	}
	common := commonBackendDevice{
		typ:        device.Type,
		vendorID:   vendorID,
		processors: processors,
		clock:      clock,
		deviceID:   deviceID,
	}
	if device.Alias != nil {
		value, err := parseUint32("Alias", *device.Alias)
		if err != nil {
			return commonBackendDevice{}, err
		}
		common.alias = &value
	}
	if device.PreferredThreadSize != nil {
		value, err := parseUint32("PreferredThreadSize", *device.PreferredThreadSize)
		if err != nil {
			return commonBackendDevice{}, err
		}
		common.preferredThreadSize = &value
	}
	if device.MemoryUnified != nil {
		value, err := parseBool("MemoryUnified", *device.MemoryUnified)
		if err != nil {
			return commonBackendDevice{}, err
		}
		common.memoryUnified = &value
	}
	return common, nil
}

func setCommonBackendFields(info protoreflect.ProtoMessage, common commonBackendDevice, device machineBackendDevice) error {
	if err := protocompat.SetUint32(info, backendFieldDeviceID, common.deviceID); err != nil {
		return err
	}
	if common.alias != nil {
		if err := protocompat.SetUint32(info, backendFieldAlias, *common.alias); err != nil {
			return err
		}
	}
	if common.preferredThreadSize != nil {
		if err := protocompat.SetUint32(info, backendFieldPreferredThreadSize, *common.preferredThreadSize); err != nil {
			return err
		}
	}
	if common.memoryUnified != nil {
		if err := protocompat.SetBool(info, backendFieldMemoryUnified, *common.memoryUnified); err != nil {
			return err
		}
	}
	return protocompat.SetString(info, backendFieldLocalMemory, normalizeV71LocalMemory(device.LocalMemory))
}

func parseUint32(name, value string) (uint32, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", name, value, err)
	}
	return uint32(parsed), nil
}

func parseInt32(name, value string, allowNA bool) (int32, error) {
	if value == "" {
		return 0, nil
	}
	if allowNA && value == "N/A" {
		return -1, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", name, value, err)
	}
	return int32(parsed), nil
}

func parseBool(name, value string) (bool, error) {
	switch value {
	case "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s %q is not a boolean", name, value)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// Hashcat v7.1.2's machine-readable formatter divides local-memory bytes by
// 1024 but labels the value MB. Its human formatter correctly labels the same
// value KB. Normalize that known formatter bug at the boundary.
func normalizeV71LocalMemory(value string) string {
	if strings.HasSuffix(value, " MB") {
		return strings.TrimSuffix(value, " MB") + " KB"
	}
	return value
}

// HIPBackendWire returns HIPBackendInfo messages encoded with the field
// numbers in Sliver's additive Hashcat 7 schema.
func (h *Hashcat) HIPBackendWire() [][]byte {
	values := make([][]byte, 0, len(h.HIPBackend))
	for _, info := range h.HIPBackend {
		values = append(values, marshalHIPBackendInfo(info))
	}
	return values
}

func marshalHIPBackendInfo(info *HIPBackendInfo) []byte {
	if info == nil {
		return nil
	}
	raw := []byte{}
	raw = appendProtoString(raw, 1, info.Type)
	raw = appendProtoInt32(raw, 2, info.VendorID)
	raw = appendProtoString(raw, 3, info.Vendor)
	raw = appendProtoString(raw, 4, info.Name)
	raw = appendProtoString(raw, 5, info.Version)
	raw = appendProtoInt32(raw, 6, info.Processors)
	raw = appendProtoInt32(raw, 7, info.Clock)
	raw = appendProtoString(raw, 8, info.MemoryTotal)
	raw = appendProtoString(raw, 9, info.MemoryFree)
	raw = appendProtoString(raw, 10, info.HIPVersion)
	raw = appendProtoUint32(raw, 11, info.BackendDeviceID, false)
	if info.BackendDeviceAlias != nil {
		raw = appendProtoUint32(raw, 12, *info.BackendDeviceAlias, true)
	}
	if info.PreferredThreadSize != nil {
		raw = appendProtoUint32(raw, 13, *info.PreferredThreadSize, true)
	}
	if info.MemoryUnified != nil {
		raw = protowire.AppendTag(raw, 14, protowire.VarintType)
		if *info.MemoryUnified {
			raw = protowire.AppendVarint(raw, 1)
		} else {
			raw = protowire.AppendVarint(raw, 0)
		}
	}
	raw = appendProtoString(raw, 15, info.LocalMemory)
	raw = appendProtoString(raw, 16, info.CacheSize)
	raw = appendProtoString(raw, 17, info.PCIAddress)
	return raw
}

func appendProtoString(raw []byte, number protowire.Number, value string) []byte {
	if value == "" {
		return raw
	}
	raw = protowire.AppendTag(raw, number, protowire.BytesType)
	return protowire.AppendString(raw, value)
}

func appendProtoInt32(raw []byte, number protowire.Number, value int32) []byte {
	if value == 0 {
		return raw
	}
	raw = protowire.AppendTag(raw, number, protowire.VarintType)
	return protowire.AppendVarint(raw, uint64(int64(value)))
}

func appendProtoUint32(raw []byte, number protowire.Number, value uint32, preserveZero bool) []byte {
	if value == 0 && !preserveZero {
		return raw
	}
	raw = protowire.AppendTag(raw, number, protowire.VarintType)
	return protowire.AppendVarint(raw, uint64(value))
}
