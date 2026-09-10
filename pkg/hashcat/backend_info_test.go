package hashcat

import (
	"testing"

	"github.com/sliverarmory/sliver-crackstation/pkg/protocompat"
	"google.golang.org/protobuf/encoding/protowire"
)

const allBackendFixture = `{
  "CUDAInfo": {"Version":"13.0","BackendDevices":[{
    "DeviceID":"01","Alias":"00","Name":"CUDA GPU","Processors":"80",
    "PreferredThreadSize":"00","Clock":"2200","MemoryTotal":"24000 MB",
    "MemoryFree":"23000 MB","MemoryUnified":"0","LocalMemory":"48 MB",
    "PCIAddrBDFe":"0000:01:00.0"
  }]},
  "HIPInfo": {"Version":"7.0.51831","BackendDevices":[{
    "DeviceID":"02","Type":"GPU","VendorID":"4098","Vendor":"AMD",
    "Name":"HIP GPU","Processors":"60","PreferredThreadSize":"64",
    "Clock":"1900","MemoryTotal":"16000 MB","MemoryFree":"15000 MB",
    "MemoryUnified":"1","LocalMemory":"64 MB","PCIAddrBDFe":"0000:02:00.0"
  }]},
  "MetalInfo": {"Version":"373.7","BackendDevices":[{
    "DeviceID":"03","Alias":"04","Type":"GPU","VendorID":"2","Vendor":"Apple",
    "Name":"Apple M5 Max","Processors":"40","PreferredThreadSize":"32",
    "Clock":"N/A","MemoryTotal":"53084 MB","MemoryAllocPerBlock":"19906 MB",
    "MemoryFree":"53020 MB","MemoryUnified":"1","LocalMemory":"32 MB",
    "PhysicalLocation":"built-in","RegistryID":"0","MaxTXRate":"N/A",
    "GPUProperties":{"headless":"0","low_power":"0","removable":"0"}
  }]},
  "OpenCLInfo": {"Platforms":[{
    "PlatformID":"1","Vendor":"Apple","Name":"Apple",
    "Version":"OpenCL 1.2 platform","BackendDevices":[{
      "DeviceID":"04","Alias":"03","Type":"GPU","VendorID":"2","Vendor":"Apple",
      "Name":"OpenCL GPU","Version":"OpenCL 1.2 device","Processors":"40",
      "PreferredThreadSize":"32","Clock":"1000","MemoryTotal":"53084 MB",
      "MemoryAllocPerBlock":"4976 MB","MemoryFree":"53020 MB","MemoryUnified":"1",
      "LocalMemory":"32 MB","OpenCLVersion":"OpenCL C 1.2","DriverVersion":"1.2 1.0",
      "PCI.Addr.BDF":"0000:03:00"
    }]
  }]}
}`

const backendCacheFixture = `CUDA Info:
Backend Device ID #01 (Alias: #02)
  Cache.Size.....: 96 MB

HIP Info:
Backend Device ID #02
  Cache.Size.....: 128 MB

Metal Info:
Backend Device ID #03 (Alias: #04)
  Cache.Size.....: 0 MB

OpenCL Info:
Backend Device ID #04 (Alias: #03)
  Cache.Size.....: ignored
`

func TestParseMachineReadableBackendInfo(t *testing.T) {
	cuda, hip, metal, openCL, err := parseMachineReadableBackendInfo([]byte(allBackendFixture))
	if err != nil {
		t.Fatalf("parseMachineReadableBackendInfo() error = %v", err)
	}
	if len(cuda) != 1 || len(hip) != 1 || len(metal) != 1 || len(openCL) != 1 {
		t.Fatalf("backend counts = CUDA %d, HIP %d, Metal %d, OpenCL %d", len(cuda), len(hip), len(metal), len(openCL))
	}

	if cuda[0].GetName() != "CUDA GPU" || cuda[0].GetCUDAVersion() != "13.0" || cuda[0].GetVersion() != "13.0" {
		t.Fatalf("unexpected CUDA device: %+v", cuda[0])
	}
	cudaFields, err := protocompat.NewReader(cuda[0])
	if err != nil {
		t.Fatal(err)
	}
	assertCompatUint32(t, cudaFields, 11, 1)
	assertCompatUint32(t, cudaFields, 12, 0)
	assertCompatUint32(t, cudaFields, 13, 0)
	assertCompatBool(t, cudaFields, 14, false)
	if localMemory, err := cudaFields.String(15); err != nil || localMemory != "48 KB" {
		t.Fatalf("CUDA local memory = %q, %v", localMemory, err)
	}

	if hip[0].Name != "HIP GPU" || hip[0].HIPVersion != "7.0.51831" || hip[0].Version != "7.0.51831" || hip[0].BackendDeviceID != 2 {
		t.Fatalf("unexpected HIP device: %+v", hip[0])
	}

	if metal[0].GetName() != "Apple M5 Max" || metal[0].GetMetalVersion() != "373.7" || metal[0].GetVersion() != "373.7" || metal[0].GetClock() != -1 {
		t.Fatalf("unexpected Metal device: %+v", metal[0])
	}
	metalFields, err := protocompat.NewReader(metal[0])
	if err != nil {
		t.Fatal(err)
	}
	assertCompatUint32(t, metalFields, 19, 0)
	assertCompatBool(t, metalFields, 21, false)
	assertCompatBool(t, metalFields, 22, false)
	assertCompatBool(t, metalFields, 23, false)

	if openCL[0].GetVersion() != "OpenCL 1.2 device" ||
		openCL[0].GetOpenCLVersion() != "OpenCL C 1.2" ||
		openCL[0].GetOpenCLDriverVersion() != "1.2 1.0" {
		t.Fatalf("unexpected OpenCL versions: %+v", openCL[0])
	}
	openCLFields, err := protocompat.NewReader(openCL[0])
	if err != nil {
		t.Fatal(err)
	}
	assertCompatUint32(t, openCLFields, 12, 4)
	assertCompatUint32(t, openCLFields, 19, 1)
	if address, err := openCLFields.String(18); err != nil || address != "0000:03:00" {
		t.Fatalf("OpenCL PCI address = %q, %v", address, err)
	}
	if platform, err := openCLFields.String(22); err != nil || platform != "OpenCL 1.2 platform" {
		t.Fatalf("OpenCL platform version = %q, %v", platform, err)
	}

	hashcat := &Hashcat{
		CUDABackend:   cuda,
		HIPBackend:    hip,
		MetalBackend:  metal,
		OpenCLBackend: openCL,
	}
	if err := hashcat.applyBackendCacheSizes([]byte(backendCacheFixture)); err != nil {
		t.Fatalf("applyBackendCacheSizes() error = %v", err)
	}
	cudaCacheFields, err := protocompat.NewReader(cuda[0])
	if err != nil {
		t.Fatal(err)
	}
	if cache, err := cudaCacheFields.String(16); err != nil || cache != "96 MB" {
		t.Fatalf("CUDA cache size = %q, %v", cache, err)
	}
	if hip[0].CacheSize != "128 MB" {
		t.Fatalf("HIP cache size = %q", hip[0].CacheSize)
	}
	metalCacheFields, err := protocompat.NewReader(metal[0])
	if err != nil {
		t.Fatal(err)
	}
	if cache, err := metalCacheFields.String(16); err != nil || cache != "0 MB" {
		t.Fatalf("Metal cache size = %q, %v", cache, err)
	}
	hipWire := hashcat.HIPBackendWire()
	if len(hipWire) != 1 {
		t.Fatalf("HIP wire count = %d, want 1", len(hipWire))
	}
	if got := wireStringField(t, hipWire[0], 10); got != "7.0.51831" {
		t.Fatalf("HIP wire version = %q", got)
	}
	if got := wireVarintField(t, hipWire[0], 11); got != 2 {
		t.Fatalf("HIP wire device ID = %d", got)
	}
}

func TestParseMachineReadableBackendInfoRejectsMalformedNumbers(t *testing.T) {
	fixture := `{"MetalInfo":{"Version":"1","BackendDevices":[{"DeviceID":"not-a-number"}]}}`
	if _, _, _, _, err := parseMachineReadableBackendInfo([]byte(fixture)); err == nil {
		t.Fatal("parseMachineReadableBackendInfo() accepted a malformed device ID")
	}
}

func assertCompatUint32(t *testing.T, reader *protocompat.Reader, number protowire.Number, want uint32) {
	t.Helper()
	if !reader.HasVarint(number) {
		t.Fatalf("field %d is not present", number)
	}
	got, err := reader.Uint32(number)
	if err != nil || got != want {
		t.Fatalf("field %d = %d, %v; want %d", number, got, err, want)
	}
}

func assertCompatBool(t *testing.T, reader *protocompat.Reader, number protowire.Number, want bool) {
	t.Helper()
	if !reader.HasVarint(number) {
		t.Fatalf("field %d is not present", number)
	}
	got, err := reader.Bool(number)
	if err != nil || got != want {
		t.Fatalf("field %d = %t, %v; want %t", number, got, err, want)
	}
}

func wireStringField(t *testing.T, raw []byte, target protowire.Number) string {
	t.Helper()
	for len(raw) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(raw)
		if tagLen < 0 {
			t.Fatal(protowire.ParseError(tagLen))
		}
		raw = raw[tagLen:]
		if number == target && typ == protowire.BytesType {
			value, valueLen := protowire.ConsumeString(raw)
			if valueLen < 0 {
				t.Fatal(protowire.ParseError(valueLen))
			}
			return value
		}
		valueLen := protowire.ConsumeFieldValue(number, typ, raw)
		if valueLen < 0 {
			t.Fatal(protowire.ParseError(valueLen))
		}
		raw = raw[valueLen:]
	}
	t.Fatalf("wire field %d not found", target)
	return ""
}

func wireVarintField(t *testing.T, raw []byte, target protowire.Number) uint64 {
	t.Helper()
	for len(raw) > 0 {
		number, typ, tagLen := protowire.ConsumeTag(raw)
		if tagLen < 0 {
			t.Fatal(protowire.ParseError(tagLen))
		}
		raw = raw[tagLen:]
		if number == target && typ == protowire.VarintType {
			value, valueLen := protowire.ConsumeVarint(raw)
			if valueLen < 0 {
				t.Fatal(protowire.ParseError(valueLen))
			}
			return value
		}
		valueLen := protowire.ConsumeFieldValue(number, typ, raw)
		if valueLen < 0 {
			t.Fatal(protowire.ParseError(valueLen))
		}
		raw = raw[valueLen:]
	}
	t.Fatalf("wire field %d not found", target)
	return 0
}
