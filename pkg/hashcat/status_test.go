package hashcat

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestParseStatusJSONFullSchema(t *testing.T) {
	raw := []byte(`{
  "session": "crackstation",
  "guess": {"guess_base": "must-not-be-retained", "guess_mod": "also-sensitive"},
  "status": 3,
  "target": "must-not-be-retained",
  "progress": [123456789012, 987654321098],
  "restore_point": 112233445566,
  "recovered_hashes": [3, 7],
  "recovered_salts": [2, 4],
  "rejected": 19,
  "devices": [
    {
      "device_id": 1,
      "device_name": "NVIDIA RTX",
      "device_type": "GPU",
      "speed": 12000000000,
      "temp": 71,
      "util": 99,
      "fanspeed": 64,
      "corespeed": 1845,
      "memoryspeed": 9501,
      "buslanes": 16,
      "power": 245000
    },
    {
      "device_id": 2,
      "device_name": "Host CPU",
      "device_type": "CPU",
      "speed": 420000,
      "temp": 52,
      "util": 80,
      "fanspeed": 0,
      "corespeed": 4100,
      "memoryspeed": -1,
      "buslanes": -1,
      "power": -1,
      "future_device_field": {"ignored": true}
    }
  ],
  "time_start": 1789066800,
  "estimated_stop": 1789067400,
  "future_top_level_field": ["ignored"]
}`)

	got, err := ParseStatusJSON(raw)
	if err != nil {
		t.Fatalf("ParseStatusJSON() error = %v", err)
	}
	want := Status{
		Session:         "crackstation",
		State:           3,
		Progress:        StatusCounter{Current: 123456789012, Total: 987654321098},
		RestorePoint:    112233445566,
		RecoveredHashes: StatusCounter{Current: 3, Total: 7},
		RecoveredSalts:  StatusCounter{Current: 2, Total: 4},
		Rejected:        19,
		Devices: []DeviceStatus{
			{ID: 1, Name: "NVIDIA RTX", Type: "GPU", Speed: 12000000000, Temp: 71, Util: 99, FanSpeed: 64, CoreSpeed: 1845, MemorySpeed: 9501, BusLanes: 16, Power: 245000},
			{ID: 2, Name: "Host CPU", Type: "CPU", Speed: 420000, Temp: 52, Util: 80, FanSpeed: 0, CoreSpeed: 4100, MemorySpeed: -1, BusLanes: -1, Power: -1},
		},
		TimeStart:     1789066800,
		EstimatedStop: 1789067400,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseStatusJSON() = %#v, want %#v", got, want)
	}
	if got.StateName() != "Running" {
		t.Fatalf("StateName() = %q, want Running", got.StateName())
	}
	if got.TotalSpeed() != 12000420000 {
		t.Fatalf("TotalSpeed() = %d, want 12000420000", got.TotalSpeed())
	}

	// Status deliberately has no place to retain sensitive target or guess data.
	typeOfStatus := reflect.TypeOf(got)
	for _, forbidden := range []string{"Target", "Guess", "Raw", "JSON"} {
		for index := 0; index < typeOfStatus.NumField(); index++ {
			if strings.Contains(typeOfStatus.Field(index).Name, forbidden) {
				t.Fatalf("Status unexpectedly retains %q in field %q", forbidden, typeOfStatus.Field(index).Name)
			}
		}
	}
}

func TestParseStatusJSONToleratesMissingFields(t *testing.T) {
	got, err := ParseStatusJSON([]byte(`{"session":"minimal","devices":[{"device_id":1,"speed":99}]}`))
	if err != nil {
		t.Fatalf("ParseStatusJSON() error = %v", err)
	}
	want := Status{
		Session: "minimal",
		Devices: []DeviceStatus{{
			ID:          1,
			Speed:       99,
			Temp:        -1,
			Util:        -1,
			FanSpeed:    -1,
			CoreSpeed:   -1,
			MemorySpeed: -1,
			BusLanes:    -1,
			Power:       -1,
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseStatusJSON() = %#v, want %#v", got, want)
	}

	empty, err := ParseStatusJSON([]byte(`{}`))
	if err != nil {
		t.Fatalf("ParseStatusJSON({}) error = %v", err)
	}
	if !reflect.DeepEqual(empty, Status{}) {
		t.Fatalf("ParseStatusJSON({}) = %#v, want zero Status", empty)
	}
}

func TestParseStatusJSONPreservesNegativeSensors(t *testing.T) {
	got, err := ParseStatusJSON([]byte(`{"devices":[{
    "temp":-1,"util":-2,"fanspeed":-3,"corespeed":-4,
    "memoryspeed":-5,"buslanes":-6,"power":-9223372036854775808
  }]}`))
	if err != nil {
		t.Fatalf("ParseStatusJSON() error = %v", err)
	}
	device := got.Devices[0]
	if device.Temp != -1 || device.Util != -2 || device.FanSpeed != -3 ||
		device.CoreSpeed != -4 || device.MemorySpeed != -5 || device.BusLanes != -6 ||
		device.Power != math.MinInt64 {
		t.Fatalf("negative device telemetry was not preserved: %+v", device)
	}
}

func TestParseStatusJSONRejectsMalformedPairs(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{"empty progress", `{"progress":[]}`},
		{"short progress", `{"progress":[1]}`},
		{"long progress", `{"progress":[1,2,3]}`},
		{"short recovered hashes", `{"recovered_hashes":[1]}`},
		{"long recovered salts", `{"recovered_salts":[1,2,3]}`},
		{"null pair", `{"progress":null}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseStatusJSON([]byte(test.raw)); err == nil {
				t.Fatalf("ParseStatusJSON(%s) accepted a malformed counter", test.raw)
			}
		})
	}
}

func TestParseStatusJSONRejectsMalformedJSONAndKnownFieldTypes(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{"malformed JSON", `{"status":3`},
		{"top-level array", `[]`},
		{"top-level null", `null`},
		{"string status", `{"status":"running"}`},
		{"negative unsigned counter", `{"rejected":-1}`},
		{"fractional counter", `{"progress":[1,2.5]}`},
		{"object devices", `{"devices":{}}`},
		{"null devices", `{"devices":null}`},
		{"null device", `{"devices":[null]}`},
		{"string device", `{"devices":["gpu"]}`},
		{"oversized device id", `{"devices":[{"device_id":4294967296}]}`},
		{"unsigned speed", `{"devices":[{"speed":-1}]}`},
		{"null sensor", `{"devices":[{"temp":null}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseStatusJSON([]byte(test.raw)); err == nil {
				t.Fatalf("ParseStatusJSON(%s) accepted invalid input", test.raw)
			}
		})
	}
}

func TestStatusStateName(t *testing.T) {
	tests := map[int]string{
		0: "Initializing", 1: "Autotuning", 2: "Selftest", 3: "Running",
		4: "Paused", 5: "Exhausted", 6: "Cracked", 7: "Aborted",
		8: "Quit", 9: "Bypass", 10: "Aborted (Checkpoint)",
		11: "Aborted (Runtime)", 13: "Error", 14: "Aborted (Finish)",
		16: "Autodetect",
		12: "Unknown", 15: "Unknown", 17: "Unknown", 18: "Unknown",
		999: "Unknown",
	}
	for state, want := range tests {
		if got := (Status{State: state}).StateName(); got != want {
			t.Errorf("Status{State:%d}.StateName() = %q, want %q", state, got, want)
		}
	}
}

func TestStatusTotalSpeedSaturates(t *testing.T) {
	tests := []struct {
		name    string
		devices []DeviceStatus
		want    uint64
	}{
		{"empty", nil, 0},
		{"ordinary sum", []DeviceStatus{{Speed: 10}, {Speed: 20}, {Speed: 30}}, 60},
		{"exact maximum", []DeviceStatus{{Speed: math.MaxUint64 - 1}, {Speed: 1}}, math.MaxUint64},
		{"overflow", []DeviceStatus{{Speed: math.MaxUint64 - 1}, {Speed: 2}}, math.MaxUint64},
		{"overflow remains saturated", []DeviceStatus{{Speed: math.MaxUint64}, {Speed: 1}, {Speed: 99}}, math.MaxUint64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := (Status{Devices: test.devices}).TotalSpeed(); got != test.want {
				t.Fatalf("TotalSpeed() = %d, want %d", got, test.want)
			}
		})
	}
}
