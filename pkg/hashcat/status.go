package hashcat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// StatusCounter is a current/total counter reported by hashcat.
type StatusCounter struct {
	Current uint64
	Total   uint64
}

// DeviceStatus contains the safe telemetry reported for a hashcat device.
// Negative hardware-monitor values mean that the metric is unavailable.
type DeviceStatus struct {
	ID          uint32
	Name        string
	Type        string
	Speed       uint64
	Temp        int64
	Util        int64
	FanSpeed    int64
	CoreSpeed   int64
	MemorySpeed int64
	BusLanes    int64
	Power       int64
}

// Status contains the non-sensitive portion of a hashcat status-json update.
// In particular, target and guess fields are intentionally not retained.
type Status struct {
	Session         string
	State           int
	Progress        StatusCounter
	RestorePoint    uint64
	RecoveredHashes StatusCounter
	RecoveredSalts  StatusCounter
	Rejected        uint64
	Devices         []DeviceStatus
	TimeStart       uint64
	EstimatedStop   uint64
}

// StateName returns hashcat's display name for the numeric state.
func (s Status) StateName() string {
	switch s.State {
	case 0:
		return "Initializing"
	case 1:
		return "Autotuning"
	case 2:
		return "Selftest"
	case 3:
		return "Running"
	case 4:
		return "Paused"
	case 5:
		return "Exhausted"
	case 6:
		return "Cracked"
	case 7:
		return "Aborted"
	case 8:
		return "Quit"
	case 9:
		return "Bypass"
	case 10:
		return "Aborted (Checkpoint)"
	case 11:
		return "Aborted (Runtime)"
	case 13:
		return "Error"
	case 14:
		return "Aborted (Finish)"
	case 16:
		return "Autodetect"
	default:
		return "Unknown"
	}
}

// TotalSpeed returns the sum of all device speeds in hashes per second. If the
// sum cannot be represented by a uint64, it saturates at the maximum value.
func (s Status) TotalSpeed() uint64 {
	const maxUint64 = ^uint64(0)

	var total uint64
	for _, device := range s.Devices {
		if device.Speed > maxUint64-total {
			return maxUint64
		}
		total += device.Speed
	}
	return total
}

type statusJSONDocument struct {
	Session         json.RawMessage `json:"session"`
	State           json.RawMessage `json:"status"`
	Progress        json.RawMessage `json:"progress"`
	RestorePoint    json.RawMessage `json:"restore_point"`
	RecoveredHashes json.RawMessage `json:"recovered_hashes"`
	RecoveredSalts  json.RawMessage `json:"recovered_salts"`
	Rejected        json.RawMessage `json:"rejected"`
	Devices         json.RawMessage `json:"devices"`
	TimeStart       json.RawMessage `json:"time_start"`
	EstimatedStop   json.RawMessage `json:"estimated_stop"`
}

type deviceStatusJSONDocument struct {
	ID          json.RawMessage `json:"device_id"`
	Name        json.RawMessage `json:"device_name"`
	Type        json.RawMessage `json:"device_type"`
	Speed       json.RawMessage `json:"speed"`
	Temp        json.RawMessage `json:"temp"`
	Util        json.RawMessage `json:"util"`
	FanSpeed    json.RawMessage `json:"fanspeed"`
	CoreSpeed   json.RawMessage `json:"corespeed"`
	MemorySpeed json.RawMessage `json:"memoryspeed"`
	BusLanes    json.RawMessage `json:"buslanes"`
	Power       json.RawMessage `json:"power"`
}

// ParseStatusJSON parses hashcat 7.1.2 status-json output and returns only the
// telemetry that is safe to retain. Fields added by future hashcat versions are
// ignored, while present known fields must have the expected JSON type.
func ParseStatusJSON(raw []byte) (Status, error) {
	var document statusJSONDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return Status{}, fmt.Errorf("decode hashcat status JSON: %w", err)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return Status{}, errors.New("decode hashcat status JSON: expected an object")
	}

	status := Status{}
	if err := decodeOptional(document.Session, "session", &status.Session); err != nil {
		return Status{}, err
	}
	if err := decodeOptional(document.State, "status", &status.State); err != nil {
		return Status{}, err
	}
	if err := decodeCounter(document.Progress, "progress", &status.Progress); err != nil {
		return Status{}, err
	}
	if err := decodeOptional(document.RestorePoint, "restore_point", &status.RestorePoint); err != nil {
		return Status{}, err
	}
	if err := decodeCounter(document.RecoveredHashes, "recovered_hashes", &status.RecoveredHashes); err != nil {
		return Status{}, err
	}
	if err := decodeCounter(document.RecoveredSalts, "recovered_salts", &status.RecoveredSalts); err != nil {
		return Status{}, err
	}
	if err := decodeOptional(document.Rejected, "rejected", &status.Rejected); err != nil {
		return Status{}, err
	}
	if err := decodeDevices(document.Devices, &status.Devices); err != nil {
		return Status{}, err
	}
	if err := decodeOptional(document.TimeStart, "time_start", &status.TimeStart); err != nil {
		return Status{}, err
	}
	if err := decodeOptional(document.EstimatedStop, "estimated_stop", &status.EstimatedStop); err != nil {
		return Status{}, err
	}

	return status, nil
}

func decodeOptional(raw json.RawMessage, field string, destination any) error {
	if len(raw) == 0 {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("decode hashcat status JSON field %q: null is not valid", field)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("decode hashcat status JSON field %q: %w", field, err)
	}
	return nil
}

func decodeCounter(raw json.RawMessage, field string, destination *StatusCounter) error {
	if len(raw) == 0 {
		return nil
	}
	var values []uint64
	if err := decodeOptional(raw, field, &values); err != nil {
		return err
	}
	if len(values) != 2 {
		return fmt.Errorf("decode hashcat status JSON field %q: got %d values, want 2", field, len(values))
	}
	destination.Current = values[0]
	destination.Total = values[1]
	return nil
}

func decodeDevices(raw json.RawMessage, destination *[]DeviceStatus) error {
	if len(raw) == 0 {
		return nil
	}
	var rawDevices []json.RawMessage
	if err := decodeOptional(raw, "devices", &rawDevices); err != nil {
		return err
	}

	devices := make([]DeviceStatus, 0, len(rawDevices))
	for index, rawDevice := range rawDevices {
		if bytes.Equal(bytes.TrimSpace(rawDevice), []byte("null")) {
			return fmt.Errorf("decode hashcat status JSON device %d: expected an object", index+1)
		}
		var document deviceStatusJSONDocument
		if err := json.Unmarshal(rawDevice, &document); err != nil {
			return fmt.Errorf("decode hashcat status JSON device %d: %w", index+1, err)
		}

		device := DeviceStatus{
			Temp:        -1,
			Util:        -1,
			FanSpeed:    -1,
			CoreSpeed:   -1,
			MemorySpeed: -1,
			BusLanes:    -1,
			Power:       -1,
		}
		fields := []struct {
			raw         json.RawMessage
			name        string
			destination any
		}{
			{document.ID, "device_id", &device.ID},
			{document.Name, "device_name", &device.Name},
			{document.Type, "device_type", &device.Type},
			{document.Speed, "speed", &device.Speed},
			{document.Temp, "temp", &device.Temp},
			{document.Util, "util", &device.Util},
			{document.FanSpeed, "fanspeed", &device.FanSpeed},
			{document.CoreSpeed, "corespeed", &device.CoreSpeed},
			{document.MemorySpeed, "memoryspeed", &device.MemorySpeed},
			{document.BusLanes, "buslanes", &device.BusLanes},
			{document.Power, "power", &device.Power},
		}
		for _, field := range fields {
			if err := decodeOptional(field.raw, field.name, field.destination); err != nil {
				return fmt.Errorf("decode hashcat status JSON device %d: %w", index+1, err)
			}
		}
		devices = append(devices, device)
	}
	*destination = devices
	return nil
}
