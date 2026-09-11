package crackstation

import (
	"sync"
	"testing"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/hashcat"
)

const fullHashcatStatusJSON = `{
	"session":"crack-task-42",
	"status":3,
	"progress":[250,1000],
	"restore_point":240,
	"recovered_hashes":[1,4],
	"recovered_salts":[1,2],
	"rejected":7,
	"devices":[
		{
			"device_id":1,
			"device_name":"GPU 1",
			"device_type":"GPU",
			"speed":1250000,
			"temp":72,
			"util":98,
			"fanspeed":61,
			"corespeed":2100,
			"memoryspeed":9500,
			"buslanes":16,
			"power":185000
		},
		{
			"device_id":2,
			"device_name":"GPU 2",
			"device_type":"GPU",
			"speed":750000,
			"temp":64,
			"util":91,
			"fanspeed":54,
			"corespeed":1950,
			"memoryspeed":9000,
			"buslanes":8,
			"power":142000
		}
	],
	"time_start":1789066800,
	"estimated_stop":1789066860,
	"target":"must-not-be-retained",
	"guess":{"guess_base":"must-not-be-retained"}
}`

func TestActivityCrackingLifecycleAndSnapshotIsolation(t *testing.T) {
	station := &Crackstation{}
	startedAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	station.beginActivity(ActivitySnapshot{
		Kind:        ActivityCracking,
		Phase:       ActivityPhaseCracking,
		JobID:       "job-42",
		StartedAt:   startedAt,
		Attempt:     2,
		HashMode:    1000,
		HasHashMode: true,
		AttackMode:  clientpb.CrackAttackMode_BRUTEFORCE,
		HashCount:   4,
		ShardSkip:   5000,
		ShardLimit:  10000,
	})
	station.observeHashcatStatus([]byte(fullHashcatStatusJSON))

	activity := station.Activity()
	if activity == nil {
		t.Fatal("Activity() = nil while cracking")
	}
	if activity.Kind != ActivityCracking || activity.Phase != ActivityPhaseCracking || activity.JobID != "job-42" || activity.StartedAt != startedAt {
		t.Fatalf("activity identity = %#v", activity)
	}
	if activity.Attempt != 2 || activity.HashMode != 1000 || !activity.HasHashMode || activity.AttackMode != clientpb.CrackAttackMode_BRUTEFORCE {
		t.Fatalf("activity command metadata = %#v", activity)
	}
	if activity.HashCount != 4 || activity.ShardSkip != 5000 || activity.ShardLimit != 10000 {
		t.Fatalf("activity workload metadata = %#v", activity)
	}
	if activity.UpdatedAt.IsZero() || activity.UpdatedAt.Before(activity.StartedAt) {
		t.Fatalf("activity UpdatedAt = %v, StartedAt = %v", activity.UpdatedAt, activity.StartedAt)
	}

	status := activity.HashcatStatus
	if status == nil {
		t.Fatal("Activity().HashcatStatus = nil after a valid status update")
	}
	if status.Session != "crack-task-42" || status.StateName() != "Running" {
		t.Fatalf("hashcat status identity = %#v", status)
	}
	if status.Progress != (hashcat.StatusCounter{Current: 250, Total: 1000}) || status.TotalSpeed() != 2000000 {
		t.Fatalf("hashcat progress/speed = %#v / %d", status.Progress, status.TotalSpeed())
	}
	if len(status.Devices) != 2 || status.Devices[0].Temp != 72 || status.Devices[1].Temp != 64 {
		t.Fatalf("hashcat device temperatures = %#v", status.Devices)
	}
	if status.RestorePoint != 240 || status.RecoveredHashes != (hashcat.StatusCounter{Current: 1, Total: 4}) ||
		status.RecoveredSalts != (hashcat.StatusCounter{Current: 1, Total: 2}) || status.Rejected != 7 {
		t.Fatalf("hashcat counters = %#v", status)
	}

	activity.HashcatStatus.Progress.Current = 999
	activity.HashcatStatus.Devices[0].Speed = 1
	activity.HashcatStatus.Devices = append(activity.HashcatStatus.Devices, hashcat.DeviceStatus{ID: 3})
	activity.JobID = "caller-mutated"

	independent := station.Activity()
	if independent.JobID != "job-42" || independent.HashcatStatus.Progress.Current != 250 {
		t.Fatalf("caller mutation leaked into activity snapshot: %#v", independent)
	}
	if len(independent.HashcatStatus.Devices) != 2 || independent.HashcatStatus.Devices[0].Speed != 1250000 {
		t.Fatalf("caller device mutation leaked into activity snapshot: %#v", independent.HashcatStatus.Devices)
	}

	activeStatus := station.Status()
	if activeStatus.GetState() != clientpb.States_CRACKING || activeStatus.GetCurrentCrackJobID() != "job-42" {
		t.Fatalf("Status() while cracking = %#v", activeStatus)
	}

	station.endActivity()
	if activity := station.Activity(); activity != nil {
		t.Fatalf("Activity() after endActivity() = %#v, want nil", activity)
	}
	idleStatus := station.Status()
	if idleStatus.GetState() != clientpb.States_IDLE || idleStatus.GetCurrentCrackJobID() != "" {
		t.Fatalf("Status() after endActivity() = %#v", idleStatus)
	}
}

func TestActivityBenchmarkProgressAndAttemptAreIsolated(t *testing.T) {
	station := &Crackstation{}
	station.beginActivity(ActivitySnapshot{
		Kind:  ActivityBenchmarking,
		JobID: "benchmark",
	})
	station.setActivityAttempt(3)
	station.setActivityPhase(ActivityPhaseBenchmarking)

	progress := hashcat.BenchmarkProgress{
		HashMode:       1000,
		HashName:       "NTLM",
		TotalModes:     8,
		CompletedModes: 3,
		Speed:          300,
		DeviceSpeeds: []hashcat.BenchmarkDeviceSpeed{
			{Device: 1, Speed: 100},
			{Device: 2, Speed: 200},
		},
		LastHashMode: 0,
		LastHashName: "MD5",
		LastSpeed:    275,
		LastDeviceSpeeds: []hashcat.BenchmarkDeviceSpeed{
			{Device: 1, Speed: 125},
			{Device: 2, Speed: 150},
		},
	}
	station.observeBenchmarkProgress(progress)

	// The observer must not retain the caller's backing arrays.
	progress.DeviceSpeeds[0].Speed = 900
	progress.LastDeviceSpeeds[0].Speed = 901

	activity := station.Activity()
	if activity == nil || activity.BenchmarkProgress == nil {
		t.Fatalf("benchmark activity = %#v", activity)
	}
	if activity.Attempt != 3 || activity.Phase != ActivityPhaseBenchmarking {
		t.Fatalf("benchmark attempt/phase = %d/%v, want 3/%v", activity.Attempt, activity.Phase, ActivityPhaseBenchmarking)
	}
	if activity.BenchmarkProgress.Speed != 300 || activity.BenchmarkProgress.DeviceSpeeds[0].Speed != 100 {
		t.Fatalf("benchmark progress = %#v", activity.BenchmarkProgress)
	}
	if activity.BenchmarkProgress.LastSpeed != 275 || activity.BenchmarkProgress.LastDeviceSpeeds[0].Speed != 125 {
		t.Fatalf("last benchmark progress = %#v", activity.BenchmarkProgress)
	}

	// Activity must also return fresh arrays to every caller.
	activity.BenchmarkProgress.DeviceSpeeds[1].Speed = 902
	activity.BenchmarkProgress.LastDeviceSpeeds[1].Speed = 903
	independent := station.Activity()
	if independent.BenchmarkProgress.DeviceSpeeds[1].Speed != 200 || independent.BenchmarkProgress.LastDeviceSpeeds[1].Speed != 150 {
		t.Fatalf("returned benchmark slice mutation leaked into stored activity: %#v", independent.BenchmarkProgress)
	}
}

func TestActivityMalformedHashcatStatusKeepsLastValidUpdate(t *testing.T) {
	station := &Crackstation{}
	station.beginActivity(ActivitySnapshot{Kind: ActivityCracking, JobID: "job-valid-status"})
	station.observeHashcatStatus([]byte(fullHashcatStatusJSON))

	valid := station.Activity()
	if valid == nil || valid.HashcatStatus == nil {
		t.Fatal("valid hashcat status was not observed")
	}
	station.observeHashcatStatus([]byte(`{"status":"running","progress":[999,1000]}`))

	afterMalformed := station.Activity()
	if afterMalformed == nil || afterMalformed.HashcatStatus == nil {
		t.Fatal("malformed update cleared the last valid hashcat status")
	}
	if afterMalformed.UpdatedAt != valid.UpdatedAt || afterMalformed.HashcatStatus.Progress != valid.HashcatStatus.Progress ||
		afterMalformed.HashcatStatus.TotalSpeed() != valid.HashcatStatus.TotalSpeed() {
		t.Fatalf("malformed update replaced the last valid status: before=%#v after=%#v", valid, afterMalformed)
	}
}

func TestActivityConcurrentObserveAndRead(t *testing.T) {
	station := &Crackstation{}
	station.beginActivity(ActivitySnapshot{Kind: ActivityCracking, JobID: "job-race"})
	station.observeHashcatStatus([]byte(fullHashcatStatusJSON))

	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for range 250 {
			station.observeHashcatStatus([]byte(fullHashcatStatusJSON))
		}
	}()
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 250 {
				activity := station.Activity()
				if activity != nil && activity.HashcatStatus != nil && len(activity.HashcatStatus.Devices) != 0 {
					// Mutating a returned slice while another update is observed should
					// remain local to this caller (and is useful coverage under -race).
					activity.HashcatStatus.Devices[0].Speed = 0
				}
				_ = station.Status()
			}
		}()
	}
	close(start)
	workers.Wait()

	activity := station.Activity()
	if activity == nil || activity.HashcatStatus == nil || len(activity.HashcatStatus.Devices) != 2 {
		t.Fatalf("activity after concurrent observation = %#v", activity)
	}
	if activity.HashcatStatus.Devices[0].Speed != 1250000 {
		t.Fatalf("concurrent caller mutation leaked into stored status: %#v", activity.HashcatStatus.Devices)
	}
}

func TestRunCrackTaskPublishesLocalActivityTelemetry(t *testing.T) {
	t.Setenv("SLIVER_CRACKSTATION_ROOT_DIR", t.TempDir())
	h := newScriptHashcat(t, `
printf '%s\n' '{"session":"integration","status":3,"progress":[25,100],"recovered_hashes":[0,1],"recovered_salts":[0,1],"rejected":2,"devices":[{"device_id":1,"device_name":"Test GPU","device_type":"GPU","speed":5000000,"temp":70,"util":95,"fanspeed":50,"corespeed":2000,"memoryspeed":8000,"buslanes":16,"power":150000}]}'
sleep 0.75
`)
	task, _ := leasedTask(t, &clientpb.CrackCommand{
		AttackMode: clientpb.CrackAttackMode_BRUTEFORCE,
		HashType:   clientpb.HashType_NTLM,
		Hashes:     []string{"8846f7eaee8fb117ad06bdd830b7586c"},
		Identify:   "?d?d",
	}, crackTaskKindCrack, 10, 100)
	capture := &taskCapture{}
	station, err := NewCrackstation("worker", t.TempDir(), h)
	if err != nil {
		t.Fatal(err)
	}
	server := taskServer(t, task, capture)
	assignment := assignmentData(t, task)

	done := make(chan struct{})
	go func() {
		station.runCrackTask(server, assignment)
		close(done)
	}()

	deadline := time.After(3 * time.Second)
	for {
		activity := station.Activity()
		if activity != nil && activity.HashcatStatus != nil {
			if activity.Kind != ActivityCracking || activity.Phase != ActivityPhaseCracking || activity.HashMode != 1000 || activity.HashcatStatus.TotalSpeed() != 5_000_000 {
				t.Fatalf("live activity = %#v", activity)
			}
			if len(activity.HashcatStatus.Devices) != 1 || activity.HashcatStatus.Devices[0].Temp != 70 {
				t.Fatalf("live device telemetry = %#v", activity.HashcatStatus.Devices)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for live crack activity")
		case <-time.After(10 * time.Millisecond):
		}
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("crack task did not finish")
	}
	if activity := station.Activity(); activity != nil {
		t.Fatalf("Activity() after crack completion = %#v, want nil", activity)
	}
}
