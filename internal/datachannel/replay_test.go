package datachannel

import (
	"testing"

	"github.com/6ccg/minivpn/internal/model"
)

func TestReplayFilter_Sequential(t *testing.T) {
	rf := newReplayFilter(64, false) // sequential mode

	// In strict sequential mode (TCP), packets must be strictly +1
	// For data channel without timestamp, all packets are in the same "time period" (timestamp=0)

	tests := []struct {
		name    string
		id      model.PacketID
		wantErr bool
	}{
		{"first packet", 1, false},
		{"second packet", 2, false},
		{"third packet", 3, false},
		{"replay of 2", 2, true},
		{"replay of 1", 1, true},
		{"fourth packet", 4, false},
		{"skip to 10 (gap not allowed)", 10, true}, // strict mode rejects gaps
		{"fifth packet", 5, false},
		{"replay of 5", 5, true},
		{"out of order 4", 4, true}, // sequential mode rejects
		{"continue with 6", 6, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rf.Check(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check(%d) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestReplayFilter_Backtrack(t *testing.T) {
	rf := newReplayFilter(64, true) // backtrack mode

	tests := []struct {
		name    string
		id      model.PacketID
		wantErr bool
	}{
		{"first packet", 1, false},
		{"second packet", 2, false},
		{"third packet", 3, false},
		{"out of order 5", 5, false},
		{"fill gap 4", 4, false},      // backtrack mode allows
		{"replay of 4", 4, true},      // but not duplicates
		{"skip to 10", 10, false},
		{"backtrack to 8", 8, false},  // within window
		{"backtrack to 6", 6, false},  // within window
		{"replay of 8", 8, true},      // duplicate
		{"continue 11", 11, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rf.Check(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("Check(%d) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestReplayFilter_WindowBoundary(t *testing.T) {
	rf := newReplayFilter(8, true) // small window for testing

	// Receive packets 1-10
	for i := model.PacketID(1); i <= 10; i++ {
		if err := rf.Check(i); err != nil {
			t.Errorf("Check(%d) unexpected error: %v", i, err)
		}
	}

	// maxID is now 10, window covers 3-10

	// Packet 3 should be within window (10 - 8 + 1 = 3)
	if err := rf.Check(3); err == nil {
		t.Error("Check(3) should fail - already seen")
	}

	// Packet 2 should be outside window
	if err := rf.Check(2); err == nil {
		t.Error("Check(2) should fail - outside window")
	}

	// Advance to 20
	if err := rf.Check(20); err != nil {
		t.Errorf("Check(20) unexpected error: %v", err)
	}

	// Now window covers 13-20, packet 10 is outside
	if err := rf.Check(10); err == nil {
		t.Error("Check(10) should fail - outside window after advance")
	}

	// Packet 15 should be within window and unseen
	if err := rf.Check(15); err != nil {
		t.Errorf("Check(15) unexpected error: %v", err)
	}

	// Replay of 15 should fail
	if err := rf.Check(15); err == nil {
		t.Error("Check(15) should fail - duplicate")
	}
}

func TestReplayFilter_PacketIDZero(t *testing.T) {
	rf := newReplayFilter(64, true)

	// Packet ID 0 should be rejected
	if err := rf.Check(0); err == nil {
		t.Error("Check(0) should fail - packet ID 0 is invalid")
	}

	// First valid packet
	if err := rf.Check(1); err != nil {
		t.Errorf("Check(1) unexpected error: %v", err)
	}
}

func TestReplayFilter_LargeJump(t *testing.T) {
	rf := newReplayFilter(64, true)

	if err := rf.Check(1); err != nil {
		t.Errorf("Check(1) unexpected error: %v", err)
	}

	// Jump far ahead - should reset window
	if err := rf.Check(1000); err != nil {
		t.Errorf("Check(1000) unexpected error: %v", err)
	}

	// Old packet 1 is now way outside window
	if err := rf.Check(1); err == nil {
		t.Error("Check(1) should fail - far outside window")
	}

	// Packet within new window should work
	if err := rf.Check(990); err != nil {
		t.Errorf("Check(990) unexpected error: %v", err)
	}
}

func TestReplayFilter_Reset(t *testing.T) {
	rf := newReplayFilter(64, true)

	rf.Check(1)
	rf.Check(2)
	rf.Check(3)

	rf.Reset()

	// After reset, packet 1 should be accepted again
	if err := rf.Check(1); err != nil {
		t.Errorf("Check(1) after reset unexpected error: %v", err)
	}
}

// TestReplayFilter_Wraparound tests 32-bit packet ID wraparound handling
// using the half-space technique (0x80000000).
func TestReplayFilter_Wraparound(t *testing.T) {
	rf := newReplayFilter(64, true) // backtrack mode

	// Start near the wraparound point
	startID := model.PacketID(0xFFFFFFF0)

	// Accept first packet
	if err := rf.Check(startID); err != nil {
		t.Errorf("Check(startID=%d) unexpected error: %v", startID, err)
	}

	// Accept packets up to max uint32
	for id := startID + 1; id != 0; id++ {
		if err := rf.Check(id); err != nil {
			t.Errorf("Check(%d) unexpected error: %v", id, err)
		}
	}

	// Now at 0xFFFFFFFF, next packet wraps to small numbers
	// Packet ID 1 should be accepted (it's "after" 0xFFFFFFFF using half-space)
	if err := rf.Check(1); err != nil {
		t.Errorf("Check(1) after wraparound unexpected error: %v", err)
	}

	// ID 2 should also be accepted
	if err := rf.Check(2); err != nil {
		t.Errorf("Check(2) after wraparound unexpected error: %v", err)
	}

	// Old ID (0xFFFFFFF5) should be rejected (it's behind in half-space)
	if err := rf.Check(0xFFFFFFF5); err == nil {
		t.Error("Check(0xFFFFFFF5) should fail - old ID after wraparound")
	}
}

// TestReplayFilter_BacktrackWithTimestamp tests UDP mode with timestamp transitions.
// This matches OpenVPN's packet_id_test() behavior in backtrack mode:
// - time goes back: reject immediately
// - time goes forward: accept immediately and reset window
// - same time period: check sliding window
func TestReplayFilter_BacktrackWithTimestamp(t *testing.T) {
	rf := newReplayFilter(64, true) // backtrack mode

	ts1 := model.PacketTimestamp(1000)
	ts2 := model.PacketTimestamp(1001)
	ts0 := model.PacketTimestamp(999) // earlier timestamp

	// First packet in time period 1
	if err := rf.CheckWithTimestamp(5, ts1); err != nil {
		t.Errorf("CheckWithTimestamp(5, ts1) unexpected error: %v", err)
	}

	// More packets in same time period (out of order allowed)
	if err := rf.CheckWithTimestamp(3, ts1); err != nil {
		t.Errorf("CheckWithTimestamp(3, ts1) unexpected error: %v", err)
	}
	if err := rf.CheckWithTimestamp(7, ts1); err != nil {
		t.Errorf("CheckWithTimestamp(7, ts1) unexpected error: %v", err)
	}

	// Duplicate should be rejected
	if err := rf.CheckWithTimestamp(5, ts1); err == nil {
		t.Error("CheckWithTimestamp(5, ts1) should fail - duplicate")
	}

	// Time backtrack should be rejected immediately (key fix verification)
	if err := rf.CheckWithTimestamp(10, ts0); err == nil {
		t.Error("CheckWithTimestamp(10, ts0) should fail - time backtrack rejected")
	}

	// Even new ID with old timestamp should be rejected
	if err := rf.CheckWithTimestamp(100, ts0); err == nil {
		t.Error("CheckWithTimestamp(100, ts0) should fail - time backtrack rejected")
	}

	// Time forward should be accepted immediately and reset window
	if err := rf.CheckWithTimestamp(1, ts2); err != nil {
		t.Errorf("CheckWithTimestamp(1, ts2) unexpected error: %v", err)
	}

	// Old IDs from previous time period should now be outside window
	// (window was reset when time moved forward)
	if err := rf.CheckWithTimestamp(3, ts2); err != nil {
		t.Errorf("CheckWithTimestamp(3, ts2) unexpected error: %v", err)
	}

	// Time backtrack to ts1 should still be rejected
	if err := rf.CheckWithTimestamp(8, ts1); err == nil {
		t.Error("CheckWithTimestamp(8, ts1) should fail - time backtrack to old period")
	}
}

// TestReplayFilter_BacktrackTimePeriodReset verifies window reset on time period change.
func TestReplayFilter_BacktrackTimePeriodReset(t *testing.T) {
	rf := newReplayFilter(8, true) // small window

	ts1 := model.PacketTimestamp(1000)
	ts2 := model.PacketTimestamp(1001)

	// Fill up window in time period 1
	for i := model.PacketID(1); i <= 10; i++ {
		if err := rf.CheckWithTimestamp(i, ts1); err != nil {
			t.Errorf("CheckWithTimestamp(%d, ts1) unexpected error: %v", i, err)
		}
	}

	// Packet 2 is now outside window (maxID=10, window=8, so 3-10 are in window)
	if err := rf.CheckWithTimestamp(2, ts1); err == nil {
		t.Error("CheckWithTimestamp(2, ts1) should fail - outside window")
	}

	// Move to new time period - window should reset
	if err := rf.CheckWithTimestamp(50, ts2); err != nil {
		t.Errorf("CheckWithTimestamp(50, ts2) unexpected error: %v", err)
	}

	// In new time period, packet 45 should be within window (50-8+1=43 to 50)
	if err := rf.CheckWithTimestamp(45, ts2); err != nil {
		t.Errorf("CheckWithTimestamp(45, ts2) unexpected error: %v", err)
	}

	// Packet from old time period should be rejected
	if err := rf.CheckWithTimestamp(5, ts1); err == nil {
		t.Error("CheckWithTimestamp(5, ts1) should fail - old time period")
	}
}

// TestReplayFilter_SequentialWithTimestamp tests TCP mode with timestamp transitions.
func TestReplayFilter_SequentialWithTimestamp(t *testing.T) {
	rf := newReplayFilter(64, false) // sequential mode

	ts1 := model.PacketTimestamp(1000)
	ts2 := model.PacketTimestamp(1001)

	// First time period
	if err := rf.CheckWithTimestamp(1, ts1); err != nil {
		t.Errorf("CheckWithTimestamp(1, ts1) unexpected error: %v", err)
	}
	if err := rf.CheckWithTimestamp(2, ts1); err != nil {
		t.Errorf("CheckWithTimestamp(2, ts1) unexpected error: %v", err)
	}

	// Gap should be rejected
	if err := rf.CheckWithTimestamp(5, ts1); err == nil {
		t.Error("CheckWithTimestamp(5, ts1) should fail - gap in sequential mode")
	}

	// Continue with 3
	if err := rf.CheckWithTimestamp(3, ts1); err != nil {
		t.Errorf("CheckWithTimestamp(3, ts1) unexpected error: %v", err)
	}

	// New time period must start with ID 1
	if err := rf.CheckWithTimestamp(10, ts2); err == nil {
		t.Error("CheckWithTimestamp(10, ts2) should fail - new period must start with 1")
	}

	if err := rf.CheckWithTimestamp(1, ts2); err != nil {
		t.Errorf("CheckWithTimestamp(1, ts2) unexpected error: %v", err)
	}

	// Time backtrack should be rejected
	if err := rf.CheckWithTimestamp(4, ts1); err == nil {
		t.Error("CheckWithTimestamp(4, ts1) should fail - time backtrack")
	}
}
