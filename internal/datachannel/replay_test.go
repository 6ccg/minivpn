package datachannel

import (
	"testing"

	"github.com/ooni/minivpn/internal/model"
)

func TestReplayFilter_Sequential(t *testing.T) {
	rf := newReplayFilter(64, false) // sequential mode

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
		{"skip to 10", 10, false},
		{"replay of 10", 10, true},
		{"out of order 5", 5, true}, // sequential mode rejects
		{"continue with 11", 11, false},
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
