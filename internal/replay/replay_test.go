package replay

import (
	"testing"
	"time"

	"github.com/6ccg/minivpn/internal/model"
)

func TestFilter_Check_RejectsZeroID(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack)
	err := f.Check(0)
	if err != ErrInvalidPacketID {
		t.Errorf("expected ErrInvalidPacketID, got %v", err)
	}
}

func TestFilter_Check_AcceptsFirstPacket(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack)
	err := f.Check(1)
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if f.MaxID() != 1 {
		t.Errorf("expected maxID=1, got %d", f.MaxID())
	}
}

func TestFilter_Check_AcceptsIncreasingIDs(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack)

	for i := model.PacketID(1); i <= 10; i++ {
		if err := f.Check(i); err != nil {
			t.Errorf("expected nil for ID %d, got %v", i, err)
		}
	}

	if f.MaxID() != 10 {
		t.Errorf("expected maxID=10, got %d", f.MaxID())
	}
}

func TestFilter_Check_RejectsDuplicate(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack)

	// First packet
	if err := f.Check(5); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Duplicate
	if err := f.Check(5); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for duplicate, got %v", err)
	}
}

func TestFilter_Check_AcceptsOutOfOrderWithinWindow(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithBacktrackMode(true))

	// Send packets 1, 2, 3
	for i := model.PacketID(1); i <= 3; i++ {
		if err := f.Check(i); err != nil {
			t.Errorf("expected nil for ID %d, got %v", i, err)
		}
	}

	// Jump to 10
	if err := f.Check(10); err != nil {
		t.Errorf("expected nil for ID 10, got %v", err)
	}

	// Receive 5 out of order (within window)
	if err := f.Check(5); err != nil {
		t.Errorf("expected nil for out-of-order ID 5, got %v", err)
	}

	// Receive 7 out of order (within window)
	if err := f.Check(7); err != nil {
		t.Errorf("expected nil for out-of-order ID 7, got %v", err)
	}

	// Try duplicate 5
	if err := f.Check(5); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for duplicate 5, got %v", err)
	}
}

func TestFilter_Check_RejectsOutsideWindow(t *testing.T) {
	windowSize := uint32(10)
	f := NewFilter(windowSize, WithBacktrackMode(true))

	// Send packet 1
	if err := f.Check(1); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Jump far ahead (beyond window)
	if err := f.Check(100); err != nil {
		t.Errorf("expected nil for ID 100, got %v", err)
	}

	// Try to receive old packet 1 (now outside window of 10)
	if err := f.Check(1); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for ID 1 outside window, got %v", err)
	}

	// Try packet 90 (just within window: 100-10=90)
	if err := f.Check(91); err != nil {
		t.Errorf("expected nil for ID 91 within window, got %v", err)
	}

	// Try packet 89 (just outside window)
	if err := f.Check(89); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for ID 89 outside window, got %v", err)
	}
}

func TestFilter_Check_SequentialModeRejectsOutOfOrder(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithBacktrackMode(false))

	// Initialize with timestamp to enable TCP sequential mode
	ts := model.PacketTimestamp(1000)

	// First packet can be any ID
	if err := f.CheckWithTimestamp(1, ts); err != nil {
		t.Errorf("expected nil for first packet ID 1, got %v", err)
	}

	// Next must be strictly +1
	if err := f.CheckWithTimestamp(2, ts); err != nil {
		t.Errorf("expected nil for ID 2, got %v", err)
	}

	// Skipping ID 3, sending ID 4 should be rejected (gap not allowed in strict mode)
	if err := f.CheckWithTimestamp(4, ts); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for gap (ID 4 after 2), got %v", err)
	}

	// Continue with ID 3 (correct sequence)
	if err := f.CheckWithTimestamp(3, ts); err != nil {
		t.Errorf("expected nil for ID 3, got %v", err)
	}

	// Try out of order (ID 2 again)
	if err := f.CheckWithTimestamp(2, ts); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for out-of-order ID 2 in sequential mode, got %v", err)
	}

	// Continue forward with ID 4
	if err := f.CheckWithTimestamp(4, ts); err != nil {
		t.Errorf("expected nil for ID 4, got %v", err)
	}
}

func TestFilter_CheckWithTimestamp_ValidatesTimestamp(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithTimestampValidation(60))

	// Current time (within acceptable range)
	now := model.PacketTimestamp(time.Now().Unix())

	// Valid timestamp (within delta)
	if err := f.CheckWithTimestamp(1, now); err != nil {
		t.Errorf("expected nil for valid timestamp, got %v", err)
	}
}

func TestFilter_CheckWithTimestamp_RejectsOldTimestamp(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithTimestampValidation(60))

	// Timestamp from long ago (more than 60 seconds from now)
	oldTimestamp := model.PacketTimestamp(1000000000)

	if err := f.CheckWithTimestamp(1, oldTimestamp); err != ErrTimestampOutOfRange {
		t.Errorf("expected ErrTimestampOutOfRange for old timestamp, got %v", err)
	}
}

func TestFilter_CheckWithTimestamp_RejectsFutureTimestamp(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithTimestampValidation(60))

	// Timestamp far in the future (max uint32 value)
	futureTimestamp := model.PacketTimestamp(4294967295)

	if err := f.CheckWithTimestamp(1, futureTimestamp); err != ErrTimestampOutOfRange {
		t.Errorf("expected ErrTimestampOutOfRange for future timestamp, got %v", err)
	}
}

func TestFilter_Reset(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack)

	// Add some packets
	for i := model.PacketID(1); i <= 5; i++ {
		f.Check(i)
	}

	if f.MaxID() != 5 {
		t.Errorf("expected maxID=5, got %d", f.MaxID())
	}

	// Reset
	f.Reset()

	if f.MaxID() != 0 {
		t.Errorf("expected maxID=0 after reset, got %d", f.MaxID())
	}

	// Should accept packet 1 again
	if err := f.Check(1); err != nil {
		t.Errorf("expected nil after reset, got %v", err)
	}
}

func TestFilter_ConcurrentAccess(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack)

	done := make(chan bool)

	// Concurrent writes
	go func() {
		for i := model.PacketID(1); i <= 1000; i++ {
			f.Check(i)
		}
		done <- true
	}()

	// Concurrent reads
	go func() {
		for i := 0; i < 1000; i++ {
			_ = f.MaxID()
		}
		done <- true
	}()

	<-done
	<-done
}

// TestFilter_PacketIDWraparound tests 32-bit packet ID wraparound handling
// using the half-space technique (0x80000000).
func TestFilter_PacketIDWraparound(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithBacktrackMode(true))

	// Start near the wraparound point
	startID := model.PacketID(0xFFFFFFF0)

	// Accept first packet
	if err := f.Check(startID); err != nil {
		t.Errorf("expected nil for first packet ID %d, got %v", startID, err)
	}

	// Accept packets up to max uint32
	for id := startID + 1; id != 0; id++ {
		if err := f.Check(id); err != nil {
			t.Errorf("expected nil for ID %d, got %v", id, err)
		}
	}

	// Now at 0xFFFFFFFF, next packet wraps to small numbers
	// Packet ID 1 should be accepted (it's "after" 0xFFFFFFFF using half-space)
	if err := f.Check(1); err != nil {
		t.Errorf("expected nil for wrapped ID 1, got %v", err)
	}

	// ID 2 should also be accepted
	if err := f.Check(2); err != nil {
		t.Errorf("expected nil for wrapped ID 2, got %v", err)
	}

	// Old ID (0xFFFFFFF5) should be rejected (it's behind in half-space)
	if err := f.Check(0xFFFFFFF5); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for old ID after wraparound, got %v", err)
	}
}

// TestFilter_PacketIDAfter tests the packetIDAfter helper function behavior.
func TestFilter_PacketIDAfterLogic(t *testing.T) {
	tests := []struct {
		name     string
		a        model.PacketID
		b        model.PacketID
		expected bool
	}{
		{"simple forward", 5, 3, true},
		{"simple backward", 3, 5, false},
		{"equal", 5, 5, false},
		{"wraparound forward", 1, 0xFFFFFFFF, true},
		{"wraparound forward 2", 10, 0xFFFFFFF0, true},
		{"wraparound backward", 0xFFFFFFFF, 1, false},
		// 0x80000000 - 1 = 0x7FFFFFFF, which is < 0x80000000, so it's forward
		{"half space minus one", 0x80000000, 1, true},
		// 0x80000001 - 1 = 0x80000000, which is NOT < 0x80000000, so it's backward
		{"exactly half space", 0x80000001, 1, false},
		{"just under half space", 0x7FFFFFFF, 1, true}, // 0x7FFFFFFF - 1 = 0x7FFFFFFE
		{"zero vs max", 0, 0xFFFFFFFF, true},           // 0 - 0xFFFFFFFF = 1, which is forward
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := packetIDAfter(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("packetIDAfter(%d, %d) = %v, expected %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestFilter_SequentialMode_TimePeriodChange tests TCP mode time period transitions.
func TestFilter_SequentialMode_TimePeriodChange(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithBacktrackMode(false))

	ts1 := model.PacketTimestamp(1000)
	ts2 := model.PacketTimestamp(1001)

	// First time period: packets 1, 2, 3
	if err := f.CheckWithTimestamp(1, ts1); err != nil {
		t.Errorf("expected nil for ID 1 ts1, got %v", err)
	}
	if err := f.CheckWithTimestamp(2, ts1); err != nil {
		t.Errorf("expected nil for ID 2 ts1, got %v", err)
	}
	if err := f.CheckWithTimestamp(3, ts1); err != nil {
		t.Errorf("expected nil for ID 3 ts1, got %v", err)
	}

	// Time moves forward - ID must be 1 to start new period
	if err := f.CheckWithTimestamp(1, ts2); err != nil {
		t.Errorf("expected nil for ID 1 in new time period ts2, got %v", err)
	}

	// Continue in new time period
	if err := f.CheckWithTimestamp(2, ts2); err != nil {
		t.Errorf("expected nil for ID 2 ts2, got %v", err)
	}

	// ID 5 in new period should be rejected (gap)
	if err := f.CheckWithTimestamp(5, ts2); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for gap in new period, got %v", err)
	}

	// Time going backwards should be rejected
	if err := f.CheckWithTimestamp(1, ts1); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for time backtrack, got %v", err)
	}
}

// TestFilter_SequentialMode_NewPeriodMustStartWithOne tests that new time periods must start with ID 1.
func TestFilter_SequentialMode_NewPeriodMustStartWithOne(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithBacktrackMode(false))

	ts1 := model.PacketTimestamp(1000)
	ts2 := model.PacketTimestamp(1001)

	// First period
	if err := f.CheckWithTimestamp(1, ts1); err != nil {
		t.Errorf("expected nil for ID 1 ts1, got %v", err)
	}

	// New time period with ID != 1 should be rejected
	if err := f.CheckWithTimestamp(5, ts2); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for new period starting with ID 5, got %v", err)
	}

	// New time period with ID 1 should be accepted
	if err := f.CheckWithTimestamp(1, ts2); err != nil {
		t.Errorf("expected nil for new period starting with ID 1, got %v", err)
	}
}

// =============================================================================
// ID Wraparound Boundary Tests (边界回绕测试)
// These tests verify correct behavior at packet ID boundaries per packet_id.c
// =============================================================================

// TestFilter_PacketIDWraparound_AtExactBoundary tests the exact 0xFFFFFFFF -> 0x00000001 transition.
// This is the most critical wraparound case matching OpenVPN's behavior.
func TestFilter_PacketIDWraparound_AtExactBoundary(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithBacktrackMode(true))

	// Start at max uint32
	maxID := model.PacketID(0xFFFFFFFF)
	if err := f.Check(maxID); err != nil {
		t.Fatalf("expected nil for max ID 0xFFFFFFFF, got %v", err)
	}

	// ID 0 should be rejected (OpenVPN never uses ID 0)
	if err := f.Check(0); err != ErrInvalidPacketID {
		t.Errorf("expected ErrInvalidPacketID for ID 0, got %v", err)
	}

	// ID 1 should be accepted (wrap to beginning, skipping 0)
	if err := f.Check(1); err != nil {
		t.Errorf("expected nil for wrapped ID 1, got %v", err)
	}

	// Duplicate ID 1 should be rejected
	if err := f.Check(1); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for duplicate ID 1, got %v", err)
	}

	// Continue with ID 2
	if err := f.Check(2); err != nil {
		t.Errorf("expected nil for ID 2, got %v", err)
	}
}

// TestFilter_PacketIDWraparound_WindowAcrossBoundary tests window behavior across wraparound.
func TestFilter_PacketIDWraparound_WindowAcrossBoundary(t *testing.T) {
	windowSize := uint32(10)
	f := NewFilter(windowSize, WithBacktrackMode(true))

	// Start at 0xFFFFFFFC (4 before max), skip some IDs to test out-of-order later
	if err := f.Check(0xFFFFFFFC); err != nil {
		t.Fatalf("expected nil for first ID, got %v", err)
	}

	// Jump directly to 0xFFFFFFFF, skipping 0xFFFFFFFD and 0xFFFFFFFE
	if err := f.Check(0xFFFFFFFF); err != nil {
		t.Fatalf("expected nil for ID 0xFFFFFFFF, got %v", err)
	}

	// Wrap to 1, 2, 3
	for id := model.PacketID(1); id <= 3; id++ {
		if err := f.Check(id); err != nil {
			t.Errorf("expected nil for wrapped ID %d, got %v", id, err)
		}
	}

	// Current maxID is 3 (after wrap)
	// Window is [3, 2, 1, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, ...]
	// ID 0xFFFFFFFD was skipped earlier, should be within window (distance = 6)
	if err := f.Check(0xFFFFFFFD); err != nil {
		t.Errorf("expected nil for in-window skipped ID 0xFFFFFFFD (distance 6), got %v", err)
	}

	// ID 0xFFFFFFFE was also skipped, should be within window (distance = 5)
	if err := f.Check(0xFFFFFFFE); err != nil {
		t.Errorf("expected nil for in-window skipped ID 0xFFFFFFFE (distance 5), got %v", err)
	}

	// ID 0xFFFFFFF5 should be outside window (distance = 14 > windowSize 10)
	if err := f.Check(0xFFFFFFF5); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for out-of-window ID 0xFFFFFFF5, got %v", err)
	}

	// Duplicate of already-seen 0xFFFFFFFD should be rejected
	if err := f.Check(0xFFFFFFFD); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for duplicate ID 0xFFFFFFFD, got %v", err)
	}
}

// TestFilter_PacketIDWraparound_HalfSpaceEdge tests the half-space boundary (0x80000000).
// The half-space technique determines whether an ID is "ahead" or "behind" the current ID.
func TestFilter_PacketIDWraparound_HalfSpaceEdge(t *testing.T) {
	f := NewFilter(DefaultSeqBacktrack, WithBacktrackMode(true))

	// Start at ID 1
	if err := f.Check(1); err != nil {
		t.Fatalf("expected nil for ID 1, got %v", err)
	}

	// ID at exactly half-space distance (0x80000001) is considered "behind"
	// because diff = 0x80000001 - 1 = 0x80000000 which is NOT < 0x80000000
	halfSpaceID := model.PacketID(0x80000001)
	if err := f.Check(halfSpaceID); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for ID at half-space (0x80000001), got %v", err)
	}

	// ID just under half-space (0x80000000) is considered "ahead"
	// because diff = 0x80000000 - 1 = 0x7FFFFFFF which IS < 0x80000000
	justUnderHalfSpace := model.PacketID(0x80000000)
	if err := f.Check(justUnderHalfSpace); err != nil {
		t.Errorf("expected nil for ID just under half-space (0x80000000), got %v", err)
	}
}

// TestFilter_PacketIDDiff tests the packetIDDiff function for wraparound correctness.
func TestFilter_PacketIDDiff(t *testing.T) {
	tests := []struct {
		name     string
		a        model.PacketID
		b        model.PacketID
		expected uint32
	}{
		{"simple forward", 10, 5, 5},
		{"equal", 5, 5, 0},
		{"wraparound diff", 5, 0xFFFFFFF0, 21}, // 5 - 0xFFFFFFF0 = 21 (unsigned)
		{"max to 1", 1, 0xFFFFFFFF, 2},         // 1 - 0xFFFFFFFF = 2 (unsigned)
		{"just wrapped", 2, 0xFFFFFFFF, 3},
		{"zero to max", 0, 0xFFFFFFFF, 1}, // 0 - 0xFFFFFFFF = 1 (unsigned wrap)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := packetIDDiff(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("packetIDDiff(%d, %d) = %d, expected %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestFilter_PacketIDWraparound_FullCycle tests a full cycle through the ID space.
// This simulates long-running connections that wrap multiple times.
func TestFilter_PacketIDWraparound_FullCycle(t *testing.T) {
	// Use a small window for efficiency
	windowSize := uint32(8)
	f := NewFilter(windowSize, WithBacktrackMode(true))

	// Simulate packets approaching, crossing, and continuing past the wraparound point
	// Test specific IDs rather than iterating through all 2^32 values
	testSequence := []model.PacketID{
		0xFFFFFFFA, 0xFFFFFFFB, 0xFFFFFFFC, 0xFFFFFFFD,
		0xFFFFFFFE, 0xFFFFFFFF, // approach max
		1, 2, 3, 4, 5, // wrap and continue
		10, 20, 30, // jump ahead
	}

	for i, id := range testSequence {
		if err := f.Check(id); err != nil {
			t.Errorf("step %d: expected nil for ID %d (0x%X), got %v", i, id, id, err)
		}
	}

	// Final maxID should be 30
	if maxID := f.MaxID(); maxID != 30 {
		t.Errorf("expected maxID=30, got %d", maxID)
	}

	// Old ID from before wrap should be rejected
	if err := f.Check(0xFFFFFFFF); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for old ID 0xFFFFFFFF after progressing, got %v", err)
	}
}

// TestFilter_PacketIDWraparound_OutOfOrderAcrossBoundary tests out-of-order packets across wraparound.
func TestFilter_PacketIDWraparound_OutOfOrderAcrossBoundary(t *testing.T) {
	windowSize := uint32(20)
	f := NewFilter(windowSize, WithBacktrackMode(true))

	// Start with packet near max
	if err := f.Check(0xFFFFFFF0); err != nil {
		t.Fatal(err)
	}

	// Jump past wraparound to ID 10
	if err := f.Check(10); err != nil {
		t.Errorf("expected nil for jump to ID 10, got %v", err)
	}

	// maxID is now 10, window covers [10 back to ~0xFFFFFFFD] spanning the boundary
	// Receive out-of-order packets that were "lost" during the transition

	// ID 5 should be accepted (within window, after 0)
	if err := f.Check(5); err != nil {
		t.Errorf("expected nil for out-of-order ID 5, got %v", err)
	}

	// ID 1 should be accepted (within window, right after wrap)
	if err := f.Check(1); err != nil {
		t.Errorf("expected nil for out-of-order ID 1, got %v", err)
	}

	// ID 0xFFFFFFFF should be accepted (within window, just before wrap)
	if err := f.Check(0xFFFFFFFF); err != nil {
		t.Errorf("expected nil for out-of-order ID 0xFFFFFFFF, got %v", err)
	}

	// ID 0xFFFFFFFE should be accepted (within window)
	if err := f.Check(0xFFFFFFFE); err != nil {
		t.Errorf("expected nil for out-of-order ID 0xFFFFFFFE, got %v", err)
	}

	// ID 0xFFFFFFEF should be outside window (distance from 10 = 21 > windowSize 20)
	// 10 - 0xFFFFFFEF = 21 (unsigned)
	if err := f.Check(0xFFFFFFEF); err != ErrReplayAttack {
		t.Errorf("expected ErrReplayAttack for out-of-window ID 0xFFFFFFEF, got %v", err)
	}
}
