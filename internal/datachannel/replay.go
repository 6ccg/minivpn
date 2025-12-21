package datachannel

import (
	"sync"

	"github.com/ooni/minivpn/internal/model"
)

const (
	// DefaultSeqBacktrack is the default sliding window size for replay protection.
	// This matches OpenVPN's DEFAULT_SEQ_BACKTRACK of 64.
	DefaultSeqBacktrack = 64
)

// replayFilter implements a sliding window algorithm for replay attack detection,
// similar to IPSec and OpenVPN's packet_id_test mechanism.
//
// It supports both:
// - Backtrack mode (UDP): allows packet reordering within the window
// - Sequential mode (TCP): requires strictly increasing packet IDs
type replayFilter struct {
	mu sync.Mutex

	// maxID is the highest packet ID we've seen so far
	maxID model.PacketID

	// windowSize is the number of packets we track for out-of-order detection
	windowSize uint32

	// bitmap tracks which packet IDs within the window have been seen
	// bit i represents (maxID - windowSize + 1 + i)
	bitmap uint64

	// backtrackMode allows out-of-order packets within the window (for UDP)
	// when false, requires strictly sequential IDs (for TCP)
	backtrackMode bool

	// initialized tracks whether we've received any packets yet
	initialized bool
}

// newReplayFilter creates a new replay filter with the specified window size.
// If backtrackMode is true, out-of-order packets within the window are allowed.
func newReplayFilter(windowSize uint32, backtrackMode bool) *replayFilter {
	if windowSize > 64 {
		windowSize = 64 // bitmap is uint64, max 64 bits
	}
	if windowSize == 0 {
		windowSize = DefaultSeqBacktrack
	}
	return &replayFilter{
		windowSize:    windowSize,
		backtrackMode: backtrackMode,
		bitmap:        0,
		initialized:   false,
	}
}

// Check tests whether a packet ID should be accepted or rejected.
// Returns nil if the packet is valid, ErrReplayAttack if it's a replay.
func (rf *replayFilter) Check(id model.PacketID) error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	// First packet: accept and initialize
	if !rf.initialized {
		if id == 0 {
			// Packet ID 0 is invalid in OpenVPN
			return ErrReplayAttack
		}
		rf.maxID = id
		rf.bitmap = 1 // mark position 0 as seen
		rf.initialized = true
		return nil
	}

	// Case 1: New packet ID is greater than any we've seen
	if id > rf.maxID {
		shift := uint32(id - rf.maxID)
		if shift >= rf.windowSize {
			// Packet is far ahead, reset the window
			rf.bitmap = 1
		} else {
			// Shift the bitmap and mark the new position
			rf.bitmap = (rf.bitmap << shift) | 1
		}
		rf.maxID = id
		return nil
	}

	// Case 2: Packet ID equals maxID (duplicate)
	if id == rf.maxID {
		return ErrReplayAttack
	}

	// Case 3: Packet ID is less than maxID
	diff := uint32(rf.maxID - id)

	// In sequential mode, any packet older than maxID is rejected
	if !rf.backtrackMode {
		return ErrReplayAttack
	}

	// In backtrack mode, check if within window
	if diff > rf.windowSize {
		// Packet is too old (outside the window)
		return ErrReplayAttack
	}

	// Check if this packet ID was already seen (check the bitmap)
	bitPos := rf.windowSize - diff
	mask := uint64(1) << bitPos
	if rf.bitmap&mask != 0 {
		// Already seen this packet
		return ErrReplayAttack
	}

	// Mark as seen
	rf.bitmap |= mask
	return nil
}

// Reset clears the replay filter state.
func (rf *replayFilter) Reset() {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.maxID = 0
	rf.bitmap = 0
	rf.initialized = false
}

// MaxID returns the highest packet ID seen so far.
func (rf *replayFilter) MaxID() model.PacketID {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return rf.maxID
}
