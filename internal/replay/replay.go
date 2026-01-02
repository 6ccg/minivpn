// Package replay implements replay attack detection for OpenVPN control and data channels.
// It uses a sliding window algorithm similar to IPSec and OpenVPN's packet_id mechanism.
package replay

import (
	"errors"
	"sync"
	"time"

	"github.com/6ccg/minivpn/internal/model"
)

const (
	// DefaultSeqBacktrack is the default sliding window size for replay protection.
	// This matches OpenVPN's DEFAULT_SEQ_BACKTRACK of 64.
	DefaultSeqBacktrack = 64

	// DefaultTimeBacktrack is the default time window in seconds for replay protection.
	// This matches OpenVPN's DEFAULT_TIME_BACKTRACK of 15 seconds.
	DefaultTimeBacktrack = 15

	// SeqReapInterval is the interval in seconds between reap passes.
	// This matches OpenVPN's SEQ_REAP_INTERVAL of 5 seconds.
	SeqReapInterval = 5

	// MaxTimestampDelta is the maximum allowed difference between packet timestamp
	// and local time in seconds. Packets outside this range are rejected.
	// This provides protection against delayed replay attacks.
	MaxTimestampDelta = 60

	// seqUnseen indicates a packet ID slot that has not been seen yet.
	seqUnseen = int64(0)

	// seqExpired indicates a packet ID slot that has expired due to time_backtrack.
	seqExpired = int64(1)

	// packetIDHalfSpace is used for wraparound detection.
	// If the difference between two IDs is less than this, we consider it a forward move.
	// This matches OpenVPN's 0x80000000u technique in reliable.c.
	packetIDHalfSpace = uint32(0x80000000)
)

var (
	// ErrReplayAttack is returned when a replay attack is detected.
	ErrReplayAttack = errors.New("replay attack detected")

	// ErrInvalidPacketID is returned when the packet ID is zero.
	ErrInvalidPacketID = errors.New("invalid packet ID (zero)")

	// ErrTimestampOutOfRange is returned when the packet timestamp is too far from local time.
	ErrTimestampOutOfRange = errors.New("packet timestamp out of acceptable range")

	// ErrTimeBacktrack is returned when the packet timestamp is older than the max seen timestamp.
	// This matches OpenVPN's packet_id_test() behavior: "if (pin->time < p->time) return false;"
	ErrTimeBacktrack = errors.New("time backtrack detected")
)

// packetIDAfter returns true if 'a' is considered to come after 'b' in the
// packet ID sequence, correctly handling wraparound.
// Uses the same technique as OpenVPN's reliable.c: if the unsigned difference
// is less than half the ID space, 'a' is ahead of 'b'.
func packetIDAfter(a, b model.PacketID) bool {
	diff := uint32(a - b)
	return diff > 0 && diff < packetIDHalfSpace
}

// packetIDDiff returns the forward distance from 'b' to 'a' in the packet ID space.
// Handles wraparound correctly using unsigned arithmetic.
func packetIDDiff(a, b model.PacketID) uint32 {
	return uint32(a - b)
}

// Filter implements a sliding window algorithm for replay attack detection,
// similar to IPSec and OpenVPN's packet_id_test mechanism.
//
// It supports both:
// - Backtrack mode (UDP): allows packet reordering within the window
// - Sequential mode (TCP): requires strictly increasing packet IDs
//
// Additionally, it implements time_backtrack protection which expires packet IDs
// that are older than a configurable time window, preventing delayed replay attacks.
type Filter struct {
	mu sync.Mutex

	// maxID is the highest packet ID we've seen so far
	maxID model.PacketID

	// maxTime is the highest timestamp we've seen so far
	maxTime model.PacketTimestamp

	// windowSize is the number of packets we track for out-of-order detection
	windowSize uint32

	// seqList stores the timestamp (Unix seconds) when each packet ID was seen.
	// Index 0 is the most recent (maxID), index i is (maxID - i).
	// Values: 0 = unseen, 1 = expired, >1 = timestamp when seen
	seqList []int64

	// timeBacktrack is the maximum age in seconds for a packet to be accepted.
	// Packets older than this will be rejected even if within the sequence window.
	timeBacktrack int

	// lastReap is the Unix timestamp of the last reap operation.
	lastReap int64

	// backtrackMode allows out-of-order packets within the window (for UDP)
	// when false, requires strictly sequential IDs (for TCP)
	backtrackMode bool

	// validateTimestamp enables timestamp validation against local time
	validateTimestamp bool

	// maxTimestampDelta is the maximum allowed difference from local time
	maxTimestampDelta int

	// initialized tracks whether we've received any packets yet
	initialized bool
}

// FilterOption is a functional option for configuring a Filter.
type FilterOption func(*Filter)

// WithTimeBacktrack sets the time backtrack window in seconds.
func WithTimeBacktrack(seconds int) FilterOption {
	return func(f *Filter) {
		if seconds >= 0 {
			f.timeBacktrack = seconds
		}
	}
}

// WithTimestampValidation enables validation of packet timestamps against local time.
func WithTimestampValidation(maxDelta int) FilterOption {
	return func(f *Filter) {
		f.validateTimestamp = true
		f.maxTimestampDelta = maxDelta
	}
}

// WithBacktrackMode enables or disables backtrack mode (UDP vs TCP).
func WithBacktrackMode(enabled bool) FilterOption {
	return func(f *Filter) {
		f.backtrackMode = enabled
	}
}

// NewFilter creates a new replay filter with the specified window size.
// Default configuration: backtrack mode enabled (UDP), time backtrack of 15 seconds.
func NewFilter(windowSize uint32, opts ...FilterOption) *Filter {
	if windowSize > 65536 {
		windowSize = 65536
	}
	if windowSize == 0 {
		windowSize = DefaultSeqBacktrack
	}

	f := &Filter{
		windowSize:        windowSize,
		timeBacktrack:     DefaultTimeBacktrack,
		seqList:           make([]int64, windowSize),
		backtrackMode:     true, // default to UDP mode
		validateTimestamp: false,
		maxTimestampDelta: MaxTimestampDelta,
		initialized:       false,
		lastReap:          0,
	}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

// Check tests whether a packet ID should be accepted or rejected.
// Returns nil if the packet is valid, an error if it should be rejected.
func (f *Filter) Check(id model.PacketID) error {
	return f.CheckWithTimestamp(id, 0)
}

// CheckWithTimestamp tests whether a packet ID and timestamp should be accepted.
// If timestamp is 0, timestamp validation is skipped.
// Returns nil if the packet is valid, an error if it should be rejected.
func (f *Filter) CheckWithTimestamp(id model.PacketID, timestamp model.PacketTimestamp) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now().Unix()

	// Perform periodic reap to expire old entries
	f.reapTestLocked(now)

	// Packet ID 0 is invalid in OpenVPN
	if id == 0 {
		return ErrInvalidPacketID
	}

	// Validate timestamp if enabled and timestamp is provided
	if f.validateTimestamp && timestamp > 0 {
		if err := f.checkTimestampLocked(timestamp, now); err != nil {
			return err
		}
	}

	// First packet: accept and initialize
	if !f.initialized {
		f.maxID = id
		if timestamp > 0 {
			f.maxTime = timestamp
		}
		f.resetSeqListLocked()
		f.seqList[0] = now // mark position 0 as seen with current timestamp
		f.initialized = true
		return nil
	}

	// In backtrack mode (UDP), we allow packet reordering subject to
	// seq_backtrack and time_backtrack constraints.
	if f.backtrackMode {
		return f.checkBacktrackModeLocked(id, timestamp, now)
	}

	// In sequential mode (TCP), packets must arrive in order
	return f.checkSequentialModeLocked(id, timestamp, now)
}

// checkTimestampLocked validates the packet timestamp against local time.
// Must be called with f.mu held.
func (f *Filter) checkTimestampLocked(timestamp model.PacketTimestamp, now int64) error {
	remote := int64(timestamp)
	var delta int64
	if now >= remote {
		delta = now - remote
	} else {
		delta = remote - now
	}

	if delta > int64(f.maxTimestampDelta) {
		return ErrTimestampOutOfRange
	}
	return nil
}

// checkBacktrackModeLocked handles replay check for UDP mode (allows reordering).
// Must be called with f.mu held.
//
// This implements OpenVPN's packet_id_test() for backtrack mode (packet_id.c:212-270):
// - Allows out-of-order packets within the sequence window
// - Rejects time-backtrack: packets with timestamp < maxTime are rejected
// - When timestamp advances, the sequence window is effectively reset
func (f *Filter) checkBacktrackModeLocked(id model.PacketID, timestamp model.PacketTimestamp, now int64) error {
	// OpenVPN packet_id_test time-backtrack check (packet_id.c:252-258):
	// "if (pin->time < p->time) return false;"
	// This prevents accepting packets with timestamps older than what we've seen.
	// Note: Only check if we have both a valid maxTime and incoming timestamp.
	if timestamp > 0 && f.maxTime > 0 && timestamp < f.maxTime {
		return ErrTimeBacktrack
	}

	// Case 1: New packet ID is ahead of maxID (using wraparound-safe comparison)
	if packetIDAfter(id, f.maxID) {
		shift := packetIDDiff(id, f.maxID)

		if shift >= f.windowSize {
			// Packet is far ahead, reset the window
			f.resetSeqListLocked()
		} else {
			// Shift the seqList forward
			f.shiftSeqListLocked(shift)
		}

		f.maxID = id
		// OpenVPN packet_id_add behavior (packet_id.c:286-297):
		// When pin->time > p->time, reset the sequence tracking for the new time period.
		if timestamp > f.maxTime {
			f.maxTime = timestamp
			// When time advances, we could optionally reset the window here,
			// but OpenVPN only does this for the base counter, not the full bitmap.
		}
		f.seqList[0] = now // mark new position as seen
		return nil
	}

	// Case 2: Packet ID equals maxID (duplicate)
	if id == f.maxID {
		return ErrReplayAttack
	}

	// Case 3: Packet ID is behind maxID (out of order, using wraparound-safe diff)
	diff := packetIDDiff(f.maxID, id)

	// Check if packet is within the window
	if diff >= f.windowSize {
		// Packet is too old (outside the window)
		return ErrReplayAttack
	}

	// Check if this packet ID was already seen or expired
	idx := diff
	seenTime := f.seqList[idx]

	if seenTime == seqExpired {
		// Packet has expired due to time_backtrack
		return ErrReplayAttack
	}

	if seenTime != seqUnseen {
		// Already seen this packet (seenTime > 1 means we have a timestamp)
		return ErrReplayAttack
	}

	// Mark as seen with current timestamp
	f.seqList[idx] = now
	return nil
}

// checkSequentialModeLocked handles replay check for TCP mode (strict ordering).
// This matches OpenVPN's packet_id_test() for non-backtrack mode.
// In non-backtrack mode, all sequence number series must begin at some number n > 0
// and must increment linearly without gaps.
// Must be called with f.mu held.
func (f *Filter) checkSequentialModeLocked(id model.PacketID, timestamp model.PacketTimestamp, now int64) error {
	// Case 1: Same time period - packet ID must be strictly sequential
	if timestamp == f.maxTime {
		// First packet in this time period, or strictly sequential
		if f.maxID == 0 || id == f.maxID+1 {
			f.maxID = id
			return nil
		}
		// Not sequential - reject (gap or duplicate or out of order)
		return ErrReplayAttack
	}

	// Case 2: Time went backwards - reject
	if timestamp < f.maxTime {
		return ErrReplayAttack
	}

	// Case 3: Time moved forward - new time period, ID must be 1
	if id == 1 {
		f.maxID = id
		f.maxTime = timestamp
		return nil
	}

	// New time period but ID is not 1 - reject
	return ErrReplayAttack
}

// reapTestLocked checks if it's time to run a reap operation.
// Must be called with f.mu held.
func (f *Filter) reapTestLocked(now int64) {
	if f.timeBacktrack > 0 && f.lastReap+SeqReapInterval <= now {
		f.reapLocked(now)
	}
}

// reapLocked expires sequence numbers which can no longer be accepted
// because they would violate time_backtrack.
// Must be called with f.mu held.
func (f *Filter) reapLocked(now int64) {
	if f.timeBacktrack == 0 {
		f.lastReap = now
		return
	}

	expireThreshold := now - int64(f.timeBacktrack)
	expired := false

	for i := uint32(0); i < f.windowSize; i++ {
		t := f.seqList[i]

		if t == seqExpired {
			// Already expired, everything after this is also expired
			break
		}

		if !expired && t > seqExpired && t < expireThreshold {
			// This entry and all subsequent ones should be expired
			expired = true
		}

		if expired {
			f.seqList[i] = seqExpired
		}
	}

	f.lastReap = now
}

// shiftSeqListLocked shifts the seqList forward by the specified amount.
// Must be called with f.mu held.
func (f *Filter) shiftSeqListLocked(shift uint32) {
	if shift >= f.windowSize {
		f.resetSeqListLocked()
		return
	}

	// Shift entries forward (newer entries at lower indices)
	for i := f.windowSize - 1; i >= shift; i-- {
		f.seqList[i] = f.seqList[i-shift]
	}

	// Clear the new positions
	for i := uint32(0); i < shift; i++ {
		f.seqList[i] = seqUnseen
	}
}

// resetSeqListLocked resets all entries in the seqList to unseen.
// Must be called with f.mu held.
func (f *Filter) resetSeqListLocked() {
	for i := range f.seqList {
		f.seqList[i] = seqUnseen
	}
}

// Reset clears the replay filter state.
func (f *Filter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxID = 0
	f.maxTime = 0
	f.resetSeqListLocked()
	f.initialized = false
	f.lastReap = 0
}

// MaxID returns the highest packet ID seen so far.
func (f *Filter) MaxID() model.PacketID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxID
}
