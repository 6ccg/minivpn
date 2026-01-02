package datachannel

import (
	"errors"
	"time"

	"github.com/6ccg/minivpn/internal/model"
)

const (
	// DefaultSeqBacktrack is the default sliding window size for replay protection.
	// This matches OpenVPN's DEFAULT_SEQ_BACKTRACK of 64.
	DefaultSeqBacktrack = 64

	// DefaultTimeBacktrack is the default time window in seconds for replay protection.
	// This matches OpenVPN's DEFAULT_TIME_BACKTRACK of 15 seconds.
	// Packets older than this will be rejected even if within the sequence window.
	DefaultTimeBacktrack = 15

	// SeqReapInterval is the interval in seconds between reap passes.
	// This matches OpenVPN's SEQ_REAP_INTERVAL of 5 seconds.
	SeqReapInterval = 5

	// MaxTimestampDelta is the maximum allowed difference between packet timestamp
	// and local time in seconds. Packets outside this range are rejected.
	// This provides protection against delayed replay attacks.
	// This matches OpenVPN's check_timestamp_delta() behavior.
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
	// ErrTimestampOutOfRange is returned when the packet timestamp is too far from local time.
	ErrTimestampOutOfRange = errors.New("packet timestamp out of acceptable range")
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

// replayFilter implements a sliding window algorithm for replay attack detection,
// similar to IPSec and OpenVPN's packet_id_test mechanism.
//
// It supports both:
// - Backtrack mode (UDP): allows packet reordering within the window
// - Sequential mode (TCP): requires strictly increasing packet IDs
//
// Additionally, it implements time_backtrack protection which expires packet IDs
// that are older than a configurable time window, preventing delayed replay attacks.
//
// It also supports optional timestamp validation (check_timestamp_delta) which
// validates packet timestamps against local time to prevent long-term replay attacks.
//
// Thread Safety: This type is NOT thread-safe. Callers must hold an external lock
// before calling any methods. This matches OpenVPN's single-threaded design where
// packet_id_test() is called without locks.
type replayFilter struct {
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
	// This matches OpenVPN's check_timestamp_delta() functionality
	validateTimestamp bool

	// maxTimestampDelta is the maximum allowed difference from local time in seconds
	maxTimestampDelta int

	// initialized tracks whether we've received any packets yet
	initialized bool
}

// newReplayFilter creates a new replay filter with the specified window size.
// If backtrackMode is true, out-of-order packets within the window are allowed.
// Uses default time backtrack of 15 seconds.
func newReplayFilter(windowSize uint32, backtrackMode bool) *replayFilter {
	return newReplayFilterWithTimeBacktrack(windowSize, DefaultTimeBacktrack, backtrackMode)
}

// newReplayFilterWithTimeBacktrack creates a new replay filter with custom time backtrack.
// windowSize: number of packet IDs to track (max 65536, default 64)
// timeBacktrack: maximum age in seconds for packets (0 to disable, default 15)
// backtrackMode: true for UDP (allows reordering), false for TCP (sequential only)
func newReplayFilterWithTimeBacktrack(windowSize uint32, timeBacktrack int, backtrackMode bool) *replayFilter {
	if windowSize > 65536 {
		windowSize = 65536
	}
	if windowSize == 0 {
		windowSize = DefaultSeqBacktrack
	}
	if timeBacktrack < 0 {
		timeBacktrack = 0
	}

	return &replayFilter{
		windowSize:        windowSize,
		timeBacktrack:     timeBacktrack,
		seqList:           make([]int64, windowSize),
		backtrackMode:     backtrackMode,
		validateTimestamp: false,
		maxTimestampDelta: MaxTimestampDelta,
		initialized:       false,
		lastReap:          0,
	}
}

// ReplayFilterOption is a functional option for configuring a replayFilter.
type ReplayFilterOption func(*replayFilter)

// WithTimestampValidation enables validation of packet timestamps against local time.
// This matches OpenVPN's check_timestamp_delta() functionality.
// maxDelta: maximum allowed difference between packet timestamp and local time in seconds
func WithTimestampValidation(maxDelta int) ReplayFilterOption {
	return func(rf *replayFilter) {
		rf.validateTimestamp = true
		if maxDelta > 0 {
			rf.maxTimestampDelta = maxDelta
		}
	}
}

// newReplayFilterWithOptions creates a new replay filter with functional options.
func newReplayFilterWithOptions(windowSize uint32, backtrackMode bool, opts ...ReplayFilterOption) *replayFilter {
	rf := newReplayFilterWithTimeBacktrack(windowSize, DefaultTimeBacktrack, backtrackMode)
	for _, opt := range opts {
		opt(rf)
	}
	return rf
}

// Check tests whether a packet ID should be accepted or rejected.
// Returns nil if the packet is valid, ErrReplayAttack if it's a replay.
func (rf *replayFilter) Check(id model.PacketID) error {
	return rf.CheckWithTimestamp(id, 0)
}

// CheckWithTimestamp tests whether a packet ID and timestamp should be accepted.
// If timestamp is 0, timestamp validation is skipped.
// Returns nil if the packet is valid, an error if it should be rejected.
// This matches OpenVPN's packet_id_test() with check_timestamp_delta() functionality.
//
// Thread Safety: Caller must hold an external lock.
func (rf *replayFilter) CheckWithTimestamp(id model.PacketID, timestamp model.PacketTimestamp) error {
	now := time.Now().Unix()

	// Perform periodic reap to expire old entries
	rf.reapTestLocked(now)

	// Packet ID 0 is invalid in OpenVPN
	if id == 0 {
		return ErrReplayAttack
	}

	// Validate timestamp if enabled and timestamp is provided
	// This matches OpenVPN's check_timestamp_delta() in packet_id.h
	if rf.validateTimestamp && timestamp > 0 {
		if err := rf.checkTimestampLocked(timestamp, now); err != nil {
			return err
		}
	}

	// First packet: accept and initialize
	if !rf.initialized {
		rf.maxID = id
		if timestamp > 0 {
			rf.maxTime = timestamp
		}
		rf.resetSeqListLocked()
		rf.seqList[0] = now // mark position 0 as seen with current timestamp
		rf.initialized = true
		return nil
	}

	// In backtrack mode (UDP), we allow packet reordering subject to
	// seq_backtrack and time_backtrack constraints.
	if rf.backtrackMode {
		return rf.checkBacktrackModeLocked(id, timestamp, now)
	}

	// In sequential mode (TCP), packets must arrive in order
	return rf.checkSequentialModeLocked(id, timestamp, now)
}

// checkTimestampLocked validates the packet timestamp against local time.
// This matches OpenVPN's check_timestamp_delta() function in packet_id.h.
// Must be called with external lock held.
func (rf *replayFilter) checkTimestampLocked(timestamp model.PacketTimestamp, now int64) error {
	remote := int64(timestamp)
	var delta int64
	if now >= remote {
		delta = now - remote
	} else {
		delta = remote - now
	}

	if delta > int64(rf.maxTimestampDelta) {
		return ErrTimestampOutOfRange
	}
	return nil
}

// checkBacktrackModeLocked handles replay check for UDP mode (allows reordering).
// Must be called with external lock held.
func (rf *replayFilter) checkBacktrackModeLocked(id model.PacketID, timestamp model.PacketTimestamp, now int64) error {
	// First check time period if timestamps are available.
	// This matches OpenVPN's packet_id_test() behavior in backtrack mode:
	// - time goes back: reject immediately
	// - time goes forward: accept immediately and reset window
	// - same time period: check sliding window
	if timestamp > 0 && rf.maxTime > 0 {
		if timestamp < rf.maxTime {
			// Time went backwards - reject
			return ErrReplayAttack
		}
		if timestamp > rf.maxTime {
			// Time moved forward - accept and reset window for new time period
			rf.maxID = id
			rf.maxTime = timestamp
			rf.resetSeqListLocked()
			rf.seqList[0] = now
			return nil
		}
		// timestamp == rf.maxTime: continue to check ID within same time period
	}

	// Case 1: New packet ID is ahead of maxID (using wraparound-safe comparison)
	if packetIDAfter(id, rf.maxID) {
		shift := packetIDDiff(id, rf.maxID)

		if shift >= rf.windowSize {
			// Packet is far ahead, reset the window
			rf.resetSeqListLocked()
		} else {
			// Shift the seqList forward
			rf.shiftSeqListLocked(shift)
		}

		rf.maxID = id
		if timestamp > rf.maxTime {
			rf.maxTime = timestamp
		}
		rf.seqList[0] = now // mark new position as seen
		return nil
	}

	// Case 2: Packet ID equals maxID (duplicate)
	if id == rf.maxID {
		return ErrReplayAttack
	}

	// Case 3: Packet ID is behind maxID (out of order, using wraparound-safe diff)
	diff := packetIDDiff(rf.maxID, id)

	// Check if packet is within the window
	if diff >= rf.windowSize {
		// Packet is too old (outside the window)
		return ErrReplayAttack
	}

	// Check if this packet ID was already seen or expired
	idx := diff
	seenTime := rf.seqList[idx]

	if seenTime == seqExpired {
		// Packet has expired due to time_backtrack
		return ErrReplayAttack
	}

	if seenTime != seqUnseen {
		// Already seen this packet (seenTime > 1 means we have a timestamp)
		return ErrReplayAttack
	}

	// Mark as seen with current timestamp
	rf.seqList[idx] = now
	return nil
}

// checkSequentialModeLocked handles replay check for TCP mode (strict ordering).
// This matches OpenVPN's packet_id_test() for non-backtrack mode.
// In non-backtrack mode, all sequence number series must begin at some number n > 0
// and must increment linearly without gaps.
// Must be called with external lock held.
func (rf *replayFilter) checkSequentialModeLocked(id model.PacketID, timestamp model.PacketTimestamp, now int64) error {
	// For data channel (short-form packet ID, no timestamp), timestamp is always 0.
	// For long-form with timestamp, we need to handle time period changes.

	// Case 1: Same time period (or both timestamps are 0 for short-form)
	if timestamp == rf.maxTime {
		// First packet in this time period (maxID == 0), or strictly sequential (id == maxID+1)
		if rf.maxID == 0 || id == rf.maxID+1 {
			rf.maxID = id
			return nil
		}
		// Not sequential - reject (gap or duplicate or out of order)
		return ErrReplayAttack
	}

	// Case 2: Time went backwards - reject
	if timestamp < rf.maxTime {
		return ErrReplayAttack
	}

	// Case 3: Time moved forward - new time period, ID must be 1
	if id == 1 {
		rf.maxID = id
		rf.maxTime = timestamp
		return nil
	}

	// New time period but ID is not 1 - reject
	return ErrReplayAttack
}

// reapTestLocked checks if it's time to run a reap operation.
// Must be called with external lock held.
func (rf *replayFilter) reapTestLocked(now int64) {
	if rf.timeBacktrack > 0 && rf.lastReap+SeqReapInterval <= now {
		rf.reapLocked(now)
	}
}

// reapLocked expires sequence numbers which can no longer be accepted
// because they would violate time_backtrack.
// Must be called with external lock held.
func (rf *replayFilter) reapLocked(now int64) {
	if rf.timeBacktrack == 0 {
		rf.lastReap = now
		return
	}

	expireThreshold := now - int64(rf.timeBacktrack)
	expired := false

	for i := uint32(0); i < rf.windowSize; i++ {
		t := rf.seqList[i]

		if t == seqExpired {
			// Already expired, everything after this is also expired
			break
		}

		if !expired && t > seqExpired && t < expireThreshold {
			// This entry and all subsequent ones should be expired
			expired = true
		}

		if expired {
			rf.seqList[i] = seqExpired
		}
	}

	rf.lastReap = now
}

// shiftSeqListLocked shifts the seqList forward by the specified amount.
// Must be called with external lock held.
func (rf *replayFilter) shiftSeqListLocked(shift uint32) {
	if shift >= rf.windowSize {
		rf.resetSeqListLocked()
		return
	}

	// Shift entries forward (newer entries at lower indices)
	for i := rf.windowSize - 1; i >= shift; i-- {
		rf.seqList[i] = rf.seqList[i-shift]
	}

	// Clear the new positions
	for i := uint32(0); i < shift; i++ {
		rf.seqList[i] = seqUnseen
	}
}

// resetSeqListLocked resets all entries in the seqList to unseen.
func (rf *replayFilter) resetSeqListLocked() {
	for i := range rf.seqList {
		rf.seqList[i] = seqUnseen
	}
}

// Reset clears the replay filter state.
//
// Thread Safety: Caller must hold an external lock.
func (rf *replayFilter) Reset() {
	rf.maxID = 0
	rf.resetSeqListLocked()
	rf.initialized = false
	rf.lastReap = 0
}

// MaxID returns the highest packet ID seen so far.
//
// Thread Safety: Caller must hold an external lock.
func (rf *replayFilter) MaxID() model.PacketID {
	return rf.maxID
}
