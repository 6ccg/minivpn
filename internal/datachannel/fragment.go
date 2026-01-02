package datachannel

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/6ccg/minivpn/internal/model"
)

// Fragment types (compatible with OpenVPN 2.5)
const (
	FragWhole      = 0 // Packet is whole (not fragmented)
	FragYesNotLast = 1 // Fragment, but not the last one
	FragYesLast    = 2 // Last fragment in sequence
	FragTest       = 3 // Test packet (not implemented)
)

// Fragment constants (compatible with OpenVPN 2.5)
const (
	NFragBuf           = 25    // Number of concurrent reassembly buffers
	FragTTLSec         = 10    // Fragment TTL in seconds
	FragWakeupInterval = 5     // Housekeeping interval in seconds
	MaxFrags           = 32    // Maximum fragments per packet
	NSeqID             = 256   // Number of sequence IDs (wrap around)
	FragHeaderSize     = 4     // Fragment header size in bytes
	FragSizeRoundShift = 2     // Fragment size must be multiple of 4
	FragSizeRoundMask  = (1 << FragSizeRoundShift) - 1
	FragMapMask        = uint32(0xFFFFFFFF) // Bitmask for fragment map
)

// Fragment header bit masks and shifts
const (
	FragTypeMask   = 0x00000003
	FragTypeShift  = 0
	FragSeqIDMask  = 0x000000ff
	FragSeqIDShift = 2
	FragIDMask     = 0x0000001f
	FragIDShift    = 10
	FragSizeMask   = 0x00003fff
	FragSizeShift  = 15
)

// FragmentHeader represents a parsed fragment header
type FragmentHeader struct {
	FragType int // Fragment type (FragWhole, FragYesNotLast, FragYesLast)
	SeqID    int // Sequence ID (0-255)
	FragID   int // Fragment ID within packet (0-31)
	FragSize int // Fragment size (only valid for FragYesLast)
}

// Fragment represents a single packet being reassembled
type Fragment struct {
	defined     bool      // Whether reassembly is in progress
	maxFragSize int       // Maximum size of each fragment
	fragMap     uint32    // Bitmap of received fragments
	timestamp   time.Time // Last update time for TTL
	buf         []byte    // Reassembly buffer
}

// FragmentList manages multiple concurrent reassembly buffers
type FragmentList struct {
	seqID     int                  // Highest seq_id currently being reassembled
	index     int                  // Index into fragments array for seqID
	fragments [NFragBuf]*Fragment  // Reassembly buffers
}

// FragmentMaster manages fragmentation and reassembly state
type FragmentMaster struct {
	mu sync.Mutex

	// Configuration
	maxPacketSize int  // --fragment max value
	Enabled       bool // Whether fragmentation is enabled

	// Outgoing state
	outgoingSeqID    int    // Current outgoing sequence ID
	outgoingFragSize int    // Calculated fragment size
	outgoingFragID   int    // Next fragment ID to send
	outgoing         []byte // Data waiting to be fragmented

	// Incoming state
	incoming FragmentList

	// Logger
	logger model.Logger

	// Housekeeping
	lastWakeup time.Time
}

// NewFragmentMaster creates a new fragment manager
// maxPacketSize is the --fragment option value (0 to disable)
func NewFragmentMaster(logger model.Logger, maxPacketSize int) *FragmentMaster {
	fm := &FragmentMaster{
		maxPacketSize: maxPacketSize,
		Enabled:       maxPacketSize > 0,
		outgoingSeqID: int(time.Now().UnixNano() & (NSeqID - 1)), // Random initial seq ID
		logger:        logger,
		lastWakeup:    time.Now(),
	}
	// Initialize reassembly buffers
	for i := 0; i < NFragBuf; i++ {
		fm.incoming.fragments[i] = &Fragment{
			buf: make([]byte, 0, 65536),
		}
	}
	return fm
}

// ParseFragmentHeader parses a fragment header from network byte order
func ParseFragmentHeader(data []byte) (*FragmentHeader, error) {
	if len(data) < FragHeaderSize {
		return nil, ErrFragmentBadSize
	}

	flags := binary.BigEndian.Uint32(data[:4])

	fragType := int((flags >> FragTypeShift) & FragTypeMask)
	seqID := int((flags >> FragSeqIDShift) & FragSeqIDMask)
	fragID := int((flags >> FragIDShift) & FragIDMask)

	var fragSize int
	if fragType == FragYesLast {
		fragSize = int((flags>>FragSizeShift)&FragSizeMask) << FragSizeRoundShift
	}

	return &FragmentHeader{
		FragType: fragType,
		SeqID:    seqID,
		FragID:   fragID,
		FragSize: fragSize,
	}, nil
}

// BuildFragmentHeader builds a fragment header in network byte order
func BuildFragmentHeader(fragType, seqID, fragID, fragSize int) []byte {
	var flags uint32

	flags |= uint32(fragType&FragTypeMask) << FragTypeShift
	flags |= uint32(seqID&FragSeqIDMask) << FragSeqIDShift
	flags |= uint32(fragID&FragIDMask) << FragIDShift

	if fragType == FragYesLast {
		// fragSize is stored right-shifted by FragSizeRoundShift
		flags |= uint32((fragSize>>FragSizeRoundShift)&FragSizeMask) << FragSizeShift
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, flags)
	return header
}

// FragmentOutgoing processes an outgoing packet, fragmenting if necessary.
// Returns the first fragment (or whole packet with header).
// Call FragmentReadyToSend repeatedly to get remaining fragments.
func (fm *FragmentMaster) FragmentOutgoing(data []byte) ([]byte, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if len(data) == 0 {
		return nil, nil
	}

	// Check if there's pending outgoing data
	if len(fm.outgoing) > 0 {
		if fm.logger != nil {
			fm.logger.Warnf("fragment: outgoing buffer not empty, len=%d", len(fm.outgoing))
		}
		// Clear old data and continue
		fm.outgoing = nil
	}

	// Calculate max payload size (minus header)
	maxPayloadSize := fm.maxPacketSize - FragHeaderSize

	if len(data) <= maxPayloadSize {
		// No fragmentation needed, send as whole
		header := BuildFragmentHeader(FragWhole, 0, 0, 0)
		return append(header, data...), nil
	}

	// Need to fragment
	fm.outgoingFragSize = optimalFragmentSize(len(data), maxPayloadSize)

	if len(data) > fm.outgoingFragSize*MaxFrags {
		return nil, ErrFragmentTooMany
	}

	// Copy data to outgoing buffer
	fm.outgoing = make([]byte, len(data))
	copy(fm.outgoing, data)

	// Increment sequence ID
	fm.outgoingSeqID = (fm.outgoingSeqID + 1) % NSeqID
	fm.outgoingFragID = 0

	// Return first fragment
	return fm.readyToSendLocked()
}

// optimalFragmentSize calculates optimal fragment size to make last fragment similar size
func optimalFragmentSize(dataLen, maxFragSize int) int {
	// Align to 4-byte boundary
	mfsAligned := maxFragSize &^ FragSizeRoundMask

	div := dataLen / mfsAligned
	mod := dataLen % mfsAligned

	if div > 0 && mod > 0 && mod < mfsAligned*3/4 {
		// Adjust fragment size to make last fragment more uniform
		adjusted := maxFragSize - ((maxFragSize - mod) / (div + 1))
		return (adjusted + FragSizeRoundMask) &^ FragSizeRoundMask
	}
	return mfsAligned
}

// FragmentReadyToSend checks if there are pending fragments and returns the next one
func (fm *FragmentMaster) FragmentReadyToSend() ([]byte, bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if len(fm.outgoing) == 0 {
		return nil, false
	}

	data, err := fm.readyToSendLocked()
	if err != nil {
		if fm.logger != nil {
			fm.logger.Warnf("fragment: readyToSend error: %v", err)
		}
		return nil, false
	}
	return data, true
}

// readyToSendLocked extracts the next fragment (caller must hold lock)
func (fm *FragmentMaster) readyToSendLocked() ([]byte, error) {
	if len(fm.outgoing) == 0 {
		return nil, nil
	}

	size := fm.outgoingFragSize
	isLast := false

	if len(fm.outgoing) <= size {
		size = len(fm.outgoing)
		isLast = true
	}

	// Extract fragment data
	fragData := fm.outgoing[:size]
	fm.outgoing = fm.outgoing[size:]

	// Build fragment header
	fragType := FragYesNotLast
	if isLast {
		fragType = FragYesLast
	}

	header := BuildFragmentHeader(fragType, fm.outgoingSeqID, fm.outgoingFragID, fm.outgoingFragSize)
	fm.outgoingFragID++

	return append(header, fragData...), nil
}

// HasPendingFragments returns whether there are fragments waiting to be sent
func (fm *FragmentMaster) HasPendingFragments() bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return len(fm.outgoing) > 0
}

// FragmentIncoming processes an incoming fragment.
// Returns reassembled data if complete, nil if waiting for more fragments.
func (fm *FragmentMaster) FragmentIncoming(data []byte) ([]byte, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Periodic housekeeping
	fm.housekeepingLocked()

	if len(data) < FragHeaderSize {
		return nil, ErrFragmentBadSize
	}

	header, err := ParseFragmentHeader(data)
	if err != nil {
		return nil, err
	}

	payload := data[FragHeaderSize:]

	switch header.FragType {
	case FragWhole:
		// Whole packet, return directly
		if header.SeqID != 0 || header.FragID != 0 {
			if fm.logger != nil {
				fm.logger.Warnf("fragment: spurious FRAG_WHOLE flags")
			}
		}
		return payload, nil

	case FragYesNotLast, FragYesLast:
		return fm.reassembleLocked(header, payload)

	case FragTest:
		return nil, ErrFragmentBadType

	default:
		return nil, ErrFragmentBadType
	}
}

// reassembleLocked performs fragment reassembly (caller must hold lock)
func (fm *FragmentMaster) reassembleLocked(header *FragmentHeader, payload []byte) ([]byte, error) {
	// Get buffer for this seq_id
	frag := fm.getFragmentBufLocked(header.SeqID)

	// Determine fragment size
	var fragSize int
	if header.FragType == FragYesLast {
		fragSize = header.FragSize
	} else {
		fragSize = len(payload)
	}

	// Verify fragment size alignment
	if fragSize&FragSizeRoundMask != 0 {
		return nil, ErrFragmentBadSize
	}

	// Initialize or verify buffer
	if !frag.defined || frag.maxFragSize != fragSize {
		frag.defined = true
		frag.maxFragSize = fragSize
		frag.fragMap = 0
		frag.buf = frag.buf[:0] // Reset but keep capacity
		// Pre-allocate enough space
		if cap(frag.buf) < fragSize*MaxFrags {
			frag.buf = make([]byte, 0, fragSize*MaxFrags)
		}
	}

	// Calculate where to place the data
	offset := header.FragID * fragSize
	endPos := offset + len(payload)

	// Extend buffer
	if endPos > len(frag.buf) {
		if endPos > cap(frag.buf) {
			return nil, ErrFragmentBufOverflow
		}
		frag.buf = frag.buf[:endPos]
	}

	// Copy fragment data
	copy(frag.buf[offset:], payload)

	// Update bitmap
	if header.FragType == FragYesLast {
		// Last fragment: set all bits from fragID to MaxFrags-1
		frag.fragMap |= FragMapMask << header.FragID
	} else {
		frag.fragMap |= 1 << header.FragID
	}

	// Update timestamp
	frag.timestamp = time.Now()

	// Check if reassembly is complete
	if frag.fragMap == FragMapMask {
		frag.defined = false
		result := make([]byte, len(frag.buf))
		copy(result, frag.buf)
		return result, nil
	}

	return nil, nil // Reassembly not complete
}

// getFragmentBufLocked gets the fragment buffer for a seq_id (sliding window)
func (fm *FragmentMaster) getFragmentBufLocked(seqID int) *Fragment {
	list := &fm.incoming

	diff := moduloSubtract(seqID, list.seqID, NSeqID)

	if abs(diff) >= NFragBuf {
		// seq_id too far, reset all buffers
		for i := 0; i < NFragBuf; i++ {
			list.fragments[i].defined = false
		}
		list.index = 0
		list.seqID = seqID
		diff = 0
	}

	// Slide window forward
	for diff > 0 {
		list.index = (list.index + 1) % NFragBuf
		list.fragments[list.index].defined = false
		list.seqID = (list.seqID + 1) % NSeqID
		diff--
	}

	// Calculate target index
	idx := (list.index + diff + NFragBuf) % NFragBuf
	return list.fragments[idx]
}

// housekeepingLocked cleans up expired fragment buffers
func (fm *FragmentMaster) housekeepingLocked() {
	now := time.Now()
	if now.Sub(fm.lastWakeup) < FragWakeupInterval*time.Second {
		return
	}
	fm.lastWakeup = now

	ttl := FragTTLSec * time.Second
	for i := 0; i < NFragBuf; i++ {
		frag := fm.incoming.fragments[i]
		if frag.defined && now.Sub(frag.timestamp) > ttl {
			if fm.logger != nil {
				fm.logger.Debugf("fragment: TTL expired for buffer %d", i)
			}
			frag.defined = false
		}
	}
}

// moduloSubtract computes (a - b) with wraparound handling
func moduloSubtract(a, b, mod int) int {
	diff := a - b
	if diff > mod/2 {
		diff -= mod
	} else if diff < -mod/2 {
		diff += mod
	}
	return diff
}

// abs returns absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
