package datachannel

import (
	"hash"
	"sync"

	"github.com/ooni/minivpn/internal/model"
)

// keySlot holds the different local and remote keys.
type keySlot [64]byte

// dataChannelState is the state of the data channel.
type dataChannelState struct {
	dataCipher dataCipher

	// outgoing and incoming nomenclature is probably more adequate here.
	hmacLocal       hash.Hash
	hmacRemote      hash.Hash
	cipherKeyLocal  keySlot
	cipherKeyRemote keySlot
	hmacKeyLocal    keySlot
	hmacKeyRemote   keySlot

	// replayFilter provides sliding window replay protection for both AEAD and non-AEAD modes.
	// For UDP: uses backtrack mode to allow out-of-order packets within the window.
	// For TCP: uses sequential mode requiring strictly increasing packet IDs.
	replayFilter *replayFilter

	hash func() hash.Hash
	mu   sync.Mutex

	// not used at the moment, paving the way for key rotation.
	// keyID           int
}

// initReplayFilter initializes the replay filter with the appropriate mode.
// backtrackMode should be true for UDP (allows out-of-order), false for TCP (sequential).
func (dcs *dataChannelState) initReplayFilter(backtrackMode bool) {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	dcs.replayFilter = newReplayFilter(DefaultSeqBacktrack, backtrackMode)
}

// CheckReplay tests whether a packet ID should be accepted or rejected.
// Returns nil if the packet is valid, ErrReplayAttack if it's a replay.
func (dcs *dataChannelState) CheckReplay(id model.PacketID) error {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	if dcs.replayFilter == nil {
		// Lazy initialization with backtrack mode (UDP-safe default)
		dcs.replayFilter = newReplayFilter(DefaultSeqBacktrack, true)
	}
	return dcs.replayFilter.Check(id)
}

// RemotePacketID returns the highest packet ID seen so far.
// Deprecated: Use CheckReplay instead for replay protection.
func (dcs *dataChannelState) RemotePacketID() (model.PacketID, error) {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	if dcs.replayFilter == nil {
		return 0, nil
	}
	return dcs.replayFilter.MaxID(), nil
}

// SetRemotePacketID is deprecated and now a no-op.
// The replayFilter automatically tracks seen packet IDs.
// Deprecated: Use CheckReplay instead.
func (dcs *dataChannelState) SetRemotePacketID(id model.PacketID) {
	// No-op: replay filter manages state internally
}

// setInitialPacketIDForTest initializes the replay filter with packets already seen up to maxID.
// This is only for testing purposes.
func (dcs *dataChannelState) setInitialPacketIDForTest(maxID model.PacketID) {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	if dcs.replayFilter == nil {
		dcs.replayFilter = newReplayFilter(DefaultSeqBacktrack, true)
	}
	// Mark all packets from 1 to maxID as seen
	for i := model.PacketID(1); i <= maxID; i++ {
		dcs.replayFilter.Check(i)
	}
}
