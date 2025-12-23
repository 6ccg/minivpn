package datachannel

import (
	"hash"
	"sync"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
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

	// Scratch buffers for zero-allocation packet processing.
	// Separated into Local (encryption/outgoing) and Remote (decryption/incoming)
	// to allow concurrent read/write operations without locking.
	// Local buffers are used by encryptAndEncodePayloadAEAD (moveDownWorker).
	// Remote buffers are used by decodeEncryptedPayloadAEAD (moveUpWorker).
	scratchAEADLocal  [8]byte  // opcode(1) + peer_id(3) + packet_id(4) for encryption
	scratchAEADRemote [8]byte  // opcode(1) + peer_id(3) + packet_id(4) for decryption
	scratchIVLocal    [12]byte // packet_id(4) + hmac_key(8) for encryption
	scratchIVRemote   [12]byte // packet_id(4) + hmac_key(8) for decryption
	scratchOutput     []byte   // reusable output buffer, grown as needed

	// Multi-key slot support for key rotation (lame duck handling).
	// Each slot holds a KeyMaterial with its own replay filter.
	keys       [session.KS_SIZE]*KeyMaterial
	activeSlot int // which slot is used for encryption (always KS_PRIMARY)
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
// Note: replayFilter should be initialized via initReplayFilter during DataChannel creation.
func (dcs *dataChannelState) CheckReplay(id model.PacketID) error {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	if dcs.replayFilter == nil {
		// Fallback lazy initialization with backtrack mode (UDP-safe default).
		// This should not happen in normal operation as initReplayFilter
		// is called during DataChannel creation.
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

// GetKeyMaterialByID finds the KeyMaterial matching the given key ID.
// Returns the KeyMaterial and its slot index, or nil and -1 if not found.
func (dcs *dataChannelState) GetKeyMaterialByID(keyID uint8) (*KeyMaterial, int) {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	for i := 0; i < session.KS_SIZE; i++ {
		km := dcs.keys[i]
		if km != nil && km.Ready() && km.KeyID() == keyID {
			return km, i
		}
	}
	return nil, -1
}

// SetKeyMaterial sets the KeyMaterial for the given slot.
func (dcs *dataChannelState) SetKeyMaterial(slot int, km *KeyMaterial) {
	if slot < 0 || slot >= session.KS_SIZE {
		return
	}
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	dcs.keys[slot] = km
}

// ClearSlot clears the KeyMaterial at the given slot.
func (dcs *dataChannelState) ClearSlot(slot int) {
	if slot < 0 || slot >= session.KS_SIZE {
		return
	}
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	if dcs.keys[slot] != nil {
		dcs.keys[slot].Clear()
		dcs.keys[slot] = nil
	}
}

// ActiveKeyMaterial returns the active (primary) KeyMaterial used for encryption.
func (dcs *dataChannelState) ActiveKeyMaterial() *KeyMaterial {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	return dcs.keys[dcs.activeSlot]
}

// KeyMaterialAt returns the KeyMaterial at the given slot index.
func (dcs *dataChannelState) KeyMaterialAt(slot int) *KeyMaterial {
	if slot < 0 || slot >= session.KS_SIZE {
		return nil
	}
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	return dcs.keys[slot]
}
