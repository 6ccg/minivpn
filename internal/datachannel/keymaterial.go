package datachannel

import (
	"crypto/hmac"
	"hash"
	"sync"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
)

// KeyMaterial holds the derived cryptographic keys for a single data channel key.
// Each KeyState in session has a corresponding KeyMaterial in datachannel.
// This enables multi-key support for smooth key rotation (lame duck handling).
type KeyMaterial struct {
	mu sync.RWMutex

	// keyID is the 3-bit key ID (0-7) this material is for
	keyID uint8

	// ready indicates if the key material has been derived and is usable
	ready bool

	// dataCipher is the cipher implementation for encryption/decryption
	dataCipher dataCipher

	// HMAC instances for authentication
	hmacLocal  hash.Hash
	hmacRemote hash.Hash

	// Derived key material
	cipherKeyLocal  keySlot
	cipherKeyRemote keySlot
	hmacKeyLocal    keySlot
	hmacKeyRemote   keySlot

	// replayFilter provides per-key replay protection
	replayFilter *replayFilter

	// hash is the factory function for creating new HMAC instances
	hash func() hash.Hash
}

// NewKeyMaterial creates a new KeyMaterial with the given key ID.
func NewKeyMaterial(keyID uint8) *KeyMaterial {
	return &KeyMaterial{
		keyID: keyID,
		ready: false,
	}
}

// KeyID returns the key ID of this material.
func (km *KeyMaterial) KeyID() uint8 {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

// Ready returns whether the key material is ready for use.
func (km *KeyMaterial) Ready() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.ready
}

// SetReady marks the key material as ready for use.
func (km *KeyMaterial) SetReady(ready bool) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.ready = ready
}

// Clear zeroes out the key material for security.
func (km *KeyMaterial) Clear() {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.ready = false
	km.hmacLocal = nil
	km.hmacRemote = nil

	// Zero out key slots for security
	for i := range km.cipherKeyLocal {
		km.cipherKeyLocal[i] = 0
	}
	for i := range km.cipherKeyRemote {
		km.cipherKeyRemote[i] = 0
	}
	for i := range km.hmacKeyLocal {
		km.hmacKeyLocal[i] = 0
	}
	for i := range km.hmacKeyRemote {
		km.hmacKeyRemote[i] = 0
	}
	km.replayFilter = nil
	km.dataCipher = nil
	km.hash = nil
}

// CheckReplay tests whether a packet ID should be accepted or rejected.
// Returns nil if the packet is valid, ErrReplayAttack if it's a replay.
func (km *KeyMaterial) CheckReplay(id model.PacketID) error {
	km.mu.Lock()
	defer km.mu.Unlock()
	if km.replayFilter == nil {
		return nil
	}
	return km.replayFilter.Check(id)
}

// DeriveKeys derives the encryption keys from the given DataChannelKey.
// This should be called once when the key is established.
func (km *KeyMaterial) DeriveKeys(
	dck *session.DataChannelKey,
	localSessionID, remoteSessionID []byte,
	cipher dataCipher,
	hashFactory func() hash.Hash,
	backtrackMode bool,
) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Derive master secret
	master := prf(
		dck.Local().PreMaster[:],
		[]byte("OpenVPN master secret"),
		dck.Local().R1[:],
		dck.Remote().R1[:],
		[]byte{}, []byte{},
		48)

	// Derive key expansion
	keys := prf(
		master,
		[]byte("OpenVPN key expansion"),
		dck.Local().R2[:],
		dck.Remote().R2[:],
		localSessionID,
		remoteSessionID,
		256)

	// Copy derived keys
	copy(km.cipherKeyLocal[:], keys[0:64])
	copy(km.hmacKeyLocal[:], keys[64:128])
	copy(km.cipherKeyRemote[:], keys[128:192])
	copy(km.hmacKeyRemote[:], keys[192:256])

	// Set up cipher and hash
	km.dataCipher = cipher
	km.hash = hashFactory

	// Initialize HMAC instances
	hashSize := hashFactory().Size()
	km.hmacLocal = hmac.New(hashFactory, km.hmacKeyLocal[:hashSize])
	km.hmacRemote = hmac.New(hashFactory, km.hmacKeyRemote[:hashSize])

	// Initialize replay filter for this key
	km.replayFilter = newReplayFilter(DefaultSeqBacktrack, backtrackMode)

	km.ready = true
	return nil
}

// GetCipherKeyLocal returns the local cipher key (for reading with lock held).
func (km *KeyMaterial) GetCipherKeyLocal() keySlot {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.cipherKeyLocal
}

// GetCipherKeyRemote returns the remote cipher key (for reading with lock held).
func (km *KeyMaterial) GetCipherKeyRemote() keySlot {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.cipherKeyRemote
}

// GetHmacKeyLocal returns the local HMAC key (for reading with lock held).
func (km *KeyMaterial) GetHmacKeyLocal() keySlot {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.hmacKeyLocal
}

// GetHmacKeyRemote returns the remote HMAC key (for reading with lock held).
func (km *KeyMaterial) GetHmacKeyRemote() keySlot {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.hmacKeyRemote
}

// DataCipher returns the data cipher (for reading with lock held).
func (km *KeyMaterial) DataCipher() dataCipher {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.dataCipher
}

// HmacLocal returns the local HMAC instance (for reading with lock held).
func (km *KeyMaterial) HmacLocal() hash.Hash {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.hmacLocal
}

// HmacRemote returns the remote HMAC instance (for reading with lock held).
func (km *KeyMaterial) HmacRemote() hash.Hash {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.hmacRemote
}

// HashFactory returns the hash factory function.
func (km *KeyMaterial) HashFactory() func() hash.Hash {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.hash
}
