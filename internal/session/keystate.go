package session

import (
	"time"

	"github.com/ooni/minivpn/internal/model"
)

// Key slot constants matching OpenVPN's ssl_common.h
const (
	// KS_PRIMARY is the primary (active) key slot
	KS_PRIMARY = 0
	// KS_LAME_DUCK is the retiring key slot
	KS_LAME_DUCK = 1
	// KS_SIZE is the number of key slots per session
	KS_SIZE = 2

	// DefaultTransitionWindow is how long (seconds) a lame duck key stays alive
	// after a soft reset. This corresponds to OpenVPN's --transition-window option.
	DefaultTransitionWindow = 60
)

// KeyState represents a data channel key with its lifecycle state.
// This mirrors OpenVPN's struct key_state in ssl_common.h.
type KeyState struct {
	// Key is the underlying data channel key material
	Key *DataChannelKey

	// KeyID is the 3-bit key ID (0-7) used in packet headers
	KeyID uint8

	// State is the negotiation state of this key
	State model.NegotiationState

	// EstablishedTime is when this key became active (entered S_GENERATED_KEYS)
	EstablishedTime time.Time

	// MustNegotiate is the deadline by which key negotiation must complete.
	// If the key hasn't reached S_ACTIVE/S_GENERATED_KEYS by this time, the handshake
	// has timed out. This matches OpenVPN's key_state.must_negotiate in ssl_common.h:181.
	// Set to: now + handshake_window when negotiation starts.
	MustNegotiate time.Time

	// MustDie is the absolute time when this key must be destroyed.
	// Set when key moves to lame duck slot: MustDie = now + transition_window
	MustDie time.Time

	// BytesRead is the number of bytes decrypted with this key
	BytesRead int64

	// BytesWritten is the number of bytes encrypted with this key
	BytesWritten int64

	// PacketsRead is the number of packets decrypted with this key
	PacketsRead int64

	// PacketsWritten is the number of packets encrypted with this key
	PacketsWritten int64

	// RemoteSessionID is the peer's session ID associated with this key
	RemoteSessionID model.SessionID
}

// IsExpired returns true if the key has passed its must_die time.
func (ks *KeyState) IsExpired() bool {
	if ks == nil || ks.MustDie.IsZero() {
		return false
	}
	return time.Now().After(ks.MustDie)
}

// AddBytes increments the byte counters.
func (ks *KeyState) AddBytes(read, written int64) {
	if ks == nil {
		return
	}
	ks.BytesRead += read
	ks.BytesWritten += written
}

// AddPackets increments the packet counters.
func (ks *KeyState) AddPackets(read, written int64) {
	if ks == nil {
		return
	}
	ks.PacketsRead += read
	ks.PacketsWritten += written
}

// TotalBytes returns the total bytes processed by this key.
func (ks *KeyState) TotalBytes() int64 {
	if ks == nil {
		return 0
	}
	return ks.BytesRead + ks.BytesWritten
}

// TotalPackets returns the total packets processed by this key.
func (ks *KeyState) TotalPackets() int64 {
	if ks == nil {
		return 0
	}
	return ks.PacketsRead + ks.PacketsWritten
}

// Reset clears all counters and state, preparing the KeyState for reuse.
func (ks *KeyState) Reset() {
	if ks == nil {
		return
	}
	ks.Key = nil
	ks.KeyID = 0
	ks.State = model.S_UNDEF
	ks.EstablishedTime = time.Time{}
	ks.MustNegotiate = time.Time{}
	ks.MustDie = time.Time{}
	ks.BytesRead = 0
	ks.BytesWritten = 0
	ks.PacketsRead = 0
	ks.PacketsWritten = 0
	ks.RemoteSessionID = model.SessionID{}
}

// TimeUntilExpiry returns the duration until this key expires.
// Returns 0 if the key is already expired or has no expiry set.
func (ks *KeyState) TimeUntilExpiry() time.Duration {
	if ks == nil || ks.MustDie.IsZero() {
		return 0
	}
	remaining := time.Until(ks.MustDie)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// IsNegotiationTimedOut returns true if the key negotiation has exceeded its deadline.
// This matches OpenVPN's check: now >= ks->must_negotiate && ks->state < S_ACTIVE (ssl.c:2747)
func (ks *KeyState) IsNegotiationTimedOut() bool {
	if ks == nil || ks.MustNegotiate.IsZero() {
		return false
	}
	// Only timeout if we haven't completed negotiation yet
	if ks.State >= model.S_GENERATED_KEYS {
		return false
	}
	return time.Now().After(ks.MustNegotiate)
}

// SetNegotiationDeadline sets the must_negotiate deadline.
// Call this when starting key negotiation with the handshake window duration.
func (ks *KeyState) SetNegotiationDeadline(handshakeWindow time.Duration) {
	if ks == nil {
		return
	}
	ks.MustNegotiate = time.Now().Add(handshakeWindow)
}

// ClearNegotiationDeadline clears the must_negotiate deadline.
// Call this when negotiation completes successfully (state reaches S_ACTIVE/S_GENERATED_KEYS).
// This matches OpenVPN's ks->must_negotiate = 0 in ssl.c:2793.
func (ks *KeyState) ClearNegotiationDeadline() {
	if ks == nil {
		return
	}
	ks.MustNegotiate = time.Time{}
}
