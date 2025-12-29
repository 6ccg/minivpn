package session

import (
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/pkg/config"
)

func newTestMultikeyManager(t *testing.T) *Manager {
	t.Helper()
	opts := &config.OpenVPNOptions{
		RenegotiateSeconds: 3600,
		RenegotiateBytes:   -1,
		RenegotiatePackets: 0,
		TransitionWindow:   60,
	}
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(opts),
		config.WithLogger(&mockLogger{}),
		config.WithHandshakeTracer(&mockTracer{}),
	)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	return m
}

func TestManager_KeySoftReset_NoPrimaryKey(t *testing.T) {
	m := newTestMultikeyManager(t)

	// Clear the primary key slot (NewManager initializes it)
	m.mu.Lock()
	m.keySlots[KS_PRIMARY] = nil
	m.mu.Unlock()

	// KeySoftReset should fail if no primary key exists
	err := m.KeySoftReset()
	if err == nil {
		t.Error("KeySoftReset should fail when no primary key exists")
	}
}

func TestManager_KeySoftReset_Success(t *testing.T) {
	m := newTestMultikeyManager(t)

	// Get the initial primary key ID
	m.mu.Lock()
	initialKeyID := m.keySlots[KS_PRIMARY].KeyID
	m.keySlots[KS_PRIMARY].EstablishedTime = time.Now().Add(-time.Hour)
	m.keySlots[KS_PRIMARY].BytesRead = 1000
	m.keySlots[KS_PRIMARY].BytesWritten = 2000
	m.mu.Unlock()

	// Perform soft reset
	err := m.KeySoftReset()
	if err != nil {
		t.Errorf("KeySoftReset failed: %v", err)
	}

	// Verify lame duck key was set with the old primary key
	lameDuck := m.LameDuckKey()
	if lameDuck == nil {
		t.Error("lame duck key should be set after KeySoftReset")
	}
	if lameDuck.KeyID != initialKeyID {
		t.Errorf("lame duck KeyID = %d, want %d", lameDuck.KeyID, initialKeyID)
	}
	if lameDuck.MustDie.IsZero() {
		t.Error("lame duck MustDie should be set")
	}
	if lameDuck.BytesRead != 1000 {
		t.Errorf("lame duck BytesRead = %d, want 1000", lameDuck.BytesRead)
	}

	// Primary slot should have a NEW key state (created by KeySoftReset)
	primary := m.PrimaryKey()
	if primary == nil {
		t.Error("primary key should exist after KeySoftReset")
	} else if primary.KeyID == initialKeyID {
		t.Error("primary key should have a new key ID after KeySoftReset")
	}
}

func TestManager_KeyByID(t *testing.T) {
	m := newTestMultikeyManager(t)

	// Set up keys with different IDs
	m.mu.Lock()
	m.keySlots[KS_PRIMARY] = &KeyState{
		Key:   &DataChannelKey{},
		KeyID: 3,
		State: model.S_GENERATED_KEYS,
	}
	m.keySlots[KS_LAME_DUCK] = &KeyState{
		Key:   &DataChannelKey{},
		KeyID: 2,
		State: model.S_GENERATED_KEYS,
	}
	m.mu.Unlock()

	// Find primary key
	ks := m.KeyByID(3)
	if ks == nil {
		t.Error("KeyByID should find key with ID 3")
	}
	if ks.KeyID != 3 {
		t.Errorf("KeyID = %d, want 3", ks.KeyID)
	}

	// Find lame duck key
	ks = m.KeyByID(2)
	if ks == nil {
		t.Error("KeyByID should find key with ID 2")
	}
	if ks.KeyID != 2 {
		t.Errorf("KeyID = %d, want 2", ks.KeyID)
	}

	// Non-existent key
	ks = m.KeyByID(5)
	if ks != nil {
		t.Error("KeyByID should return nil for non-existent key")
	}
}

func TestManager_CheckAndExpireLameDuck(t *testing.T) {
	m := newTestMultikeyManager(t)

	// No lame duck - should return false
	if m.CheckAndExpireLameDuck() {
		t.Error("CheckAndExpireLameDuck should return false when no lame duck")
	}

	// Set up expired lame duck
	m.mu.Lock()
	m.keySlots[KS_LAME_DUCK] = &KeyState{
		Key:     &DataChannelKey{},
		KeyID:   1,
		MustDie: time.Now().Add(-time.Second), // already expired
	}
	m.mu.Unlock()

	// Should expire and return true
	if !m.CheckAndExpireLameDuck() {
		t.Error("CheckAndExpireLameDuck should return true for expired lame duck")
	}

	// Lame duck should be cleared
	if m.LameDuckKey() != nil {
		t.Error("lame duck should be nil after expiry")
	}
}

func TestManager_CheckAndExpireLameDuck_NotExpired(t *testing.T) {
	m := newTestMultikeyManager(t)

	// Set up non-expired lame duck
	m.mu.Lock()
	m.keySlots[KS_LAME_DUCK] = &KeyState{
		Key:     &DataChannelKey{},
		KeyID:   1,
		MustDie: time.Now().Add(time.Hour), // future
	}
	m.mu.Unlock()

	// Should return false
	if m.CheckAndExpireLameDuck() {
		t.Error("CheckAndExpireLameDuck should return false for non-expired lame duck")
	}

	// Lame duck should still exist
	if m.LameDuckKey() == nil {
		t.Error("lame duck should still exist")
	}
}

func TestManager_AddKeyBytes(t *testing.T) {
	m := newTestMultikeyManager(t)

	// Set up primary key
	m.mu.Lock()
	m.keySlots[KS_PRIMARY] = &KeyState{
		Key:   &DataChannelKey{},
		KeyID: 0,
	}
	m.mu.Unlock()

	// Add bytes
	m.AddKeyBytes(KS_PRIMARY, 100, 200)

	primary := m.PrimaryKey()
	if primary.BytesRead != 100 {
		t.Errorf("BytesRead = %d, want 100", primary.BytesRead)
	}
	if primary.BytesWritten != 200 {
		t.Errorf("BytesWritten = %d, want 200", primary.BytesWritten)
	}
}

func TestManager_AddKeyPackets(t *testing.T) {
	m := newTestMultikeyManager(t)

	// Set up primary key
	m.mu.Lock()
	m.keySlots[KS_PRIMARY] = &KeyState{
		Key:   &DataChannelKey{},
		KeyID: 0,
	}
	m.mu.Unlock()

	// Add packets
	m.AddKeyPackets(KS_PRIMARY, 10, 20)

	primary := m.PrimaryKey()
	if primary.PacketsRead != 10 {
		t.Errorf("PacketsRead = %d, want 10", primary.PacketsRead)
	}
	if primary.PacketsWritten != 20 {
		t.Errorf("PacketsWritten = %d, want 20", primary.PacketsWritten)
	}
}

func TestManager_ShouldRenegotiate_Packets(t *testing.T) {
	opts := &config.OpenVPNOptions{
		RenegotiateSeconds: 0,  // disable time-based
		RenegotiateBytes:   -1, // disable bytes-based
		RenegotiatePackets: 100,
		TransitionWindow:   60,
	}
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(opts),
		config.WithLogger(&mockLogger{}),
		config.WithHandshakeTracer(&mockTracer{}),
	)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Set up state to allow renegotiation check
	m.mu.Lock()
	m.negState = model.S_GENERATED_KEYS
	m.keyEstablishedTime = time.Now().Add(-time.Minute)
	m.keySlots[KS_PRIMARY].PacketsRead = 50
	m.keySlots[KS_PRIMARY].PacketsWritten = 40 // total = 90
	m.mu.Unlock()

	// Should not trigger yet (90 < 100)
	if m.ShouldRenegotiate() {
		t.Error("ShouldRenegotiate should return false when below threshold")
	}

	// Clear renegotiation requested flag and add more packets to exceed threshold
	m.mu.Lock()
	m.renegotiationRequested = false
	m.keySlots[KS_PRIMARY].PacketsRead = 65 // total = 105
	m.mu.Unlock()

	// Should trigger now
	if !m.ShouldRenegotiate() {
		t.Error("ShouldRenegotiate should return true when above threshold")
	}
}

func TestManager_LameDuckWakeup(t *testing.T) {
	m := newTestMultikeyManager(t)

	// No lame duck - should return 0
	wakeup := m.LameDuckWakeup()
	if wakeup != 0 {
		t.Errorf("LameDuckWakeup = %v, want 0 when no lame duck", wakeup)
	}

	// Set up lame duck expiring in 30 seconds
	m.mu.Lock()
	m.keySlots[KS_LAME_DUCK] = &KeyState{
		Key:     &DataChannelKey{},
		KeyID:   1,
		MustDie: time.Now().Add(30 * time.Second),
	}
	m.mu.Unlock()

	wakeup = m.LameDuckWakeup()
	if wakeup > 31*time.Second || wakeup < 29*time.Second {
		t.Errorf("LameDuckWakeup = %v, want ~30s", wakeup)
	}
}

func TestManager_DataKeyID_SoftResetPrefersLameDuckUntilPrimaryEstablished(t *testing.T) {
	m := newTestMultikeyManager(t)

	// Simulate initial key establishment.
	m.MarkPrimaryKeyEstablished()
	if got := m.DataKeyID(); got != 0 {
		t.Fatalf("DataKeyID() = %d, want 0 before rotation", got)
	}

	// Rotate keys (soft reset): key_id advances, but data key must remain on the
	// established lame duck until the new primary is established.
	if err := m.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset failed: %v", err)
	}
	if got := m.CurrentKeyID(); got == 0 {
		t.Fatalf("CurrentKeyID() = %d, want non-zero after rotation", got)
	}
	if got := m.DataKeyID(); got != 0 {
		t.Fatalf("DataKeyID() = %d, want 0 during rotation (lame duck)", got)
	}

	// When the new primary reaches S_GENERATED_KEYS, data key must switch.
	m.MarkPrimaryKeyEstablished()
	if got, want := m.DataKeyID(), m.CurrentKeyID(); got != want {
		t.Fatalf("DataKeyID() = %d, want %d after primary established", got, want)
	}
}
