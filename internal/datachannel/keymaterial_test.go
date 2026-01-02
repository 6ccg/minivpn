package datachannel

import (
	"testing"

	"github.com/6ccg/minivpn/internal/model"
)

func TestNewKeyMaterial(t *testing.T) {
	km := NewKeyMaterial(5)

	if km.KeyID() != 5 {
		t.Errorf("KeyID() = %d, want 5", km.KeyID())
	}
	if km.Ready() {
		t.Error("newly created KeyMaterial should not be ready")
	}
}

func TestKeyMaterial_SetReady(t *testing.T) {
	km := NewKeyMaterial(1)

	if km.Ready() {
		t.Error("newly created KeyMaterial should not be ready")
	}

	km.SetReady(true)
	if !km.Ready() {
		t.Error("KeyMaterial should be ready after SetReady(true)")
	}

	km.SetReady(false)
	if km.Ready() {
		t.Error("KeyMaterial should not be ready after SetReady(false)")
	}
}

func TestKeyMaterial_Clear(t *testing.T) {
	km := NewKeyMaterial(3)
	km.SetReady(true)

	// Set some non-zero values
	km.cipherKeyLocal[0] = 0xFF
	km.cipherKeyRemote[0] = 0xFF
	km.hmacKeyLocal[0] = 0xFF
	km.hmacKeyRemote[0] = 0xFF

	km.Clear()

	if km.Ready() {
		t.Error("KeyMaterial should not be ready after Clear()")
	}
	if km.cipherKeyLocal[0] != 0 {
		t.Error("cipherKeyLocal should be zeroed after Clear()")
	}
	if km.cipherKeyRemote[0] != 0 {
		t.Error("cipherKeyRemote should be zeroed after Clear()")
	}
	if km.hmacKeyLocal[0] != 0 {
		t.Error("hmacKeyLocal should be zeroed after Clear()")
	}
	if km.hmacKeyRemote[0] != 0 {
		t.Error("hmacKeyRemote should be zeroed after Clear()")
	}
	if km.hmacLocal != nil {
		t.Error("hmacLocal should be nil after Clear()")
	}
	if km.hmacRemote != nil {
		t.Error("hmacRemote should be nil after Clear()")
	}
	if km.replayFilter != nil {
		t.Error("replayFilter should be nil after Clear()")
	}
}

func TestKeyMaterial_CheckReplay_NilFilter(t *testing.T) {
	km := NewKeyMaterial(0)

	// With nil replay filter, should always return nil (no error)
	err := km.CheckReplay(1)
	if err != nil {
		t.Errorf("CheckReplay with nil filter should return nil, got %v", err)
	}
}

func TestKeyMaterial_ConcurrentAccess(t *testing.T) {
	km := NewKeyMaterial(0)

	// Test concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = km.Ready()
			_ = km.KeyID()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestKeyMaterial_KeySlots(t *testing.T) {
	km := NewKeyMaterial(1)

	// Set some values
	km.mu.Lock()
	km.cipherKeyLocal[0] = 0x01
	km.cipherKeyLocal[1] = 0x02
	km.cipherKeyRemote[0] = 0x03
	km.hmacKeyLocal[0] = 0x04
	km.hmacKeyRemote[0] = 0x05
	km.mu.Unlock()

	// Test getters
	localCipher := km.GetCipherKeyLocal()
	if localCipher[0] != 0x01 || localCipher[1] != 0x02 {
		t.Error("GetCipherKeyLocal returned wrong values")
	}

	remoteCipher := km.GetCipherKeyRemote()
	if remoteCipher[0] != 0x03 {
		t.Error("GetCipherKeyRemote returned wrong value")
	}

	localHmac := km.GetHmacKeyLocal()
	if localHmac[0] != 0x04 {
		t.Error("GetHmacKeyLocal returned wrong value")
	}

	remoteHmac := km.GetHmacKeyRemote()
	if remoteHmac[0] != 0x05 {
		t.Error("GetHmacKeyRemote returned wrong value")
	}
}

// TestKeyMaterial_IndependentReplayFilters verifies that each KeyMaterial has
// its own independent replay filter, matching OpenVPN's behavior where each
// key_state has its own packet_id_rec.
//
// This is critical for key rotation: when a new key is established, packets
// using the new key start with packet ID 1. If replay filters were shared,
// packet ID 1 would be rejected as a replay since it was already seen with
// the old key.
func TestKeyMaterial_IndependentReplayFilters(t *testing.T) {
	// Create two KeyMaterial instances (simulating primary and lame duck keys)
	km1 := NewKeyMaterial(0)
	km2 := NewKeyMaterial(1)

	// Initialize replay filters for both (simulating DeriveKeys behavior)
	km1.mu.Lock()
	km1.replayFilter = newReplayFilter(DefaultSeqBacktrack, true) // UDP mode
	km1.mu.Unlock()

	km2.mu.Lock()
	km2.replayFilter = newReplayFilter(DefaultSeqBacktrack, true) // UDP mode
	km2.mu.Unlock()

	// Accept packet ID 1 on km1
	err := km1.CheckReplay(1)
	if err != nil {
		t.Fatalf("km1.CheckReplay(1) should succeed, got: %v", err)
	}

	// Accept packet ID 1 on km2 - this should also succeed because
	// km2 has its own independent replay filter
	err = km2.CheckReplay(1)
	if err != nil {
		t.Fatalf("km2.CheckReplay(1) should succeed (independent filter), got: %v", err)
	}

	// Verify replay detection still works within each filter
	err = km1.CheckReplay(1)
	if err == nil {
		t.Error("km1.CheckReplay(1) should fail on second attempt (replay)")
	}

	err = km2.CheckReplay(1)
	if err == nil {
		t.Error("km2.CheckReplay(1) should fail on second attempt (replay)")
	}

	// Accept sequential packet IDs on each filter independently
	// km1: 2, 3, 4
	for i := model.PacketID(2); i <= 4; i++ {
		if err := km1.CheckReplay(i); err != nil {
			t.Fatalf("km1.CheckReplay(%d) should succeed, got: %v", i, err)
		}
	}

	// km2: 2, 3, 4 - should also succeed because km2 has independent filter
	for i := model.PacketID(2); i <= 4; i++ {
		if err := km2.CheckReplay(i); err != nil {
			t.Fatalf("km2.CheckReplay(%d) should succeed (independent filter), got: %v", i, err)
		}
	}

	// Verify each filter rejects its own replays
	if err := km1.CheckReplay(3); err == nil {
		t.Error("km1 should reject replay of packet 3")
	}
	if err := km2.CheckReplay(3); err == nil {
		t.Error("km2 should reject replay of packet 3")
	}
}

// TestKeyMaterial_ReplayFilterKeyRotation simulates a key rotation scenario
// to verify that per-key replay filters work correctly during transition.
func TestKeyMaterial_ReplayFilterKeyRotation(t *testing.T) {
	// Simulate the scenario:
	// 1. Primary key (km_old) has been receiving packets (IDs 1-1000)
	// 2. Key rotation happens: km_old becomes lame duck, km_new becomes primary
	// 3. km_new should accept packets starting from ID 1

	km_old := NewKeyMaterial(0)
	km_old.mu.Lock()
	km_old.replayFilter = newReplayFilter(DefaultSeqBacktrack, true)
	km_old.mu.Unlock()

	// Simulate old key receiving packets 1-100
	for i := model.PacketID(1); i <= 100; i++ {
		err := km_old.CheckReplay(i)
		if err != nil {
			t.Fatalf("km_old.CheckReplay(%d) failed: %v", i, err)
		}
	}

	// Key rotation: create new key
	km_new := NewKeyMaterial(1)
	km_new.mu.Lock()
	km_new.replayFilter = newReplayFilter(DefaultSeqBacktrack, true)
	km_new.mu.Unlock()

	// New key should accept packets starting from 1
	// This would fail if replay filters were shared!
	for i := model.PacketID(1); i <= 50; i++ {
		err := km_new.CheckReplay(i)
		if err != nil {
			t.Fatalf("km_new.CheckReplay(%d) should succeed (new key, new filter), got: %v", i, err)
		}
	}

	// Old key (lame duck) should still work for in-flight packets
	// Packets 101-150 arriving late on old key
	for i := model.PacketID(101); i <= 150; i++ {
		err := km_old.CheckReplay(i)
		if err != nil {
			t.Fatalf("km_old.CheckReplay(%d) should succeed, got: %v", i, err)
		}
	}

	// Verify both keys still reject replays
	if err := km_old.CheckReplay(50); err == nil {
		t.Error("km_old should reject replay of packet 50")
	}
	if err := km_new.CheckReplay(25); err == nil {
		t.Error("km_new should reject replay of packet 25")
	}
}

