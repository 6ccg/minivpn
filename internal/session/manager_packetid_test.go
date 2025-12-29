package session

import (
	"testing"

	"github.com/ooni/minivpn/internal/model"
)

func TestManager_LocalDataPacketID_PerKeyRotation(t *testing.T) {
	m := newTestMultikeyManager(t)

	// Pretend the initial key is established so outbound data uses KS_PRIMARY.
	m.MarkPrimaryKeyEstablished()

	pid1, err := m.LocalDataPacketID()
	if err != nil {
		t.Fatalf("LocalDataPacketID failed: %v", err)
	}
	pid2, err := m.LocalDataPacketID()
	if err != nil {
		t.Fatalf("LocalDataPacketID failed: %v", err)
	}
	if pid1 != 1 || pid2 != 2 {
		t.Fatalf("initial packet IDs = (%d, %d), want (1, 2)", pid1, pid2)
	}

	// Initiate key rotation: old primary becomes lame duck, new primary is not
	// established yet. Outbound data must keep using the lame-duck key counter.
	if err := m.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset failed: %v", err)
	}

	pid3, err := m.LocalDataPacketID()
	if err != nil {
		t.Fatalf("LocalDataPacketID failed: %v", err)
	}
	if pid3 != 3 {
		t.Fatalf("packet ID during rotation = %d, want 3", pid3)
	}

	// Now pretend the new primary key is established; packet IDs must restart
	// from 1 for the new key.
	m.MarkPrimaryKeyEstablished()

	pidNew1, err := m.LocalDataPacketID()
	if err != nil {
		t.Fatalf("LocalDataPacketID failed: %v", err)
	}
	if pidNew1 != 1 {
		t.Fatalf("packet ID after rotation = %d, want 1", pidNew1)
	}

	// The lame-duck key should have kept its counter.
	lameDuck := m.LameDuckKey()
	if lameDuck == nil {
		t.Fatal("lame duck key should exist after KeySoftReset")
	}
	if lameDuck.localDataPacketID != 4 {
		t.Fatalf("lame duck next packet ID = %d, want 4", lameDuck.localDataPacketID)
	}
}

func TestManager_DataPacketIDWrapFlag_IsPerKey(t *testing.T) {
	m := newTestMultikeyManager(t)
	m.MarkPrimaryKeyEstablished()

	// Force the current key to hit the wrap trigger threshold.
	m.mu.Lock()
	primary := m.keySlots[KS_PRIMARY]
	primary.localDataPacketID = packetIDWrapTrigger
	m.mu.Unlock()

	if _, err := m.LocalDataPacketID(); err != nil {
		t.Fatalf("LocalDataPacketID failed: %v", err)
	}
	if !m.IsDataPacketIDNearWrap() {
		t.Fatal("IsDataPacketIDNearWrap = false, want true")
	}

	// Start rotation: outbound still uses lame duck, so the flag remains true.
	if err := m.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset failed: %v", err)
	}
	if !m.IsDataPacketIDNearWrap() {
		t.Fatal("IsDataPacketIDNearWrap during rotation = false, want true")
	}

	// After the new key becomes established, we switch to its per-key wrap flag.
	m.MarkPrimaryKeyEstablished()
	if m.IsDataPacketIDNearWrap() {
		t.Fatal("IsDataPacketIDNearWrap after rotation = true, want false")
	}
}

func TestManager_ShouldRenegotiate_IncludesPacketIDWrapTrigger(t *testing.T) {
	m := newTestMultikeyManager(t)
	m.MarkPrimaryKeyEstablished()
	m.SetNegotiationState(model.S_GENERATED_KEYS)

	m.mu.Lock()
	primary := m.keySlots[KS_PRIMARY]
	primary.localDataPacketID = packetIDWrapTrigger
	m.mu.Unlock()

	if _, err := m.LocalDataPacketID(); err != nil {
		t.Fatalf("LocalDataPacketID failed: %v", err)
	}
	if !m.IsDataPacketIDNearWrap() {
		t.Fatal("IsDataPacketIDNearWrap = false, want true")
	}

	if !m.ShouldRenegotiate() {
		t.Fatal("ShouldRenegotiate = false, want true (wrap-trigger)")
	}
}
