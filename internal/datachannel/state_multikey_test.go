package datachannel

import (
	"testing"

	"github.com/6ccg/minivpn/internal/session"
)

func TestDataChannelState_GetKeyMaterialByID(t *testing.T) {
	dcs := &dataChannelState{}

	// Set up key materials
	km0 := NewKeyMaterial(0)
	km0.SetReady(true)
	km1 := NewKeyMaterial(1)
	km1.SetReady(true)

	dcs.keys[session.KS_PRIMARY] = km0
	dcs.keys[session.KS_LAME_DUCK] = km1

	// Find by ID
	km, slot := dcs.GetKeyMaterialByID(0)
	if km == nil {
		t.Error("should find key with ID 0")
	}
	if slot != session.KS_PRIMARY {
		t.Errorf("slot = %d, want %d", slot, session.KS_PRIMARY)
	}

	km, slot = dcs.GetKeyMaterialByID(1)
	if km == nil {
		t.Error("should find key with ID 1")
	}
	if slot != session.KS_LAME_DUCK {
		t.Errorf("slot = %d, want %d", slot, session.KS_LAME_DUCK)
	}

	// Non-existent ID
	km, slot = dcs.GetKeyMaterialByID(5)
	if km != nil {
		t.Error("should return nil for non-existent key")
	}
	if slot != -1 {
		t.Errorf("slot = %d, want -1", slot)
	}
}

func TestDataChannelState_GetKeyMaterialByID_NotReady(t *testing.T) {
	dcs := &dataChannelState{}

	// Set up key material that's not ready
	km := NewKeyMaterial(0)
	km.SetReady(false)
	dcs.keys[session.KS_PRIMARY] = km

	// Should not find non-ready key
	found, _ := dcs.GetKeyMaterialByID(0)
	if found != nil {
		t.Error("should not find non-ready key")
	}
}

func TestDataChannelState_SetKeyMaterial(t *testing.T) {
	dcs := &dataChannelState{}

	km := NewKeyMaterial(5)
	dcs.SetKeyMaterial(session.KS_PRIMARY, km)

	if dcs.keys[session.KS_PRIMARY] != km {
		t.Error("SetKeyMaterial should set the key material")
	}

	// Test invalid slot - should be a no-op
	dcs.SetKeyMaterial(-1, km)
	dcs.SetKeyMaterial(session.KS_SIZE, km)
}

func TestDataChannelState_ClearSlot(t *testing.T) {
	dcs := &dataChannelState{}

	km := NewKeyMaterial(0)
	km.SetReady(true)
	km.cipherKeyLocal[0] = 0xFF
	dcs.keys[session.KS_LAME_DUCK] = km

	dcs.ClearSlot(session.KS_LAME_DUCK)

	if dcs.keys[session.KS_LAME_DUCK] != nil {
		t.Error("ClearSlot should set slot to nil")
	}

	// Verify the key material was cleared
	if km.cipherKeyLocal[0] != 0 {
		t.Error("ClearSlot should zero out key material")
	}
	if km.Ready() {
		t.Error("ClearSlot should mark key as not ready")
	}
}

func TestDataChannelState_ClearSlot_InvalidSlot(t *testing.T) {
	dcs := &dataChannelState{}

	// Should be no-op for invalid slots
	dcs.ClearSlot(-1)
	dcs.ClearSlot(session.KS_SIZE)
	dcs.ClearSlot(100)
}

func TestDataChannelState_ActiveKeyMaterial(t *testing.T) {
	dcs := &dataChannelState{}

	// No key set
	if dcs.ActiveKeyMaterial() != nil {
		t.Error("ActiveKeyMaterial should return nil when no key set")
	}

	// Set primary key
	km := NewKeyMaterial(0)
	dcs.keys[session.KS_PRIMARY] = km
	dcs.activeSlot = session.KS_PRIMARY

	if dcs.ActiveKeyMaterial() != km {
		t.Error("ActiveKeyMaterial should return the primary key")
	}
}

func TestDataChannelState_KeyMaterialAt(t *testing.T) {
	dcs := &dataChannelState{}

	km := NewKeyMaterial(1)
	dcs.keys[session.KS_LAME_DUCK] = km

	// Valid slot
	if dcs.KeyMaterialAt(session.KS_LAME_DUCK) != km {
		t.Error("KeyMaterialAt should return the key at the slot")
	}

	// Invalid slots
	if dcs.KeyMaterialAt(-1) != nil {
		t.Error("KeyMaterialAt should return nil for negative slot")
	}
	if dcs.KeyMaterialAt(session.KS_SIZE) != nil {
		t.Error("KeyMaterialAt should return nil for out-of-bounds slot")
	}
}
