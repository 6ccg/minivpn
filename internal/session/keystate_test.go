package session

import (
	"testing"
	"time"

	"github.com/6ccg/minivpn/internal/model"
)

func TestKeyState_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		ks       *KeyState
		expected bool
	}{
		{
			name:     "nil KeyState",
			ks:       nil,
			expected: false,
		},
		{
			name: "zero MustDie",
			ks: &KeyState{
				MustDie: time.Time{},
			},
			expected: false,
		},
		{
			name: "future MustDie",
			ks: &KeyState{
				MustDie: time.Now().Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "past MustDie",
			ks: &KeyState{
				MustDie: time.Now().Add(-time.Second),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ks.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestKeyState_Counters(t *testing.T) {
	ks := &KeyState{}

	// Test initial state
	if ks.TotalBytes() != 0 {
		t.Errorf("TotalBytes() = %d, want 0", ks.TotalBytes())
	}
	if ks.TotalPackets() != 0 {
		t.Errorf("TotalPackets() = %d, want 0", ks.TotalPackets())
	}

	// Test AddBytes
	ks.AddBytes(100, 200)
	if ks.BytesRead != 100 {
		t.Errorf("BytesRead = %d, want 100", ks.BytesRead)
	}
	if ks.BytesWritten != 200 {
		t.Errorf("BytesWritten = %d, want 200", ks.BytesWritten)
	}
	if ks.TotalBytes() != 300 {
		t.Errorf("TotalBytes() = %d, want 300", ks.TotalBytes())
	}

	// Test AddPackets
	ks.AddPackets(10, 20)
	if ks.PacketsRead != 10 {
		t.Errorf("PacketsRead = %d, want 10", ks.PacketsRead)
	}
	if ks.PacketsWritten != 20 {
		t.Errorf("PacketsWritten = %d, want 20", ks.PacketsWritten)
	}
	if ks.TotalPackets() != 30 {
		t.Errorf("TotalPackets() = %d, want 30", ks.TotalPackets())
	}
}

func TestKeyState_Reset(t *testing.T) {
	ks := &KeyState{
		Key:             &DataChannelKey{},
		KeyID:           5,
		State:           model.S_GENERATED_KEYS,
		EstablishedTime: time.Now(),
		MustDie:         time.Now().Add(time.Hour),
		BytesRead:       1000,
		BytesWritten:    2000,
		PacketsRead:     100,
		PacketsWritten:  200,
		RemoteSessionID: model.SessionID{1, 2, 3, 4, 5, 6, 7, 8},
	}

	ks.Reset()

	if ks.Key != nil {
		t.Error("Key should be nil after Reset")
	}
	if ks.KeyID != 0 {
		t.Errorf("KeyID = %d, want 0", ks.KeyID)
	}
	if ks.State != model.S_UNDEF {
		t.Errorf("State = %v, want S_UNDEF", ks.State)
	}
	if !ks.EstablishedTime.IsZero() {
		t.Error("EstablishedTime should be zero")
	}
	if !ks.MustDie.IsZero() {
		t.Error("MustDie should be zero")
	}
	if ks.BytesRead != 0 || ks.BytesWritten != 0 {
		t.Error("Byte counters should be zero")
	}
	if ks.PacketsRead != 0 || ks.PacketsWritten != 0 {
		t.Error("Packet counters should be zero")
	}
}

func TestKeyState_TimeUntilExpiry(t *testing.T) {
	tests := []struct {
		name     string
		ks       *KeyState
		wantZero bool
	}{
		{
			name:     "nil KeyState",
			ks:       nil,
			wantZero: true,
		},
		{
			name: "zero MustDie",
			ks: &KeyState{
				MustDie: time.Time{},
			},
			wantZero: true,
		},
		{
			name: "past MustDie",
			ks: &KeyState{
				MustDie: time.Now().Add(-time.Second),
			},
			wantZero: true,
		},
		{
			name: "future MustDie",
			ks: &KeyState{
				MustDie: time.Now().Add(time.Hour),
			},
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ks.TimeUntilExpiry()
			if tt.wantZero && got != 0 {
				t.Errorf("TimeUntilExpiry() = %v, want 0", got)
			}
			if !tt.wantZero && got <= 0 {
				t.Errorf("TimeUntilExpiry() = %v, want > 0", got)
			}
		})
	}
}

func TestKeyState_NilSafety(t *testing.T) {
	var ks *KeyState

	// All methods should be nil-safe
	ks.AddBytes(100, 200)
	ks.AddPackets(10, 20)
	ks.Reset()

	if ks.TotalBytes() != 0 {
		t.Error("TotalBytes on nil should return 0")
	}
	if ks.TotalPackets() != 0 {
		t.Error("TotalPackets on nil should return 0")
	}
	if ks.IsExpired() {
		t.Error("IsExpired on nil should return false")
	}
	if ks.TimeUntilExpiry() != 0 {
		t.Error("TimeUntilExpiry on nil should return 0")
	}
}
