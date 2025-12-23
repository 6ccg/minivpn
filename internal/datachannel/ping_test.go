package datachannel

import (
	"bytes"
	"testing"
)

// TestIsPingPacket tests the ping packet detection logic.
func TestIsPingPacket(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "valid ping packet",
			payload:  []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48},
			expected: true,
		},
		{
			name:     "wrong content but correct length",
			payload:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "too short",
			payload:  []byte{0x2a, 0x18, 0x7b, 0xf3},
			expected: false,
		},
		{
			name:     "too long",
			payload:  []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48, 0x00},
			expected: false,
		},
		{
			name:     "empty",
			payload:  []byte{},
			expected: false,
		},
		{
			name:     "nil",
			payload:  nil,
			expected: false,
		},
		{
			name:     "real ICMP-like 16 bytes (not ping)",
			payload:  []byte{0x45, 0x00, 0x00, 0x10, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPingPacket(tt.payload)
			if result != tt.expected {
				t.Errorf("IsPingPacket(%v) = %v, want %v", tt.payload, result, tt.expected)
			}
		})
	}
}

// TestPingPayload tests that PingPayload returns the correct signature.
func TestPingPayload(t *testing.T) {
	expected := []byte{
		0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
		0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
	}

	payload := PingPayload()

	if len(payload) != pingStringSize {
		t.Errorf("PingPayload() length = %d, want %d", len(payload), pingStringSize)
	}

	if !bytes.Equal(payload, expected) {
		t.Errorf("PingPayload() = %x, want %x", payload, expected)
	}

	// Verify that modifying the returned slice doesn't affect the original
	payload[0] = 0xFF
	payload2 := PingPayload()
	if payload2[0] != expected[0] {
		t.Error("PingPayload() returns mutable reference to internal data")
	}
}

// TestPingPayloadIsPing verifies that PingPayload output is detected as ping.
func TestPingPayloadIsPing(t *testing.T) {
	payload := PingPayload()
	if !IsPingPacket(payload) {
		t.Error("IsPingPacket(PingPayload()) should return true")
	}
}
