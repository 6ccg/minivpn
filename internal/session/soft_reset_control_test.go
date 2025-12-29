package session

import (
	"testing"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/pkg/config"
)

func TestKeySoftReset_ResetsControlPacketID(t *testing.T) {
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{}),
		config.WithLogger(&mockLogger{}),
		config.WithHandshakeTracer(&mockTracer{}),
	)

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Bump control packet IDs to a non-trivial value.
	for i := 0; i < 5; i++ {
		p, err := mgr.NewPacket(model.P_CONTROL_V1, []byte("x"))
		if err != nil {
			t.Fatalf("NewPacket(P_CONTROL_V1): %v", err)
		}
		p.Free()
	}

	if err := mgr.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset: %v", err)
	}

	// In OpenVPN, key_state_init() reinitializes the per-key reliable layer,
	// resetting the control packet_id sequencing. We should restart from 1
	// (0 is reserved for hard-reset packets).
	p, err := mgr.NewPacket(model.P_CONTROL_SOFT_RESET_V1, nil)
	if err != nil {
		t.Fatalf("NewPacket(P_CONTROL_SOFT_RESET_V1): %v", err)
	}
	defer p.Free()
	if got, want := p.ID, model.PacketID(1); got != want {
		t.Fatalf("control packet ID after soft reset = %d, want %d", got, want)
	}
}
