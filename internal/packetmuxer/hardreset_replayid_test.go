package packetmuxer

import (
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/wire"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

func TestStartHardReset_RetransmissionUsesFreshReplayID(t *testing.T) {
	opts := &config.OpenVPNOptions{TLSAuth: []byte(ovpnStaticKeyAuth)}
	sm, logger := newTestSessionManager(t, opts)

	muxerToNetwork := make(chan []byte, 2)
	ws := &workersState{
		logger:          logger,
		hardResetTicker: time.NewTicker(longWakeup),
		handshakeTimer:  time.NewTimer(longWakeup),
		muxerToNetwork:  muxerToNetwork,
		sessionManager:  sm,
		tracer:          &model.DummyTracer{},
		workersManager:  workers.NewManager(logger),
	}
	t.Cleanup(func() {
		ws.hardResetTicker.Stop()
		if ws.handshakeTimer != nil {
			ws.handshakeTimer.Stop()
		}
	})

	if err := ws.startHardReset(); err != nil {
		t.Fatalf("startHardReset (first) failed: %v", err)
	}
	raw1 := <-muxerToNetwork
	p1, err := wire.UnmarshalPacket(raw1, sm.PacketAuth())
	if err != nil {
		t.Fatalf("wire.UnmarshalPacket (first) failed: %v", err)
	}

	if err := ws.startHardReset(); err != nil {
		t.Fatalf("startHardReset (retransmit) failed: %v", err)
	}
	raw2 := <-muxerToNetwork
	p2, err := wire.UnmarshalPacket(raw2, sm.PacketAuth())
	if err != nil {
		t.Fatalf("wire.UnmarshalPacket (retransmit) failed: %v", err)
	}

	if p1.ReplayPacketID == p2.ReplayPacketID {
		t.Fatalf("expected hard reset replay-id to change across retransmits, got %d then %d", p1.ReplayPacketID, p2.ReplayPacketID)
	}
	if p2.ReplayPacketID <= p1.ReplayPacketID {
		t.Fatalf("expected hard reset replay-id to increase: %d -> %d", p1.ReplayPacketID, p2.ReplayPacketID)
	}
}
