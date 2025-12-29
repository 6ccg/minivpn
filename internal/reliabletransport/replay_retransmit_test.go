package reliabletransport

import (
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	vpnconfig "github.com/ooni/minivpn/pkg/config"
)

const ovpnStaticKeyCrypt = `
-----BEGIN OpenVPN Static key V1-----
f077aa700c7e2cb73d6fb0d13593a169
73b8ccbe725d637bb9d536b3e2871082
47bb9509ff55b9a9e96fb808e651d7a4
d41ec6709bb2544dfa6b821da1a24779
bef28bd707cc07f3aea76f9c6982b6e4
66c35fcbf78cd31db0a6e4f5d92400cc
75018b8fe1448fb6a06e3274d561fed0
ae518aa6d64a1ee61399ed9c8e29179a
25d5aab3fee1bb36f77e0d78c99892f3
6d59f42be49ba971920cb356d582f51c
b716da710009a37a6cb6e70c5ca782a0
e1edd17445bea1c8f330c653511a8621
4fd5f432c1b35bb8f6114b8f31213fb9
37d370d2aa00c355bfe0f03ad64a323a
6e0afca660f6c2517c61ddbc13f7cebf
1f9386c6de7c79bc652d3fd418b9ad45
-----END OpenVPN Static key V1-----
`

func TestBlockOnTryingToSend_RetransmissionClonesInFlightPacket(t *testing.T) {
	logger := newTestLogger(1024)
	workersManager := workers.NewManager(logger)

	cfg := vpnconfig.NewConfig(
		vpnconfig.WithLogger(logger),
		vpnconfig.WithOpenVPNOptions(&vpnconfig.OpenVPNOptions{
			TLSCrypt: []byte(ovpnStaticKeyCrypt),
		}),
	)
	sessionManager, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	out := make(chan *model.Packet, 2)
	ws := &workersState{
		dataOrControlToMuxer: out,
		incomingSeen:         make(chan incomingPacketSeen, 1),
		logger:               logger,
		sessionManager:       sessionManager,
		tracer:               &model.DummyTracer{},
		workersManager:       workersManager,
	}

	sender := newReliableSender(logger, make(chan incomingPacketSeen, 1))
	packet, err := sessionManager.NewPacket(model.P_CONTROL_V1, []byte("payload"))
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}
	if !sender.TryInsertOutgoingPacket(packet) {
		t.Fatalf("TryInsertOutgoingPacket: expected insert to succeed")
	}
	if len(sender.inFlight) != 1 {
		t.Fatalf("expected one in-flight packet, got %d", len(sender.inFlight))
	}

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	// Ensure we have ACKs to piggyback so a retransmission would mutate the
	// outgoing packet if we were reusing the in-flight pointer.
	sender.pendingACKsToSend = newACKSet(1)

	// First send.
	sender.inFlight[0].deadline = time.Now().Add(-time.Second)
	ws.blockOnTryingToSend(sender, ticker)
	p1 := <-out
	id1 := p1.ID

	// Force a retransmission of the same reliable packet.
	sender.inFlight[0].deadline = time.Now().Add(-time.Second)
	ws.blockOnTryingToSend(sender, ticker)
	p2 := <-out
	id2 := p2.ID

	if p1 == p2 {
		t.Fatalf("expected retransmission to clone the in-flight packet (got same pointer)")
	}
	if id1 != id2 {
		t.Fatalf("expected retransmission to keep packet ID stable: %d != %d", id1, id2)
	}
	if len(packet.ACKs) != 0 {
		t.Fatalf("expected in-flight packet to stay immutable (ACKs mutated to %v)", packet.ACKs)
	}
}
