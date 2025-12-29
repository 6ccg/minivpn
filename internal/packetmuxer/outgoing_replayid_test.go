package packetmuxer

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

func TestMoveDownWorker_ControlRetransmitUsesFreshReplayID(t *testing.T) {
	opts := &config.OpenVPNOptions{TLSAuth: []byte(ovpnStaticKeyAuth)}
	sm, logger := newTestSessionManager(t, opts)

	dataOrControlToMuxer := make(chan *model.Packet, 2)
	muxerToNetwork := make(chan []byte, 2)

	ws := &workersState{
		logger:               logger,
		dataOrControlToMuxer: dataOrControlToMuxer,
		muxerToNetwork:       muxerToNetwork,
		sessionManager:       sm,
		workersManager:       workers.NewManager(logger),
	}

	ws.workersManager.StartWorker(ws.moveDownWorker)
	t.Cleanup(func() {
		ws.workersManager.StartShutdown()
		ws.workersManager.WaitWorkersShutdown()
	})

	// Create one control packet and send it twice to simulate reliable transport retransmission.
	packet, err := sm.NewPacket(model.P_CONTROL_V1, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("session.Manager.NewPacket() failed: %v", err)
	}
	dataOrControlToMuxer <- packet
	dataOrControlToMuxer <- packet

	var raw1, raw2 []byte
	select {
	case raw1 = <-muxerToNetwork:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first outgoing packet")
	}
	select {
	case raw2 = <-muxerToNetwork:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for second outgoing packet")
	}

	// TLS-AUTH format: header(9) || hmac(digest) || replay(8) || ctrl.
	digestSize := sm.PacketAuth().TLSAuthDigest.Size()
	if digestSize == 0 {
		digestSize = 20
	}
	off := 9 + digestSize
	if len(raw1) < off+8 || len(raw2) < off+8 {
		t.Fatalf("serialized packets too short for tls-auth replay fields (len1=%d len2=%d)", len(raw1), len(raw2))
	}
	replay1 := binary.BigEndian.Uint32(raw1[off : off+4])
	replay2 := binary.BigEndian.Uint32(raw2[off : off+4])
	if replay1 == replay2 {
		t.Fatalf("expected replay_id to change across retransmits, got %d then %d", replay1, replay2)
	}
	if replay2 <= replay1 {
		t.Fatalf("expected replay_id to increase across retransmits, got %d then %d", replay1, replay2)
	}
}
