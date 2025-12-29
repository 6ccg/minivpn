package reliabletransport

import (
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

func TestReliableTransport_IncomingControlResetsOnControlEpochChange(t *testing.T) {
	if testing.Verbose() {
		log.SetLevel(log.DebugLevel)
	}

	cfg := config.NewConfig(config.WithLogger(log.Log))
	workersManager := workers.NewManager(log.Log)
	sessionManager, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("session.NewManager() failed: %v", err)
	}

	remoteSessionID := newRandomSessionID()
	sessionManager.SetRemoteSessionID(remoteSessionID)

	dataOrControlToMuxer := make(chan *model.Packet, 16)
	controlToReliable := make(chan *model.Packet, 16)
	muxerToReliable := make(chan *model.Packet, 16)
	reliableToControl := make(chan *model.Packet, 16)

	svc := &Service{
		DataOrControlToMuxer: &dataOrControlToMuxer,
		ControlToReliable:    controlToReliable,
		MuxerToReliable:      muxerToReliable,
		ReliableToControl:    &reliableToControl,
	}
	svc.StartWorkers(cfg, workersManager, sessionManager)
	defer func() {
		workersManager.StartShutdown()
		workersManager.WaitWorkersShutdown()
	}()

	for _, id := range []model.PacketID{1, 2, 3} {
		muxerToReliable <- &model.Packet{
			Opcode:         model.P_CONTROL_V1,
			KeyID:          0,
			LocalSessionID: remoteSessionID,
			ID:             id,
			Payload:        []byte{0x01},
		}
	}

	deadline := time.After(1 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case <-reliableToControl:
		case <-deadline:
			t.Fatal("timed out waiting for initial control packets")
		}
	}

	if err := sessionManager.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset() failed: %v", err)
	}

	muxerToReliable <- &model.Packet{
		Opcode:         model.P_CONTROL_V1,
		KeyID:          byte(sessionManager.CurrentKeyID()),
		LocalSessionID: remoteSessionID,
		ID:             1,
		Payload:        []byte{0x02},
	}

	select {
	case p := <-reliableToControl:
		if p.Opcode != model.P_CONTROL_V1 || p.KeyID != byte(sessionManager.CurrentKeyID()) || p.ID != 1 {
			t.Fatalf("unexpected packet delivered: opcode=%s key_id=%d id=%d", p.Opcode, p.KeyID, p.ID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected control packet after ControlEpoch change")
	}
}
