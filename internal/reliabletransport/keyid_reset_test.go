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

func TestReliableTransport_IncomingControlResetsOnKeyIDChange(t *testing.T) {
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

	muxerToReliable <- &model.Packet{
		Opcode:         model.P_CONTROL_SOFT_RESET_V1,
		KeyID:          1,
		LocalSessionID: remoteSessionID,
		ID:             1,
		Payload:        []byte{},
	}

	select {
	case p := <-reliableToControl:
		if p.Opcode != model.P_CONTROL_SOFT_RESET_V1 || p.KeyID != 1 || p.ID != 1 {
			t.Fatalf("unexpected packet delivered: opcode=%s key_id=%d id=%d", p.Opcode, p.KeyID, p.ID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected SOFT_RESET packet after key_id change")
	}
}

func TestReliableTransport_IncomingControlResetsOnKeyIDChange_IDZero(t *testing.T) {
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

	// OpenVPN's per-key reliable layer restarts packet IDs, with the first packet
	// typically using ID=0 for the initial SOFT_RESET.
	muxerToReliable <- &model.Packet{
		Opcode:         model.P_CONTROL_SOFT_RESET_V1,
		KeyID:          1,
		LocalSessionID: remoteSessionID,
		ID:             0,
		Payload:        []byte{},
	}

	select {
	case p := <-reliableToControl:
		if p.Opcode != model.P_CONTROL_SOFT_RESET_V1 || p.KeyID != 1 || p.ID != 0 {
			t.Fatalf("unexpected packet delivered: opcode=%s key_id=%d id=%d", p.Opcode, p.KeyID, p.ID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected SOFT_RESET packet (id=0) after key_id change")
	}
}
