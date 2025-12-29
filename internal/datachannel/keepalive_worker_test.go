package datachannel

import (
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

func TestKeepaliveWorker_PingResetsOnOutgoingActivity(t *testing.T) {
	sessionManager := makeTestingSession()
	sessionManager.SetPingOptions(1, 0, 0) // ping=1s, no ping-restart/ping-exit

	dc := &DataChannel{
		log:            log.Log,
		options:        &config.OpenVPNOptions{Compress: config.CompressionEmpty},
		sessionManager: sessionManager,
		state:          makeTestingStateNonAEAD(),
		encryptEncodeFn: func(_ model.Logger, padded []byte, _ *session.Manager, _ *dataChannelState) ([]byte, error) {
			return append([]byte(nil), padded...), nil
		},
	}

	out := make(chan *model.Packet, 8)
	workersManager := workers.NewManager(log.Log)

	ws := &workersState{
		dataChannel:          dc,
		dataOrControlToMuxer: out,
		logger:               log.Log,
		sessionManager:       sessionManager,
		workersManager:       workersManager,
	}

	firstKeyReady := make(chan any)
	close(firstKeyReady)

	workersManager.StartWorker(func() { ws.keepaliveWorker(firstKeyReady) })
	t.Cleanup(func() {
		workersManager.StartShutdown()
		workersManager.WaitWorkersShutdown()
	})

	time.Sleep(400 * time.Millisecond)
	sessionManager.NotifyOutgoingPacket()

	select {
	case <-out:
		t.Fatalf("unexpected ping before inactivity interval elapsed")
	case <-time.After(700 * time.Millisecond):
		// No ping should be sent yet: activity reset the timer.
	}

	select {
	case <-out:
		// Ping sent after inactivity interval.
	case <-time.After(900 * time.Millisecond):
		t.Fatalf("expected ping after inactivity interval elapsed")
	}
}
