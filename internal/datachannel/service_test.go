package datachannel

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/6ccg/minivpn/internal/model"
	"github.com/6ccg/minivpn/internal/session"
	"github.com/6ccg/minivpn/internal/workers"
	"github.com/6ccg/minivpn/pkg/config"
)

type lockedLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *lockedLogger) append(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, msg)
}

func (l *lockedLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *lockedLogger) Debug(msg string)               { l.append(msg) }
func (l *lockedLogger) Debugf(format string, v ...any) { l.append(fmt.Sprintf(format, v...)) }
func (l *lockedLogger) Info(msg string)                { l.append(msg) }
func (l *lockedLogger) Infof(format string, v ...any)  { l.append(fmt.Sprintf(format, v...)) }
func (l *lockedLogger) Warn(msg string)                { l.append(msg) }
func (l *lockedLogger) Warnf(format string, v ...any)  { l.append(fmt.Sprintf(format, v...)) }

// test that we can start and stop the workers
func TestService_StartWorkers(t *testing.T) {
	dataToMuxer := make(chan *model.Packet, 100)
	keyReady := make(chan *session.DataChannelKey)
	muxerToData := make(chan *model.Packet, 100)

	s := Service{
		MuxerToData:          muxerToData,
		DataOrControlToMuxer: &dataToMuxer,
		TUNToData:            make(chan []byte, 100),
		DataToTUN:            make(chan []byte, 100),
		KeyReady:             keyReady,
	}
	logger := &lockedLogger{}
	workers := workers.NewManager(logger)
	session := makeTestingSession()

	opts := makeTestingOptions(t, "AES-128-GCM", "sha512")
	s.StartWorkers(config.NewConfig(config.WithOpenVPNOptions(opts), config.WithLogger(logger)), workers, session)

	keyReady <- makeTestingDataChannelKey()
	<-session.Ready
	muxerToData <- &model.Packet{Opcode: model.P_DATA_V1, Payload: []byte("aaaa")}
	muxerToData <- &model.Packet{Opcode: model.P_DATA_V1, Payload: []byte("bbbb")}
	workers.StartShutdown()
	workers.WaitWorkersShutdown()
}

func TestService_PingDisabledByDefault(t *testing.T) {
	dataToMuxer := make(chan *model.Packet, 100)
	keyReady := make(chan *session.DataChannelKey)
	muxerToData := make(chan *model.Packet, 100)

	s := Service{
		MuxerToData:          muxerToData,
		DataOrControlToMuxer: &dataToMuxer,
		TUNToData:            make(chan []byte, 100),
		DataToTUN:            make(chan []byte, 100),
		KeyReady:             keyReady,
	}
	logger := &lockedLogger{}
	workers := workers.NewManager(logger)
	session := makeTestingSession()

	opts := makeTestingOptions(t, "AES-128-GCM", "sha512")
	opts.Ping = 0
	cfg := config.NewConfig(config.WithOpenVPNOptions(opts), config.WithLogger(logger))
	s.StartWorkers(cfg, workers, session)

	keyReady <- makeTestingDataChannelKey()
	<-session.Ready
	workers.StartShutdown()
	workers.WaitWorkersShutdown()

	want := "datachannel: keepaliveWorker: started (ping=0s,"
	for _, line := range logger.snapshot() {
		if strings.Contains(line, want) {
			return
		}
	}
	t.Fatalf("expected log line containing %q; got:\n%s", want, strings.Join(logger.snapshot(), "\n"))
}

func TestWorkersState_TriggerRenegotiation_KeyIDAdvancesOnce(t *testing.T) {
	logger := &lockedLogger{}
	controlToReliable := make(chan *model.Packet, 1)
	notifyTLS := make(chan *model.Notification, 1)

	ws := &workersState{
		logger:            logger,
		workersManager:    workers.NewManager(logger),
		sessionManager:    makeTestingSession(),
		controlToReliable: controlToReliable,
		notifyTLS:         notifyTLS,
	}

	if ws.sessionManager.CurrentKeyID() != 0 {
		t.Fatalf("expected initial key_id=0, got %d", ws.sessionManager.CurrentKeyID())
	}

	if err := ws.triggerRenegotiation(); err != nil {
		t.Fatalf("triggerRenegotiation: %v", err)
	}

	select {
	case packet := <-controlToReliable:
		if packet.Opcode != model.P_CONTROL_SOFT_RESET_V1 {
			t.Fatalf("unexpected packet opcode: %v", packet.Opcode)
		}
		if packet.KeyID != 1 {
			t.Fatalf("expected SOFT_RESET key_id=1, got %d", packet.KeyID)
		}
	default:
		t.Fatal("expected a SOFT_RESET packet to be sent to controlToReliable")
	}

	select {
	case notif := <-notifyTLS:
		if notif.Flags != model.NotificationReset {
			t.Fatalf("unexpected notification flags: %v", notif.Flags)
		}
	default:
		t.Fatal("expected a TLS reset notification to be sent")
	}

	// After the soft reset we must have a consistent single key_id increment:
	// - CurrentKeyID() matches the new primary slot key ID
	// - ActiveKey() is available for the current key_id
	if ws.sessionManager.CurrentKeyID() != 1 {
		t.Fatalf("expected CurrentKeyID()=1, got %d", ws.sessionManager.CurrentKeyID())
	}
	if primary := ws.sessionManager.PrimaryKey(); primary == nil || primary.KeyID != 1 {
		if primary == nil {
			t.Fatal("expected primary key slot to be set")
		}
		t.Fatalf("expected primary key slot key_id=1, got %d", primary.KeyID)
	}
	if _, err := ws.sessionManager.ActiveKey(); err != nil {
		t.Fatalf("expected ActiveKey() to succeed, got %v", err)
	}
}

func TestWorkersState_HandlePingTimeout_RestartStartsShutdown(t *testing.T) {
	logger := &lockedLogger{}
	controlToReliable := make(chan *model.Packet, 1)
	notifyTLS := make(chan *model.Notification, 1)

	ws := &workersState{
		logger:            logger,
		workersManager:    workers.NewManager(logger),
		sessionManager:    makeTestingSession(),
		controlToReliable: controlToReliable,
		notifyTLS:         notifyTLS,
	}

	ws.handlePingTimeout(session.PingTimeoutActionRestart)

	select {
	case <-ws.workersManager.ShouldShutdown():
	default:
		t.Fatal("expected shutdown to be started on ping-restart")
	}

	select {
	case <-controlToReliable:
		t.Fatal("did not expect SOFT_RESET on ping-restart")
	default:
	}

	select {
	case <-notifyTLS:
		t.Fatal("did not expect TLS notification on ping-restart")
	default:
	}
}
