package reliabletransport

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	vpnconfig "github.com/ooni/minivpn/pkg/config"
)

type testLogger struct {
	mu    sync.Mutex
	lines []string
	ch    chan string
}

func newTestLogger(buffer int) *testLogger {
	return &testLogger{ch: make(chan string, buffer)}
}

func (l *testLogger) append(msg string) {
	l.mu.Lock()
	l.lines = append(l.lines, msg)
	l.mu.Unlock()
	select {
	case l.ch <- msg:
	default:
	}
}

func (l *testLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *testLogger) Debug(msg string)               { l.append(msg) }
func (l *testLogger) Debugf(format string, v ...any) { l.append(fmt.Sprintf(format, v...)) }
func (l *testLogger) Info(msg string)                { l.append(msg) }
func (l *testLogger) Infof(format string, v ...any)  { l.append(fmt.Sprintf(format, v...)) }
func (l *testLogger) Warn(msg string)                { l.append(msg) }
func (l *testLogger) Warnf(format string, v ...any)  { l.append(fmt.Sprintf(format, v...)) }

func waitForEnqueueInflight(t *testing.T, logger *testLogger, timeout time.Duration) int {
	t.Helper()

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	const needle = "reliabletransport: enqueue "
	const inflightNeedle = "inflight="

	for {
		select {
		case msg := <-logger.ch:
			if !strings.Contains(msg, needle) {
				continue
			}
			idx := strings.LastIndex(msg, inflightNeedle)
			if idx < 0 {
				continue
			}
			value := strings.TrimSpace(msg[idx+len(inflightNeedle):])
			n, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			return n

		case <-deadline.C:
			t.Fatalf("timeout waiting for enqueue log; logs:\n%s", strings.Join(logger.snapshot(), "\n"))
		}
	}
}

func TestMoveDownWorker_ResetsSenderOnKeySoftReset(t *testing.T) {
	logger := newTestLogger(1024)
	workersManager := workers.NewManager(logger)
	sessionManager, err := session.NewManager(vpnconfig.NewConfig(vpnconfig.WithLogger(logger)))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	sessionManager.SetRemoteSessionID(newRandomSessionID())

	controlToReliable := make(chan *model.Packet, 8)
	dataOrControlToMuxer := make(chan *model.Packet, 8)

	ws := &workersState{
		controlToReliable:    controlToReliable,
		dataOrControlToMuxer: dataOrControlToMuxer,
		incomingSeen:         make(chan incomingPacketSeen, 8),
		logger:               logger,
		sessionManager:       sessionManager,
		tracer:               &model.DummyTracer{},
		workersManager:       workersManager,
	}

	workersManager.StartWorker(ws.moveDownWorker)
	t.Cleanup(func() {
		workersManager.StartShutdown()
		workersManager.WaitWorkersShutdown()
	})

	controlToReliable <- &model.Packet{
		Opcode:  model.P_CONTROL_V1,
		KeyID:   sessionManager.CurrentKeyID(),
		ID:      1,
		Payload: []byte("first"),
	}
	if got := waitForEnqueueInflight(t, logger, 2*time.Second); got != 1 {
		t.Fatalf("expected first enqueue inflight=1, got %d", got)
	}

	if err := sessionManager.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset: %v", err)
	}

	controlToReliable <- &model.Packet{
		Opcode:  model.P_CONTROL_V1,
		KeyID:   sessionManager.CurrentKeyID(),
		ID:      2,
		Payload: []byte("second"),
	}
	if got := waitForEnqueueInflight(t, logger, 2*time.Second); got != 1 {
		t.Fatalf("expected enqueue inflight=1 after KeySoftReset, got %d", got)
	}
}
