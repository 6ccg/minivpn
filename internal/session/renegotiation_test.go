package session

import (
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/pkg/config"
)

// mockLogger implements model.Logger for testing
type mockLogger struct{}

func (m *mockLogger) Debug(msg string)                 {}
func (m *mockLogger) Debugf(fmt string, v ...any)      {}
func (m *mockLogger) Info(msg string)                  {}
func (m *mockLogger) Infof(fmt string, v ...any)       {}
func (m *mockLogger) Warn(msg string)                  {}
func (m *mockLogger) Warnf(fmt string, v ...any)       {}
func (m *mockLogger) Error(msg string)                 {}
func (m *mockLogger) Errorf(fmt string, v ...any)      {}
func (m *mockLogger) WithFields(fields map[string]any) model.Logger { return m }

// mockTracer implements model.HandshakeTracer for testing
type mockTracer struct{}

func (m *mockTracer) TimeNow() time.Time                                          { return time.Now() }
func (m *mockTracer) OnStateChange(state model.NegotiationState)                   {}
func (m *mockTracer) OnIncomingPacket(packet *model.Packet, stage model.NegotiationState) {}
func (m *mockTracer) OnOutgoingPacket(packet *model.Packet, state model.NegotiationState, retries int) {
}
func (m *mockTracer) OnDroppedPacket(direction model.Direction, stage model.NegotiationState, packet *model.Packet) {
}

// drainReady starts a goroutine that drains the Ready channel.
// This is needed because SetNegotiationState(S_GENERATED_KEYS) sends to Ready.
func drainReady(mgr *Manager) {
	go func() {
		for range mgr.Ready {
		}
	}()
}

func TestReadySignalRequiresGeneratedKeys(t *testing.T) {
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{}),
		config.WithLogger(&mockLogger{}),
		config.WithHandshakeTracer(&mockTracer{}),
	)
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ready := make(chan struct{})
	go func() {
		<-mgr.Ready
		close(ready)
	}()

	mgr.SetNegotiationState(model.S_ACTIVE)
	select {
	case <-ready:
		t.Fatal("S_ACTIVE should not signal Ready before data channel keys are generated")
	case <-time.After(50 * time.Millisecond):
	}

	mgr.SetNegotiationState(model.S_GENERATED_KEYS)
	select {
	case <-ready:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("S_GENERATED_KEYS should signal Ready")
	}
}

func TestRenegotiationConfig(t *testing.T) {
	t.Run("default renegotiation config is set from options", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 7200,
			RenegotiateBytes:   100000000,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		sec, bytes := mgr.RenegotiationConfig()
		if sec != 7200 {
			t.Errorf("expected RenegotiateSeconds=7200, got %d", sec)
		}
		if bytes != 100000000 {
			t.Errorf("expected RenegotiateBytes=100000000, got %d", bytes)
		}
	})
}

func TestMarkKeyEstablished(t *testing.T) {
	t.Run("MarkKeyEstablished resets counters", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 3600,
			RenegotiateBytes:   -1,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// Add some bytes
		mgr.AddDataChannelBytes(1000, 2000)

		// Mark key established
		mgr.MarkKeyEstablished()

		// Check counters are reset
		read, written := mgr.DataChannelBytes()
		if read != 0 || written != 0 {
			t.Errorf("expected counters to be reset, got read=%d written=%d", read, written)
		}

		// Check timestamp is set
		if mgr.KeyEstablishedTime().IsZero() {
			t.Error("expected keyEstablishedTime to be set")
		}
	})
}

func TestAddDataChannelBytes(t *testing.T) {
	t.Run("bytes are accumulated correctly", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 3600,
			RenegotiateBytes:   -1,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		mgr.AddDataChannelBytes(100, 200)
		mgr.AddDataChannelBytes(50, 75)

		read, written := mgr.DataChannelBytes()
		if read != 150 {
			t.Errorf("expected read=150, got %d", read)
		}
		if written != 275 {
			t.Errorf("expected written=275, got %d", written)
		}
	})
}

func TestShouldRenegotiate(t *testing.T) {
	t.Run("returns false before keys are generated", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 1, // 1 second
			RenegotiateBytes:   -1,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// State is not yet S_GENERATED_KEYS
		if mgr.ShouldRenegotiate() {
			t.Error("should not trigger renegotiation before keys are generated")
		}
	})

	t.Run("returns false when key establishment time is zero", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 1,
			RenegotiateBytes:   -1,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// Drain Ready channel to prevent blocking
		drainReady(mgr)

		// Set state to generated keys but don't mark key established
		mgr.SetNegotiationState(model.S_GENERATED_KEYS)

		if mgr.ShouldRenegotiate() {
			t.Error("should not trigger renegotiation when key establishment time is zero")
		}
	})

	t.Run("triggers on time-based threshold", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 1, // 1 second for quick test
			RenegotiateBytes:   -1,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// Drain Ready channel to prevent blocking
		drainReady(mgr)

		mgr.SetNegotiationState(model.S_GENERATED_KEYS)
		mgr.MarkKeyEstablished()

		// Should not trigger immediately
		if mgr.ShouldRenegotiate() {
			t.Error("should not trigger renegotiation immediately")
		}

		// Wait for threshold
		time.Sleep(1100 * time.Millisecond)

		if !mgr.ShouldRenegotiate() {
			t.Error("should trigger renegotiation after time threshold")
		}

		// Should not trigger again (already requested)
		if mgr.ShouldRenegotiate() {
			t.Error("should not trigger renegotiation twice")
		}
	})

	t.Run("triggers on bytes-based threshold", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 0,    // Disable time-based
			RenegotiateBytes:   1000, // 1KB
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// Drain Ready channel to prevent blocking
		drainReady(mgr)

		mgr.SetNegotiationState(model.S_GENERATED_KEYS)
		mgr.MarkKeyEstablished()

		// Should not trigger before threshold
		// Use AddKeyBytes for per-key counters (matches OpenVPN ssl.c:3256/3890)
		mgr.AddKeyBytes(KS_PRIMARY, 500, 400)
		if mgr.ShouldRenegotiate() {
			t.Error("should not trigger renegotiation before bytes threshold")
		}

		// Add more bytes to exceed threshold
		mgr.AddKeyBytes(KS_PRIMARY, 50, 60)
		if !mgr.ShouldRenegotiate() {
			t.Error("should trigger renegotiation after bytes threshold")
		}
	})

	t.Run("disabled when reneg-sec is 0 and reneg-bytes is -1", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 0,
			RenegotiateBytes:   -1,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// Drain Ready channel to prevent blocking
		drainReady(mgr)

		mgr.SetNegotiationState(model.S_GENERATED_KEYS)
		mgr.MarkKeyEstablished()

		// Add lots of bytes
		mgr.AddDataChannelBytes(1000000, 1000000)

		// Should never trigger
		if mgr.ShouldRenegotiate() {
			t.Error("should not trigger renegotiation when disabled")
		}
	})
}

func TestClearRenegotiationRequest(t *testing.T) {
	t.Run("clears renegotiation requested flag", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			RenegotiateSeconds: 1,
			RenegotiateBytes:   -1,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// Drain Ready channel to prevent blocking
		drainReady(mgr)

		mgr.SetNegotiationState(model.S_GENERATED_KEYS)
		mgr.MarkKeyEstablished()

		// Wait for threshold
		time.Sleep(1100 * time.Millisecond)

		// Trigger renegotiation
		if !mgr.ShouldRenegotiate() {
			t.Fatal("expected renegotiation to be triggered")
		}

		if !mgr.RenegotiationRequested() {
			t.Error("expected RenegotiationRequested to be true")
		}

		// Clear the request
		mgr.ClearRenegotiationRequest()

		if mgr.RenegotiationRequested() {
			t.Error("expected RenegotiationRequested to be false after clear")
		}

		// Should be able to trigger again
		if !mgr.ShouldRenegotiate() {
			t.Error("should be able to trigger renegotiation again after clear")
		}
	})
}

func TestNextKeyID(t *testing.T) {
	t.Run("key ID cycles correctly following OpenVPN rules", func(t *testing.T) {
		opts := &config.OpenVPNOptions{}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// Initial key ID should be 0
		if mgr.CurrentKeyID() != 0 {
			t.Errorf("expected initial key ID to be 0, got %d", mgr.CurrentKeyID())
		}

		// Test cycling through all values: 0→1→2→3→4→5→6→7→1→2→...
		expectedSequence := []uint8{1, 2, 3, 4, 5, 6, 7, 1, 2, 3}
		for i, expected := range expectedSequence {
			got := mgr.NextKeyID()
			if got != expected {
				t.Errorf("iteration %d: expected key ID %d, got %d", i, expected, got)
			}
			if mgr.CurrentKeyID() != expected {
				t.Errorf("iteration %d: CurrentKeyID() returned %d, expected %d", i, mgr.CurrentKeyID(), expected)
			}
		}
	})

	t.Run("key ID never returns 0 after first use", func(t *testing.T) {
		opts := &config.OpenVPNOptions{}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		// Cycle through many iterations and verify 0 never appears
		for i := 0; i < 100; i++ {
			keyID := mgr.NextKeyID()
			if keyID == 0 {
				t.Errorf("iteration %d: key ID should never be 0 after initial key", i)
			}
			if keyID > 7 {
				t.Errorf("iteration %d: key ID %d exceeds maximum (7)", i, keyID)
			}
		}
	})
}
