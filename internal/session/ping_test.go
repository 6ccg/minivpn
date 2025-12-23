package session

import (
	"testing"
	"time"

	"github.com/ooni/minivpn/pkg/config"
)

func TestPingConfig(t *testing.T) {
	tests := []struct {
		name         string
		ping         int
		pingRestart  int
		pingExit     int
		wantInterval int
		wantTimeout  int
		wantAction   int
	}{
		{"all disabled", 0, 0, 0, 0, 0, PingTimeoutActionNone},
		{"ping only", 10, 0, 0, 10, 0, PingTimeoutActionNone},
		{"ping-restart only", 0, 60, 0, 0, 60, PingTimeoutActionRestart},
		{"ping-exit only", 0, 0, 120, 0, 120, PingTimeoutActionExit},
		{"ping-exit takes precedence", 10, 60, 120, 10, 120, PingTimeoutActionExit},
		{"keepalive equivalent", 10, 60, 0, 10, 60, PingTimeoutActionRestart},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &config.OpenVPNOptions{
				Ping:        tt.ping,
				PingRestart: tt.pingRestart,
				PingExit:    tt.pingExit,
			}
			cfg := config.NewConfig(
				config.WithOpenVPNOptions(opts),
				config.WithLogger(&mockLogger{}),
				config.WithHandshakeTracer(&mockTracer{}),
			)
			mgr, err := NewManager(cfg)
			if err != nil {
				t.Fatalf("NewManager() error = %v", err)
			}

			interval, timeout, action := mgr.PingConfig()
			if interval != tt.wantInterval {
				t.Errorf("PingConfig() interval = %v, want %v", interval, tt.wantInterval)
			}
			if timeout != tt.wantTimeout {
				t.Errorf("PingConfig() timeout = %v, want %v", timeout, tt.wantTimeout)
			}
			if action != tt.wantAction {
				t.Errorf("PingConfig() action = %v, want %v", action, tt.wantAction)
			}
		})
	}
}

func TestCheckPingTimeout(t *testing.T) {
	t.Run("no timeout before first packet", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			PingRestart: 1, // 1 second for fast testing
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}

		// Before any packet, should not timeout
		exceeded, _ := mgr.CheckPingTimeout()
		if exceeded {
			t.Error("CheckPingTimeout() should not exceed before first packet")
		}
	})

	t.Run("no timeout immediately after packet", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			PingRestart: 2, // 2 seconds
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}

		// Update last packet time
		mgr.UpdateLastPacketTime()

		// Immediately after, should not timeout
		exceeded, _ := mgr.CheckPingTimeout()
		if exceeded {
			t.Error("CheckPingTimeout() should not exceed immediately after packet")
		}
	})

	t.Run("timeout after period expires", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			PingRestart: 1, // 1 second for fast testing
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}

		// Update last packet time
		mgr.UpdateLastPacketTime()

		// Wait for timeout
		time.Sleep(1100 * time.Millisecond)

		exceeded, action := mgr.CheckPingTimeout()
		if !exceeded {
			t.Error("CheckPingTimeout() should exceed after timeout period")
		}
		if action != PingTimeoutActionRestart {
			t.Errorf("CheckPingTimeout() action = %v, want %v", action, PingTimeoutActionRestart)
		}
	})

	t.Run("no timeout when disabled", func(t *testing.T) {
		opts := &config.OpenVPNOptions{
			PingRestart: 0,
			PingExit:    0,
		}
		cfg := config.NewConfig(
			config.WithOpenVPNOptions(opts),
			config.WithLogger(&mockLogger{}),
			config.WithHandshakeTracer(&mockTracer{}),
		)
		mgr, err := NewManager(cfg)
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}

		mgr.UpdateLastPacketTime()

		exceeded, action := mgr.CheckPingTimeout()
		if exceeded {
			t.Error("CheckPingTimeout() should not exceed when disabled")
		}
		if action != PingTimeoutActionNone {
			t.Errorf("CheckPingTimeout() action = %v, want %v", action, PingTimeoutActionNone)
		}
	})
}

func TestUpdateLastPacketTime(t *testing.T) {
	opts := &config.OpenVPNOptions{}
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(opts),
		config.WithLogger(&mockLogger{}),
		config.WithHandshakeTracer(&mockTracer{}),
	)
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Initially zero
	if !mgr.LastPacketTime().IsZero() {
		t.Error("LastPacketTime() should be zero initially")
	}

	// After update, should be recent
	mgr.UpdateLastPacketTime()
	lastTime := mgr.LastPacketTime()
	if lastTime.IsZero() {
		t.Error("LastPacketTime() should not be zero after update")
	}
	if time.Since(lastTime) > time.Second {
		t.Error("LastPacketTime() should be very recent")
	}
}
