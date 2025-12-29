package session

import (
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/pkg/config"
)

func TestMustNegotiateIsSetOnInitialHandshake(t *testing.T) {
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{
			HandshakeWindow: 60,
		}),
		config.WithLogger(&mockLogger{}),
		config.WithHandshakeTracer(&mockTracer{}),
	)

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if got, want := mgr.NegotiationState(), model.S_INITIAL; got != want {
		t.Fatalf("NegotiationState() = %s, want %s", got, want)
	}

	primary := mgr.PrimaryKey()
	if primary == nil {
		t.Fatal("PrimaryKey() = nil")
	}
	if !primary.MustNegotiate.IsZero() {
		t.Fatalf("primary.MustNegotiate should be unset before handshake starts, got %v", primary.MustNegotiate)
	}

	mgr.SetNegotiationState(model.S_PRE_START)

	primary = mgr.PrimaryKey()
	if primary == nil {
		t.Fatal("PrimaryKey() = nil after SetNegotiationState")
	}
	if primary.MustNegotiate.IsZero() {
		t.Fatal("must_negotiate deadline not set on S_INITIAL -> S_PRE_START transition")
	}

	remaining := time.Until(primary.MustNegotiate)
	if remaining <= 0 {
		t.Fatalf("must_negotiate already expired: %v", remaining)
	}
	if remaining > mgr.handshakeWindow {
		t.Fatalf("must_negotiate remaining=%v exceeds handshakeWindow=%v", remaining, mgr.handshakeWindow)
	}

	deadline := primary.MustNegotiate
	mgr.SetNegotiationState(model.S_PRE_START)
	if got := mgr.PrimaryKey().MustNegotiate; !got.Equal(deadline) {
		t.Fatalf("must_negotiate changed on S_PRE_START -> S_PRE_START: got=%v want=%v", got, deadline)
	}
}

func TestMustNegotiateIsClearedOnActive(t *testing.T) {
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{HandshakeWindow: 60}),
		config.WithLogger(&mockLogger{}),
		config.WithHandshakeTracer(&mockTracer{}),
	)

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	mgr.SetNegotiationState(model.S_PRE_START)
	if mgr.PrimaryKey().MustNegotiate.IsZero() {
		t.Fatal("must_negotiate should be set after starting negotiation")
	}

	mgr.SetNegotiationState(model.S_ACTIVE)
	if !mgr.PrimaryKey().MustNegotiate.IsZero() {
		t.Fatal("must_negotiate should be cleared when reaching S_ACTIVE")
	}
}

func TestMustNegotiateIsSetOnSoftReset(t *testing.T) {
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{HandshakeWindow: 60}),
		config.WithLogger(&mockLogger{}),
		config.WithHandshakeTracer(&mockTracer{}),
	)

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if !mgr.PrimaryKey().MustNegotiate.IsZero() {
		t.Fatal("must_negotiate should be unset before soft reset")
	}

	if err := mgr.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset: %v", err)
	}

	primary := mgr.PrimaryKey()
	if primary == nil {
		t.Fatal("PrimaryKey() = nil after KeySoftReset")
	}
	if primary.MustNegotiate.IsZero() {
		t.Fatal("must_negotiate not set after KeySoftReset")
	}

	remaining := time.Until(primary.MustNegotiate)
	if remaining <= 0 {
		t.Fatalf("must_negotiate already expired after KeySoftReset: %v", remaining)
	}
	if remaining > mgr.handshakeWindow {
		t.Fatalf("must_negotiate remaining=%v exceeds handshakeWindow=%v", remaining, mgr.handshakeWindow)
	}
}
