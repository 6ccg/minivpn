package tlssession

import (
	"net"
	"testing"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

func Test_recvPushResponseMessage_updatesPingFromPushReply(t *testing.T) {
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()

	opts := &config.OpenVPNOptions{Proto: config.ProtoUDP}
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(opts),
		config.WithLogger(model.NewTestLogger()),
	)
	mgr, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	go func() {
		_, _ = c1.Write([]byte("PUSH_REPLY,ping 10,ping-restart 60,route-gateway 10.0.0.1,ifconfig 10.0.0.2 255.255.255.0\x00"))
		_ = c1.Close()
	}()

	ws := &workersState{
		logger:         model.NewTestLogger(),
		options:        opts,
		sessionManager: mgr,
	}

	_, err = ws.recvPushResponseMessage(c0)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if opts.Ping != 10 {
		t.Fatalf("unexpected ping: %d", opts.Ping)
	}
	if opts.PingRestart != 60 {
		t.Fatalf("unexpected ping-restart: %d", opts.PingRestart)
	}

	interval, timeout, action := mgr.PingConfig()
	if interval != 10 || timeout != 60 || action != session.PingTimeoutActionRestart {
		t.Fatalf("PingConfig() = (interval=%d timeout=%d action=%d)", interval, timeout, action)
	}
}

func Test_recvPushResponseMessage_updatesKeepaliveFromPushReply(t *testing.T) {
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()

	opts := &config.OpenVPNOptions{Proto: config.ProtoUDP}
	cfg := config.NewConfig(
		config.WithOpenVPNOptions(opts),
		config.WithLogger(model.NewTestLogger()),
	)
	mgr, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	go func() {
		_, _ = c1.Write([]byte("PUSH_REPLY,keepalive 10 60,route-gateway 10.0.0.1,ifconfig 10.0.0.2 255.255.255.0\x00"))
		_ = c1.Close()
	}()

	ws := &workersState{
		logger:         model.NewTestLogger(),
		options:        opts,
		sessionManager: mgr,
	}

	_, err = ws.recvPushResponseMessage(c0)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if opts.Ping != 10 {
		t.Fatalf("unexpected ping: %d", opts.Ping)
	}
	if opts.PingRestart != 60 {
		t.Fatalf("unexpected ping-restart: %d", opts.PingRestart)
	}

	interval, timeout, action := mgr.PingConfig()
	if interval != 10 || timeout != 60 || action != session.PingTimeoutActionRestart {
		t.Fatalf("PingConfig() = (interval=%d timeout=%d action=%d)", interval, timeout, action)
	}
}
