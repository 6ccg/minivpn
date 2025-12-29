package tlssession

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"

	tls "github.com/refraction-networking/utls"
)

func Test_doTLSAuth_timesOutDuringTLSHandshake(t *testing.T) {
	old := tlsHandshakeFn
	t.Cleanup(func() { tlsHandshakeFn = old })

	tlsHandshakeFn = func(c net.Conn, _ *tls.Config) (net.Conn, error) {
		buf := make([]byte, 1)
		_, err := c.Read(buf) // block until the conn is closed by the hand-window timeout
		return nil, err
	}

	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{HandshakeWindow: 1}),
		config.WithLogger(model.NewTestLogger()),
		config.WithHandshakeTracer(&model.DummyTracer{}),
	)
	mgr, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}

	c0, c1 := net.Pipe()
	t.Cleanup(func() { _ = c0.Close() })
	t.Cleanup(func() { _ = c1.Close() })

	ws := &workersState{
		logger:         model.NewTestLogger(),
		options:        cfg.OpenVPNOptions(),
		sessionManager: mgr,
	}

	errCh := make(chan error, 1)
	go ws.doTLSAuth(c0, &tls.Config{}, errCh)

	select {
	case got := <-errCh:
		if !errors.Is(got, ErrTLSNegotiationTimeout) {
			t.Fatalf("expected ErrTLSNegotiationTimeout, got %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for doTLSAuth to return")
	}
}
