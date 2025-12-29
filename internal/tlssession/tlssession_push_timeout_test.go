package tlssession

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"

	tls "github.com/refraction-networking/utls"
)

func Test_doTLSAuth_pushTimeoutReturnsErrNoPushReply(t *testing.T) {
	old := tlsHandshakeFn
	t.Cleanup(func() { tlsHandshakeFn = old })

	tlsHandshakeFn = func(c net.Conn, _ *tls.Config) (net.Conn, error) {
		// For this test, we don't need a real TLS handshake; we just need a
		// bidirectional stream between client and "server".
		return c, nil
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

	// Minimal valid auth-reply message for parseServerControlMessage().
	opt, err := bytesx.EncodeOptionStringToBytes("")
	if err != nil {
		t.Fatalf("EncodeOptionStringToBytes: %v", err)
	}
	authReply := append([]byte{0x00, 0x00, 0x00, 0x00, 0x02}, make([]byte, 64)...)
	authReply = append(authReply, opt...)

	c0, c1 := net.Pipe()
	t.Cleanup(func() { _ = c0.Close() })
	t.Cleanup(func() { _ = c1.Close() })

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer func() { _ = c1.Close() }()

		buf := make([]byte, 1<<16)
		// Drain the client's auth request, then respond with the auth reply.
		for {
			n, err := c1.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = c1.Write(authReply)
				break
			}
		}
		// Drain any subsequent PUSH_REQUEST retries; never send PUSH_REPLY.
		for {
			_, err := c1.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	ws := &workersState{
		logger:         model.NewTestLogger(),
		options:        cfg.OpenVPNOptions(),
		sessionManager: mgr,
		workersManager: workers.NewManager(model.NewTestLogger()),
	}

	errCh := make(chan error, 1)
	go ws.doTLSAuth(c0, &tls.Config{}, errCh)

	select {
	case got := <-errCh:
		// OpenVPN 2.5.x bounds the PUSH_REQUEST retry loop using hand-window,
		// but a missing PUSH_REPLY is not a TLS negotiation timeout.
		if !errors.Is(got, ErrNoPushReply) {
			t.Fatalf("expected ErrNoPushReply, got %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for doTLSAuth to return")
	}

	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server goroutine to exit")
	}
}
