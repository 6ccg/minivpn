package tlssession

import (
	"bytes"
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

func Test_recvPushResponseMessage_readsNullTerminatedMessages(t *testing.T) {
	t.Run("handles split writes", func(t *testing.T) {
		c0, c1 := net.Pipe()
		defer c0.Close()
		defer c1.Close()

		go func() {
			_, _ = c1.Write([]byte("PUSH_REPLY,route-gateway 10.0.0.1,ifconfig "))
			_, _ = c1.Write([]byte("10.0.0.2 255.255.255.0\x00"))
			_ = c1.Close()
		}()

		ws := &workersState{logger: model.NewTestLogger()}
		ti, err := ws.recvPushResponseMessage(c0)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if ti.IP != "10.0.0.2" {
			t.Fatalf("unexpected IP: %q", ti.IP)
		}
		if ti.NetMask != "255.255.255.0" {
			t.Fatalf("unexpected NetMask: %q", ti.NetMask)
		}
		if ti.GW != "10.0.0.1" {
			t.Fatalf("unexpected GW: %q", ti.GW)
		}
	})

	t.Run("ignores non-push control strings before PUSH_REPLY", func(t *testing.T) {
		c0, c1 := net.Pipe()
		defer c0.Close()
		defer c1.Close()

		go func() {
			_, _ = c1.Write([]byte("AUTH_PENDING,timeout 10\x00PUSH_REPLY,route-gateway 10.0.0.1,ifconfig 10.0.0.2 255.255.255.0\x00"))
			_ = c1.Close()
		}()

		ws := &workersState{logger: model.NewTestLogger()}
		ti, err := ws.recvPushResponseMessage(c0)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if ti.IP != "10.0.0.2" {
			t.Fatalf("unexpected IP: %q", ti.IP)
		}
	})

	t.Run("fails on AUTH_FAILED", func(t *testing.T) {
		c0, c1 := net.Pipe()
		defer c0.Close()
		defer c1.Close()

		go func() {
			_, _ = c1.Write([]byte("AUTH_FAILED\x00"))
			_ = c1.Close()
		}()

		ws := &workersState{logger: model.NewTestLogger()}
		_, err := ws.recvPushResponseMessage(c0)
		if !errors.Is(err, errBadAuth) {
			t.Fatalf("expected errBadAuth, got %v", err)
		}
	})
}

func Test_recvPushResponseMessage_updatesCipherFromPushReply(t *testing.T) {
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()

	opts := &config.OpenVPNOptions{Cipher: "AES-256-CBC"}

	go func() {
		_, _ = c1.Write([]byte("PUSH_REPLY,cipher AES-256-GCM,route-gateway 10.0.0.1,ifconfig 10.0.0.2 255.255.255.0\x00"))
		_ = c1.Close()
	}()

	ws := &workersState{
		logger:  model.NewTestLogger(),
		options: opts,
	}
	_, err := ws.recvPushResponseMessage(c0)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if opts.Cipher != "AES-256-GCM" {
		t.Fatalf("unexpected cipher: %q", opts.Cipher)
	}
}

func Test_doTLSAuth_setsActiveBeforePushRequest(t *testing.T) {
	old := tlsHandshakeFn
	t.Cleanup(func() { tlsHandshakeFn = old })
	tlsHandshakeFn = func(c net.Conn, _ *tls.Config) (net.Conn, error) { return c, nil }

	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{
			HandshakeWindow: 60,
			Cipher:          "AES-256-GCM",
			Auth:            "SHA256",
		}),
		config.WithLogger(model.NewTestLogger()),
		config.WithHandshakeTracer(&model.DummyTracer{}),
	)
	mgr, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}
	mgr.SetNegotiationState(model.S_PRE_START)

	optBytes, err := bytesx.EncodeOptionStringToBytes("V4,dev-type tun,link-mtu 1551,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server")
	if err != nil {
		t.Fatalf("bytesx.EncodeOptionStringToBytes: %v", err)
	}
	authReply := make([]byte, 0, 4+1+64+len(optBytes))
	authReply = append(authReply, controlMessageHeader...)
	authReply = append(authReply, 0x02) // key method (2)
	authReply = append(authReply, bytes.Repeat([]byte{0xa4}, 32)...)
	authReply = append(authReply, bytes.Repeat([]byte{0x2f}, 32)...)
	authReply = append(authReply, optBytes...)

	c0, c1 := net.Pipe()
	t.Cleanup(func() { _ = c0.Close() })
	t.Cleanup(func() { _ = c1.Close() })

	pushReqSeen := make(chan struct{})
	pattern := []byte("PUSH_REQUEST\x00")

	// Drain client writes and detect the PUSH_REQUEST marker.
	go func() {
		buf := make([]byte, 4096)
		pending := make([]byte, 0, 2*len(pattern))
		seen := false
		for {
			n, err := c1.Read(buf)
			if n > 0 {
				pending = append(pending, buf[:n]...)
				if !seen && bytes.Contains(pending, pattern) {
					seen = true
					close(pushReqSeen)
				}
				if len(pending) > cap(pending) {
					pending = append(pending[:0], pending[len(pending)-cap(pending):]...)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Send auth reply (will unblock once client starts reading).
	go func() { _, _ = c1.Write(authReply) }()

	ws := &workersState{
		logger:         model.NewTestLogger(),
		options:        cfg.OpenVPNOptions(),
		sessionManager: mgr,
		workersManager: workers.NewManager(model.NewTestLogger()),
	}

	errCh := make(chan error, 1)
	go ws.doTLSAuth(c0, &tls.Config{}, errCh)

	select {
	case <-pushReqSeen:
		if got := mgr.NegotiationState(); got < model.S_ACTIVE {
			t.Fatalf("expected negotiation state >= %s before push request, got %s", model.S_ACTIVE, got)
		}
		if pk := mgr.PrimaryKey(); pk == nil || !pk.MustNegotiate.IsZero() {
			t.Fatalf("expected must_negotiate to be cleared before push request, got %v", pk.MustNegotiate)
		}
		_ = c0.Close()
	case got := <-errCh:
		t.Fatalf("doTLSAuth returned before push request: %v", got)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for push request")
	}

	select {
	case <-errCh:
		// ok; we forced shutdown by closing the conn
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for doTLSAuth to return")
	}
}
