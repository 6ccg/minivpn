package tlssession

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"

	tls "github.com/refraction-networking/utls"
)

type scriptedConn struct {
	reads  chan []byte
	writes chan []byte

	mu      sync.Mutex
	pending bytes.Buffer

	closed    chan struct{}
	closeOnce sync.Once
}

func newScriptedConn() *scriptedConn {
	return &scriptedConn{
		reads:  make(chan []byte, 16),
		writes: make(chan []byte, 128),
		closed: make(chan struct{}),
	}
}

func (c *scriptedConn) enqueueRead(b []byte) {
	select {
	case <-c.closed:
		return
	default:
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case c.reads <- cp:
	case <-c.closed:
	}
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.pending.Len() > 0 {
			n, _ := c.pending.Read(p)
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()

		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case chunk := <-c.reads:
			c.mu.Lock()
			_, _ = c.pending.Write(chunk)
			c.mu.Unlock()
		}
	}
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case c.writes <- cp:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *scriptedConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *scriptedConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *scriptedConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return "0.0.0.0:0" }

func makeServerControlMessage(t *testing.T, optionsString string) []byte {
	t.Helper()

	opt, err := bytesx.EncodeOptionStringToBytes(optionsString)
	if err != nil {
		t.Fatalf("EncodeOptionStringToBytes: %v", err)
	}

	var r1, r2 [32]byte
	for i := range r1 {
		r1[i] = byte(i + 1)
		r2[i] = byte(i + 101)
	}

	msg := make([]byte, 0, len(controlMessageHeader)+1+32+32+len(opt))
	msg = append(msg, controlMessageHeader...)
	msg = append(msg, 0x02) // key method (2)
	msg = append(msg, r1[:]...)
	msg = append(msg, r2[:]...)
	msg = append(msg, opt...)
	return msg
}

func Test_doTLSAuth_reachesS_ACTIVE_beforePUSH_REPLY(t *testing.T) {
	oldHandshake := tlsHandshakeFn
	t.Cleanup(func() { tlsHandshakeFn = oldHandshake })
	tlsHandshakeFn = func(c net.Conn, _ *tls.Config) (net.Conn, error) { return c, nil }

	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{HandshakeWindow: 6}),
		config.WithLogger(model.NewTestLogger()),
		config.WithHandshakeTracer(&model.DummyTracer{}),
	)
	mgr, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}

	ws := &workersState{
		logger:         model.NewTestLogger(),
		options:        cfg.OpenVPNOptions(),
		sessionManager: mgr,
		workersManager: workers.NewManager(model.NewTestLogger()),
		keyUp:          make(chan *session.DataChannelKey, 1),
	}

	conn := newScriptedConn()
	t.Cleanup(func() { _ = conn.Close() })

	errCh := make(chan error, 1)
	go ws.doTLSAuth(conn, &tls.Config{}, errCh)

	// Consume the client's auth request and reply with server options+key material.
	select {
	case <-conn.writes:
		conn.enqueueRead(makeServerControlMessage(t, "tun-mtu 1500,peer-id 1"))
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for auth request write")
	}

	// Wait until the client sends PUSH_REQUEST, which happens after auth reply is processed.
	wantPushRequest := append([]byte("PUSH_REQUEST"), 0x00)
	for {
		select {
		case w := <-conn.writes:
			if bytes.Equal(w, wantPushRequest) {
				if got := mgr.NegotiationState(); got < model.S_ACTIVE {
					t.Errorf("NegotiationState() = %s, want >= %s", got, model.S_ACTIVE)
				}

				// Complete the pull with a PUSH_REPLY so doTLSAuth can return cleanly.
				conn.enqueueRead([]byte("PUSH_REPLY,route-gateway 10.0.0.1,ifconfig 10.0.0.2 255.255.255.0\x00"))
				goto waitDone
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for PUSH_REQUEST write")
		}
	}

waitDone:
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("doTLSAuth() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for doTLSAuth to return")
	}
}

func Test_doTLSAuth_pushRequestMaxRetry_matchesOpenVPN(t *testing.T) {
	oldHandshake := tlsHandshakeFn
	t.Cleanup(func() { tlsHandshakeFn = oldHandshake })
	tlsHandshakeFn = func(c net.Conn, _ *tls.Config) (net.Conn, error) { return c, nil }

	oldInterval := pushRequestInterval
	t.Cleanup(func() { pushRequestInterval = oldInterval })
	pushRequestInterval = 400 * time.Millisecond

	cfg := config.NewConfig(
		config.WithOpenVPNOptions(&config.OpenVPNOptions{HandshakeWindow: 1}),
		config.WithLogger(model.NewTestLogger()),
		config.WithHandshakeTracer(&model.DummyTracer{}),
	)
	mgr, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}

	ws := &workersState{
		logger:         model.NewTestLogger(),
		options:        cfg.OpenVPNOptions(),
		sessionManager: mgr,
		workersManager: workers.NewManager(model.NewTestLogger()),
		keyUp:          make(chan *session.DataChannelKey, 1),
	}

	conn := newScriptedConn()
	t.Cleanup(func() { _ = conn.Close() })

	errCh := make(chan error, 1)
	go ws.doTLSAuth(conn, &tls.Config{}, errCh)

	wantPushRequest := append([]byte("PUSH_REQUEST"), 0x00)
	pushRequests := 0
	authReplySent := false

	// OpenVPN computes:
	//   max_push_requests = handshake_window / PUSH_REQUEST_INTERVAL
	//
	// With handshakeWindow=1s and pushRequestInterval=400ms, we expect 2.
	maxPushRequests := int(time.Duration(ws.options.HandshakeWindow) * time.Second / pushRequestInterval)
	if maxPushRequests != 2 {
		t.Fatalf("test invariant: maxPushRequests = %d, want 2", maxPushRequests)
	}

	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case err := <-errCh:
			if err == nil {
				t.Fatal("expected doTLSAuth to fail without PUSH_REPLY")
			}
			if pushRequests != maxPushRequests {
				t.Fatalf("push requests sent = %d, want %d", pushRequests, maxPushRequests)
			}
			return

		case w := <-conn.writes:
			if !authReplySent {
				// First write is the auth request. Respond with auth reply so the
				// client can proceed to sending PUSH_REQUEST.
				authReplySent = true
				conn.enqueueRead(makeServerControlMessage(t, "tun-mtu 1500,peer-id 1"))
				continue
			}

			if bytes.Equal(w, wantPushRequest) {
				pushRequests++
				continue
			}

		case <-timeout.C:
			t.Fatal("timed out waiting for doTLSAuth to return")
		}
	}
}

var _ net.Conn = (*scriptedConn)(nil)
var _ io.Reader = (*scriptedConn)(nil)
var _ io.Writer = (*scriptedConn)(nil)
