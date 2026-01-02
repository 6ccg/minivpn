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

func Test_workersState_sendAuthRequestMessage_AuthNoCacheEncodesCredentialsOnSubsequentSends(t *testing.T) {
	conn := newScriptedConn()
	t.Cleanup(func() { _ = conn.Close() })

	opts := &config.OpenVPNOptions{
		AuthUserPass: true,
		AuthNoCache:  true,
		Username:     "user",
		Password:     "pass",
		Cipher:       "AES-256-GCM",
		Auth:         "SHA256",
		Proto:        config.ProtoUDP,
	}

	activeKey := &session.DataChannelKey{}
	if err := activeKey.AddLocalKey(&session.KeySource{}); err != nil {
		t.Fatalf("AddLocalKey: %v", err)
	}

	ws := &workersState{
		logger:  model.NewTestLogger(),
		options: opts,
	}

	// Send twice to simulate a later reset/renegotiation reusing the same worker state.
	for i := 0; i < 2; i++ {
		opts.Username = "user"
		opts.Password = "pass"
		if err := ws.sendAuthRequestMessage(conn, activeKey); err != nil {
			t.Fatalf("sendAuthRequestMessage (attempt=%d): %v", i, err)
		}
	}

	for i := 0; i < 2; i++ {
		var msg []byte
		select {
		case msg = <-conn.writes:
		default:
			t.Fatalf("missing auth request write (idx=%d)", i)
		}

		offset := 4 + 1 + len(activeKey.Local().Bytes())
		_, offset, err := decodeOptionStringAndAdvance(msg, offset) // opts
		if err != nil {
			t.Fatalf("decode options (idx=%d): %v", i, err)
		}
		user, offset, err := decodeOptionStringAndAdvance(msg, offset)
		if err != nil {
			t.Fatalf("decode username (idx=%d): %v", i, err)
		}
		pass, _, err := decodeOptionStringAndAdvance(msg, offset)
		if err != nil {
			t.Fatalf("decode password (idx=%d): %v", i, err)
		}
		if user != "user" || pass != "pass" {
			t.Fatalf("unexpected encoded credentials (idx=%d): user=%q pass=%q", i, user, pass)
		}
	}

	if opts.Username != "" || opts.Password != "" {
		t.Fatalf("expected credentials to be purged when auth-nocache is set, got user=%q pass=%q", opts.Username, opts.Password)
	}
}

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
