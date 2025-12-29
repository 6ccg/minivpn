package tun

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	vpnconfig "github.com/ooni/minivpn/pkg/config"
)

type blockingFramingConn struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newBlockingFramingConn() *blockingFramingConn {
	return &blockingFramingConn{closed: make(chan struct{})}
}

func (c *blockingFramingConn) ReadRawPacket() ([]byte, error) {
	<-c.closed
	return nil, net.ErrClosed
}

func (c *blockingFramingConn) WriteRawPacket(_ []byte) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
		return nil
	}
}

func (c *blockingFramingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingFramingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *blockingFramingConn) LocalAddr() net.Addr  { return dummyAddr("udp") }
func (c *blockingFramingConn) RemoteAddr() net.Addr { return dummyAddr("udp") }

func (c *blockingFramingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return "0.0.0.0:0" }

func TestStartTUN_HandshakeWindowTimeout_NoServerResponse(t *testing.T) {
	cfg := vpnconfig.NewConfig(
		vpnconfig.WithOpenVPNOptions(&vpnconfig.OpenVPNOptions{HandshakeWindow: 1}),
		vpnconfig.WithLogger(model.NewTestLogger()),
		vpnconfig.WithHandshakeTracer(&model.DummyTracer{}),
	)

	conn := newBlockingFramingConn()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	started := time.Now()
	_, err := StartTUN(ctx, conn, cfg)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, session.ErrTLSNegotiationTimeout) {
		t.Fatalf("expected ErrTLSNegotiationTimeout, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("handshake took too long: %v", elapsed)
	}
}
