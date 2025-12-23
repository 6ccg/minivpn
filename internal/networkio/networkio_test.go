package networkio

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/bytespool"
	"github.com/ooni/minivpn/internal/vpntest"
)

func Test_TCPLikeConn(t *testing.T) {
	t.Run("A tcp-like conn implements the openvpn size framing", func(t *testing.T) {
		dataIn := make([][]byte, 0)
		dataOut := make([][]byte, 0)
		// write size
		dataOut = append(dataOut, []byte{0, 8})
		// write payload
		want := []byte("deadbeef")
		dataOut = append(dataOut, want)

		underlying := newMockedConn("tcp", dataIn, dataOut)
		testDialer := newDialer(underlying)
		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "tcp", "1.1.1.1")

		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		got, err := framingConn.ReadRawPacket()
		if err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got = %v, want = %v", got, want)
		}

		written := []byte("ingirumimusnocteetconsumimurigni")
		framingConn.WriteRawPacket(written)
		gotWritten := underlying.NetworkWrites()
		// WriteRawPacket uses net.Buffers (writev), which may result in
		// multiple write calls. Concatenate all writes to verify the framed data.
		var combined []byte
		for _, w := range gotWritten {
			combined = append(combined, w...)
		}
		wantWritten := append([]byte{0, byte(len(written))}, written...)
		if !bytes.Equal(combined, wantWritten) {
			t.Errorf("got = %v, want = %v", combined, wantWritten)
		}
	})
}

func Test_UDPLikeConn(t *testing.T) {
	t.Run("A udp-like conn returns the packets directly", func(t *testing.T) {
		dataIn := make([][]byte, 0)
		dataOut := make([][]byte, 0)
		// write payload
		want := []byte("deadbeef")
		dataOut = append(dataOut, want)

		underlying := newMockedConn("udp", dataIn, dataOut)
		testDialer := newDialer(underlying)
		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "udp", "1.1.1.1")
		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		got, err := framingConn.ReadRawPacket()
		if err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got = %v, want = %v", got, want)
		}
		written := []byte("ingirumimusnocteetconsumimurigni")
		framingConn.WriteRawPacket(written)
		gotWritten := underlying.NetworkWrites()
		if !bytes.Equal(gotWritten[0], written) {
			t.Errorf("got = %v, want = %v", gotWritten, written)
		}
	})
}

func Test_CloseOnceConn(t *testing.T) {
	t.Run("A conn can be closed more than once", func(t *testing.T) {
		ctr := 0
		testDialer := &vpntest.Dialer{
			MockDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn := &vpntest.Conn{
					MockClose: func() error {
						ctr++
						return nil
					},
					MockLocalAddr: func() net.Addr {
						addr := &vpntest.Addr{
							MockString:  func() string { return "1.2.3.4" },
							MockNetwork: func() string { return network },
						}
						return addr
					},
				}
				return conn, nil
			},
		}

		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "tcp", "1.1.1.1")
		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		framingConn.Close()
		framingConn.Close()
		if ctr != 1 {
			t.Errorf("close function should be called only once")
		}
	})
}

func Test_UDPLikeConn_BytesPool(t *testing.T) {
	t.Run("UDP ReadRawPacket returns buffer from bytespool", func(t *testing.T) {
		dataIn := make([][]byte, 0)
		dataOut := make([][]byte, 0)
		// write payload - use a size that fits in pool (256 bytes pool bucket)
		want := []byte("deadbeef")
		dataOut = append(dataOut, want)

		underlying := newMockedConn("udp", dataIn, dataOut)
		testDialer := newDialer(underlying)
		dialer := NewDialer(log.Log, testDialer)
		framingConn, err := dialer.DialContext(context.Background(), "udp", "1.1.1.1")
		if err != nil {
			t.Errorf("should not error getting a framingConn")
		}
		got, err := framingConn.ReadRawPacket()
		if err != nil {
			t.Errorf("should not error: err = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got = %v, want = %v", got, want)
		}

		// Verify the buffer capacity is from the pool (power of 2)
		// For 8 bytes, it should use the 256-byte pool bucket
		if cap(got) != 256 {
			t.Errorf("expected buffer capacity 256 (from pool), got = %d", cap(got))
		}

		// Return buffer to pool - this should not panic
		bytespool.Default.Put(got)
	})

	t.Run("UDP ReadRawPacket handles various packet sizes", func(t *testing.T) {
		testCases := []struct {
			name         string
			size         int
			expectedCap  int
			shouldBePool bool // whether the buffer should come from pool
		}{
			{"tiny packet (8 bytes)", 8, 256, true},
			{"small packet (200 bytes)", 200, 256, true},
			{"medium packet (500 bytes)", 500, 512, true},
			{"large packet (1000 bytes)", 1000, 1024, true},
			{"larger packet (1500 bytes)", 1500, 2048, true},
			{"max pool packet (4000 bytes)", 4000, 4096, true},
			{"oversized packet (5000 bytes)", 5000, 5000, false}, // exceeds pool, allocated directly
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				dataIn := make([][]byte, 0)
				dataOut := make([][]byte, 0)
				payload := make([]byte, tc.size)
				for i := range payload {
					payload[i] = byte(i % 256)
				}
				dataOut = append(dataOut, payload)

				underlying := newMockedConn("udp", dataIn, dataOut)
				testDialer := newDialer(underlying)
				dialer := NewDialer(log.Log, testDialer)
				framingConn, err := dialer.DialContext(context.Background(), "udp", "1.1.1.1")
				if err != nil {
					t.Fatalf("should not error getting a framingConn")
				}
				got, err := framingConn.ReadRawPacket()
				if err != nil {
					t.Fatalf("should not error: err = %v", err)
				}
				if !bytes.Equal(got, payload) {
					t.Errorf("packet content mismatch")
				}
				if len(got) != tc.size {
					t.Errorf("expected len %d, got %d", tc.size, len(got))
				}
				if tc.shouldBePool && cap(got) != tc.expectedCap {
					t.Errorf("expected capacity %d (from pool), got %d", tc.expectedCap, cap(got))
				}
				if !tc.shouldBePool && cap(got) < tc.size {
					t.Errorf("expected capacity at least %d, got %d", tc.size, cap(got))
				}

				// Return buffer to pool
				bytespool.Default.Put(got)
			})
		}
	})
}
