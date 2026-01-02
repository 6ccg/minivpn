package networkio

import (
	"math"
	"net"

	"github.com/6ccg/minivpn/internal/bytespool"
)

// datagramConn wraps a datagram socket and implements OpenVPN framing.
type datagramConn struct {
	net.Conn
	scratch []byte
}

var _ FramingConn = &datagramConn{}

// ReadRawPacket implements FramingConn.
// The returned buffer is from the pool and must be returned via bytespool.Default.Put()
// after processing, or by calling Free() on the associated Packet.
func (c *datagramConn) ReadRawPacket() ([]byte, error) {
	if c.scratch == nil {
		// maximum UDP datagram size
		c.scratch = make([]byte, math.MaxUint16)
	}
	count, err := c.Read(c.scratch)
	if err != nil {
		return nil, err
	}
	// Get right-sized buffer from pool to avoid retaining a 64KiB backing array
	// for small packets and reduce GC pressure.
	pkt := bytespool.Default.Get(count)
	copy(pkt, c.scratch[:count])
	return pkt, nil
}

// WriteRawPacket implements FramingConn
func (c *datagramConn) WriteRawPacket(pkt []byte) error {
	if len(pkt) > math.MaxUint16 {
		return ErrPacketTooLarge
	}
	_, err := c.Conn.Write(pkt)
	return err
}
