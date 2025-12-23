package networkio

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"

	"github.com/ooni/minivpn/internal/bytespool"
)

// streamConn wraps a stream socket and implements OpenVPN framing.
// It uses stack-allocated buffers and net.Buffers to minimize allocations.
type streamConn struct {
	net.Conn
	lenBuf   [2]byte      // stack-allocated length buffer for read
	writeBuf net.Buffers  // reusable Buffers for writev
	writeLen [2]byte      // stack-allocated length buffer for write
}

var _ FramingConn = &streamConn{}

// ReadRawPacket implements FramingConn.
// The returned buffer is from the pool and must be returned via bytespool.Default.Put()
// after processing, or by calling Free() on the associated Packet.
func (c *streamConn) ReadRawPacket() ([]byte, error) {
	// Use stack-allocated buffer for length header
	if _, err := io.ReadFull(c.Conn, c.lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(c.lenBuf[:])

	// Get buffer from pool
	buf := bytespool.Default.Get(int(length))
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		// Return buffer on error
		bytespool.Default.Put(buf)
		return nil, err
	}
	return buf, nil
}

// ErrPacketTooLarge means that a packet is larger than [math.MaxUint16].
var ErrPacketTooLarge = errors.New("openvpn: packet too large")

// WriteRawPacket implements FramingConn.
// Uses net.Buffers (writev) to avoid copying the length header and payload together.
func (c *streamConn) WriteRawPacket(pkt []byte) error {
	if len(pkt) > math.MaxUint16 {
		return ErrPacketTooLarge
	}

	// Use stack-allocated buffer for length header
	binary.BigEndian.PutUint16(c.writeLen[:], uint16(len(pkt)))

	// Use net.Buffers for scatter-gather I/O (writev)
	// This avoids copying the length header and payload together
	c.writeBuf = c.writeBuf[:0]
	c.writeBuf = append(c.writeBuf, c.writeLen[:], pkt)
	_, err := c.writeBuf.WriteTo(c.Conn)
	return err
}
