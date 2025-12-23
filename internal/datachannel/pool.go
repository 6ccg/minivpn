package datachannel

//
// Buffer pooling for zero-allocation packet processing
//

import (
	"bytes"
	"sync"

	"github.com/ooni/minivpn/internal/bytespool"
)

// bufferPool pools bytes.Buffer instances for small header buffers
var bufferPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

// getBuffer gets a reset bytes.Buffer from the pool
func getBuffer() *bytes.Buffer {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// putBuffer returns a bytes.Buffer to the pool
func putBuffer(buf *bytes.Buffer) {
	if buf != nil {
		bufferPool.Put(buf)
	}
}

// defaultSlicePool is the global slice pool for crypto buffers.
// This is now a wrapper around bytespool.Default for backward compatibility.
var defaultSlicePool = &slicePoolWrapper{}

// slicePoolWrapper wraps bytespool.SlicePool for backward compatibility.
type slicePoolWrapper struct{}

// getSlice gets a byte slice from the pool.
func (p *slicePoolWrapper) getSlice(size int) []byte {
	return bytespool.Default.Get(size)
}

// putSlice returns a slice to the pool.
func (p *slicePoolWrapper) putSlice(buf []byte) {
	bytespool.Default.Put(buf)
}
