// Package bytespool provides buffer pooling for zero-allocation packet processing.
package bytespool

import (
	"sync"
)

// SlicePool pools []byte slices for packet operations.
// Uses power-of-2 sizing for efficiency: 256, 512, 1024, 2048, 4096, 8192, 16384 bytes.
// Covers standard MTU (1500) and Jumbo Frame MTU (9000).
type SlicePool struct {
	pools [7]sync.Pool
}

// Default is the global slice pool for packet buffers.
var Default = &SlicePool{
	pools: [7]sync.Pool{
		{New: func() any { b := make([]byte, 256); return &b }},
		{New: func() any { b := make([]byte, 512); return &b }},
		{New: func() any { b := make([]byte, 1024); return &b }},
		{New: func() any { b := make([]byte, 2048); return &b }},
		{New: func() any { b := make([]byte, 4096); return &b }},
		{New: func() any { b := make([]byte, 8192); return &b }},
		{New: func() any { b := make([]byte, 16384); return &b }},
	},
}

// Get gets a byte slice of at least 'size' bytes from the pool.
// Returns a new slice if size exceeds pool capacity.
func (p *SlicePool) Get(size int) []byte {
	idx := p.poolIndex(size)
	if idx < 0 {
		// Too large for pool, allocate directly
		return make([]byte, size)
	}
	buf := p.pools[idx].Get().(*[]byte)
	return (*buf)[:size]
}

// Put returns a slice to the pool.
// Only slices with exact power-of-2 capacity are accepted.
func (p *SlicePool) Put(buf []byte) {
	if buf == nil {
		return
	}
	idx := p.poolIndexByCapacity(cap(buf))
	if idx < 0 {
		// Not from our pool or too large, don't return
		return
	}
	buf = buf[:cap(buf)]
	p.pools[idx].Put(&buf)
}

// poolIndex returns the pool index for a given size, or -1 if too large.
func (p *SlicePool) poolIndex(size int) int {
	switch {
	case size <= 256:
		return 0
	case size <= 512:
		return 1
	case size <= 1024:
		return 2
	case size <= 2048:
		return 3
	case size <= 4096:
		return 4
	case size <= 8192:
		return 5
	case size <= 16384:
		return 6
	default:
		return -1
	}
}

// poolIndexByCapacity returns the pool index for a given capacity, or -1 if not a valid pool size.
func (p *SlicePool) poolIndexByCapacity(cap int) int {
	switch cap {
	case 256:
		return 0
	case 512:
		return 1
	case 1024:
		return 2
	case 2048:
		return 3
	case 4096:
		return 4
	case 8192:
		return 5
	case 16384:
		return 6
	default:
		return -1
	}
}
