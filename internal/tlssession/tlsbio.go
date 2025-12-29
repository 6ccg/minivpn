package tlssession

import (
	"bytes"
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
)

// tlsBio allows to use channels to read and write
type tlsBio struct {
	closeOnce     sync.Once
	directionDown chan<- []byte
	directionUp   <-chan []byte
	hangup        chan any
	logger        model.Logger
	readBuffer    *bytes.Buffer

	mu            sync.Mutex
	readDeadline  time.Time
	readCtx       context.Context
	readCancel    context.CancelFunc
	writeDeadline time.Time
	writeCtx      context.Context
	writeCancel   context.CancelFunc
}

// newTLSBio creates a new tlsBio
func newTLSBio(logger model.Logger, directionUp <-chan []byte, directionDown chan<- []byte) *tlsBio {
	readCtx, readCancel := context.WithCancel(context.Background())
	writeCtx, writeCancel := context.WithCancel(context.Background())
	return &tlsBio{
		closeOnce:     sync.Once{},
		directionDown: directionDown,
		directionUp:   directionUp,
		hangup:        make(chan any),
		logger:        logger,
		readBuffer:    &bytes.Buffer{},
		readCtx:       readCtx,
		readCancel:    readCancel,
		writeCtx:      writeCtx,
		writeCancel:   writeCancel,
	}
}

func (t *tlsBio) Close() error {
	t.closeOnce.Do(func() {
		close(t.hangup)
	})
	return nil
}

func (t *tlsBio) readDeadlineState() (time.Time, <-chan struct{}) {
	t.mu.Lock()
	deadline := t.readDeadline
	ctx := t.readCtx
	t.mu.Unlock()
	if ctx == nil {
		return deadline, nil
	}
	return deadline, ctx.Done()
}

func (t *tlsBio) Read(data []byte) (int, error) {
	for {
		count, _ := t.readBuffer.Read(data)
		if count > 0 {
			t.logger.Debugf("[tlsbio] read %d bytes head=%s", count, bytesx.HexPrefix(data[:count], 32))
			return count, nil
		}

		// Fast-path: if we already have bytes ready, don't consult deadlines.
		select {
		case extra, ok := <-t.directionUp:
			if !ok {
				return 0, net.ErrClosed
			}
			t.logger.Debugf("[tlsbio] buffer incoming %d bytes head=%s", len(extra), bytesx.HexPrefix(extra, 32))
			_, _ = t.readBuffer.Write(extra)
			continue
		case <-t.hangup:
			return 0, net.ErrClosed
		default:
		}

		deadline, done := t.readDeadlineState()
		if !deadline.IsZero() && time.Until(deadline) <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		select {
		case extra, ok := <-t.directionUp:
			if !ok {
				return 0, net.ErrClosed
			}
			t.logger.Debugf("[tlsbio] buffer incoming %d bytes head=%s", len(extra), bytesx.HexPrefix(extra, 32))
			_, _ = t.readBuffer.Write(extra)
		case <-t.hangup:
			return 0, net.ErrClosed
		case <-done:
		}
	}
}

func (t *tlsBio) writeDeadlineState() (time.Time, <-chan struct{}) {
	t.mu.Lock()
	deadline := t.writeDeadline
	ctx := t.writeCtx
	t.mu.Unlock()
	if ctx == nil {
		return deadline, nil
	}
	return deadline, ctx.Done()
}

func (t *tlsBio) Write(data []byte) (int, error) {
	t.logger.Debugf("[tlsbio] write %d bytes head=%s", len(data), bytesx.HexPrefix(data, 32))

	// Fast-path: if we can send immediately, don't consult deadlines.
	select {
	case t.directionDown <- data:
		return len(data), nil
	case <-t.hangup:
		return 0, net.ErrClosed
	default:
	}

	for {
		deadline, done := t.writeDeadlineState()
		if !deadline.IsZero() && time.Until(deadline) <= 0 {
			return 0, os.ErrDeadlineExceeded
		}

		select {
		case t.directionDown <- data:
			return len(data), nil
		case <-t.hangup:
			return 0, net.ErrClosed
		case <-done:
		}
	}
}

func (t *tlsBio) LocalAddr() net.Addr {
	return &tlsBioAddr{}
}

func (t *tlsBio) RemoteAddr() net.Addr {
	return &tlsBioAddr{}
}

func (t *tlsBio) SetDeadline(tt time.Time) error {
	_ = t.SetReadDeadline(tt)
	_ = t.SetWriteDeadline(tt)
	return nil
}

func (t *tlsBio) SetReadDeadline(tt time.Time) error {
	t.mu.Lock()
	oldCancel := t.readCancel
	t.readDeadline = tt
	t.readCtx, t.readCancel = context.WithCancel(context.Background())
	newCancel := t.readCancel
	t.mu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if tt.IsZero() {
		return nil
	}
	if d := time.Until(tt); d <= 0 {
		newCancel()
		return nil
	} else {
		time.AfterFunc(d, newCancel)
	}
	return nil
}

func (t *tlsBio) SetWriteDeadline(tt time.Time) error {
	t.mu.Lock()
	oldCancel := t.writeCancel
	t.writeDeadline = tt
	t.writeCtx, t.writeCancel = context.WithCancel(context.Background())
	newCancel := t.writeCancel
	t.mu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if tt.IsZero() {
		return nil
	}
	if d := time.Until(tt); d <= 0 {
		newCancel()
		return nil
	} else {
		time.AfterFunc(d, newCancel)
	}
	return nil
}

// tlsBioAddr is the type of address returned by [Conn]
type tlsBioAddr struct{}

var _ net.Addr = &tlsBioAddr{}

// Network implements net.Addr
func (*tlsBioAddr) Network() string {
	return "tlsBioAddr"
}

// String implements net.Addr
func (*tlsBioAddr) String() string {
	return "tlsBioAddr"
}
