package networkio

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/6ccg/minivpn/internal/model"
	"github.com/6ccg/minivpn/internal/workers"
	"github.com/6ccg/minivpn/pkg/config"
)

var (
	serviceName = "networkio"
)

// isTemporaryError checks if an error is temporary and should be ignored.
// This matches OpenVPN's ignore_sys_error() behavior in error.h.
func isTemporaryError(err error) bool {
	// Check for timeout errors (like EAGAIN/EWOULDBLOCK)
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	// Check for specific syscall errors that should be ignored
	var syscallErr syscall.Errno
	if errors.As(err, &syscallErr) {
		switch syscallErr {
		case syscall.EAGAIN, syscall.EWOULDBLOCK, syscall.EINTR:
			return true
		}
	}

	return false
}

// isConnectionReset checks if an error indicates a connection reset.
// This matches OpenVPN's socket_connection_reset() behavior in socket.h.
func isConnectionReset(err error) bool {
	// Check for EOF (connection closed gracefully)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// Check for network closed errors
	if errors.Is(err, net.ErrClosed) {
		return true
	}

	// Check for specific syscall errors indicating connection reset
	var syscallErr syscall.Errno
	if errors.As(err, &syscallErr) {
		switch syscallErr {
		case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE:
			return true
		}
	}

	// Check for os.ErrDeadlineExceeded (context deadline)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return false // This is a timeout, not a reset
	}

	return false
}

// Service is the network I/O service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// MuxerToNetwork moves bytes down from the muxer to the network IO layer
	MuxerToNetwork chan []byte

	// NetworkToMuxer moves bytes up from the network IO layer to the muxer
	NetworkToMuxer *chan []byte
}

// StartWorkers starts the network I/O workers. See the [ARCHITECTURE]
// file for more information about the network I/O workers.
//
// [ARCHITECTURE]: https://github.com/6ccg/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	config *config.Config,
	manager *workers.Manager,
	conn FramingConn,
) {
	ws := &workersState{
		conn:           conn,
		logger:         config.Logger(),
		manager:        manager,
		muxerToNetwork: svc.MuxerToNetwork,
		networkToMuxer: *svc.NetworkToMuxer,
	}

	manager.StartWorker(ws.moveUpWorker)
	manager.StartWorker(ws.moveDownWorker)
}

// workersState contains the service workers state
type workersState struct {
	// conn is the connection to use
	conn FramingConn

	// logger is the logger to use
	logger model.Logger

	// manager controls the workers lifecycle
	manager *workers.Manager

	// muxerToNetwork is the channel for reading outgoing packets
	// that are coming down to us
	muxerToNetwork <-chan []byte

	// networkToMuxer is the channel for writing incoming packets
	// that are coming up to us from the net
	networkToMuxer chan<- []byte
}

// moveUpWorker moves packets up the stack.
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		// make sure the manager knows we're done
		ws.manager.OnWorkerDone(workerName)

		// tear down everything else because a workers exited
		ws.manager.StartShutdown()
	}()

	ws.logger.Debug("networkio: moveUpWorker: started")

	for {
		// Check if we should shutdown before blocking on read
		select {
		case <-ws.manager.ShouldShutdown():
			return
		default:
		}

		// POSSIBLY BLOCK on the connection to read a new packet
		pkt, err := ws.conn.ReadRawPacket()
		if err != nil {
			// Match OpenVPN's error handling behavior from forward.c:read_incoming_link()

			// 1. Check for temporary errors that should be ignored (like EAGAIN)
			// This matches OpenVPN's ignore_sys_error() in error.h
			if isTemporaryError(err) {
				ws.logger.Debugf("%s: ReadRawPacket: temporary error (ignored): %s", workerName, err.Error())
				continue
			}

			// 2. Check for connection reset - log and exit
			// This matches OpenVPN's socket_connection_reset() in socket.h
			if isConnectionReset(err) {
				ws.logger.Infof("%s: ReadRawPacket: connection reset: %s", workerName, err.Error())
				return
			}

			// 3. Other errors - log and exit
			ws.logger.Infof("%s: ReadRawPacket: %s", workerName, err.Error())
			return
		}

		// POSSIBLY BLOCK on the channel to deliver the packet
		select {
		case ws.networkToMuxer <- pkt:
		case <-ws.manager.ShouldShutdown():
			return
		}
	}
}

// moveDownWorker moves packets down the stack
func (ws *workersState) moveDownWorker() {
	workerName := fmt.Sprintf("%s: moveDownWorker", serviceName)

	defer func() {
		// make sure the manager knows we're done
		ws.manager.OnWorkerDone(workerName)

		// tear down everything else because a worker exited
		ws.manager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK when receiving from channel.
		select {
		case pkt := <-ws.muxerToNetwork:
			// POSSIBLY BLOCK on the connection to write the packet
			if err := ws.conn.WriteRawPacket(pkt); err != nil {
				// Match OpenVPN's error handling behavior from forward.c:process_outgoing_link()

				// 1. Check for temporary errors that should be ignored (like EAGAIN)
				if isTemporaryError(err) {
					ws.logger.Debugf("%s: WriteRawPacket: temporary error (ignored): %s", workerName, err.Error())
					continue
				}

				// 2. Check for connection reset - log and exit
				if isConnectionReset(err) {
					ws.logger.Infof("%s: WriteRawPacket: connection reset: %s", workerName, err.Error())
					return
				}

				// 3. Other errors - log and exit
				ws.logger.Infof("%s: WriteRawPacket: %s", workerName, err.Error())
				return
			}

		case <-ws.manager.ShouldShutdown():
			return
		}
	}
}
