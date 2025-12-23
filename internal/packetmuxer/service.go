// Package packetmuxer implements the packet-muxer workers.
package packetmuxer

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ooni/minivpn/internal/bytespool"
	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/wire"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

// debugWireEnabled checks if wire-level debug is enabled
func debugWireEnabled() bool {
	return os.Getenv("MINIVPN_DEBUG_WIRE") == "1" || os.Getenv("MINIVPN_DEBUG_ALL") == "1"
}

var serviceName = "packetmuxer"

const (
	// A sufficiently long wakup period to initialize a ticker with.
	longWakeup = time.Hour * 24 * 30
)

// Service is the packetmuxer service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// HardReset receives requests to initiate a hard reset, that will start the openvpn handshake.
	HardReset chan any

	// NotifyTLS sends reset notifications to tlsstate.
	NotifyTLS *chan *model.Notification

	// MuxerToReliable moves packets up to reliabletransport.
	MuxerToReliable *chan *model.Packet

	// MuxerToData moves packets up to the datachannel.
	MuxerToData *chan *model.Packet

	// DataOrControlToMuxer moves packets down from the reliabletransport or datachannel.
	DataOrControlToMuxer chan *model.Packet

	// MuxerToNetwork moves bytes down to the networkio layer below us.
	MuxerToNetwork *chan []byte

	// NetworkToMuxer moves bytes up to us from the networkio layer below.
	NetworkToMuxer chan []byte
}

// StartWorkers starts the packet-muxer workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (s *Service) StartWorkers(
	config *config.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		logger:    config.Logger(),
		hardReset: s.HardReset,
		// initialize to a sufficiently long time from now
		hardResetTicker:      time.NewTicker(longWakeup),
		notifyTLS:            *s.NotifyTLS,
		dataOrControlToMuxer: s.DataOrControlToMuxer,
		muxerToReliable:      *s.MuxerToReliable,
		muxerToData:          *s.MuxerToData,
		muxerToNetwork:       *s.MuxerToNetwork,
		networkToMuxer:       s.NetworkToMuxer,
		sessionManager:       sessionManager,
		tracer:               config.Tracer(),
		workersManager:       workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the reliabletransport workers state.
type workersState struct {
	// logger is the logger to use
	logger model.Logger

	// hardReset is the channel posted to force a hard reset.
	hardReset <-chan any

	// how many times have we sent the initial hardReset packet
	hardResetCount int

	// hardResetTimeout is the current retry timeout (exponential backoff)
	hardResetTimeout time.Duration

	// hardResetTicker is a channel to retry the initial send of hard reset packet.
	hardResetTicker *time.Ticker

	// notifyTLS is used to send notifications to the TLS service.
	notifyTLS chan<- *model.Notification

	// dataOrControlToMuxer is the channel for reading all the packets traveling down the stack.
	dataOrControlToMuxer <-chan *model.Packet

	// muxerToReliable is the channel for writing control packets going up the stack.
	muxerToReliable chan<- *model.Packet

	// muxerToData is the channel for writing data packets going up the stack.
	muxerToData chan<- *model.Packet

	// muxerToNetwork is the channel for writing raw packets going down the stack.
	muxerToNetwork chan<- []byte

	// networkToMuxer is the channel for reading raw packets going up the stack.
	networkToMuxer <-chan []byte

	// sessionManager manages the OpenVPN session.
	sessionManager *session.Manager

	// tracer is a [model.HandshakeTracer].
	tracer model.HandshakeTracer

	// workersManager controls the workers lifecycle.
	workersManager *workers.Manager

	// loggedIncomingDataPacket indicates whether we've logged the first incoming data packet.
	loggedIncomingDataPacket bool

	// loggedOutgoingDataPacket indicates whether we've logged the first outgoing data packet.
	loggedOutgoingDataPacket bool
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK awaiting for incoming raw packet
		select {
		case rawPacket := <-ws.networkToMuxer:
			if err := ws.handleRawPacket(rawPacket); err != nil {
				// error already printed
				// TODO(ainghazal): trace malformed input
				continue
			}

		case <-ws.hardResetTicker.C:
			// retry the hard reset, it probably was lost
			if err := ws.startHardReset(); err != nil {
				// error already logged
				return
			}

		case <-ws.hardReset:
			if err := ws.startHardReset(); err != nil {
				// error already logged
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// moveDownWorker moves packets down the stack
func (ws *workersState) moveDownWorker() {
	workerName := fmt.Sprintf("%s: moveDownWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK on reading the packet moving down the stack
		select {
		case packet := <-ws.dataOrControlToMuxer:
			// serialize the packet
			rawPacket, err := wire.MarshalPacket(packet, ws.sessionManager.PacketAuth())
			if err != nil {
				ws.logger.Warnf("%s: cannot serialize packet: %s", workerName, err.Error())
				continue
			}

			if packet.IsData() && !ws.loggedOutgoingDataPacket {
				ws.loggedOutgoingDataPacket = true
				if parsed, err := model.ParsePacket(rawPacket); err == nil {
					ws.logger.Infof(
						"packetmuxer: first outgoing data packet (opcode=%s key-id=%d peer-id=%x len=%d)",
						parsed.Opcode,
						parsed.KeyID,
						parsed.PeerID,
						len(rawPacket),
					)
				} else {
					ws.logger.Infof("packetmuxer: first outgoing data packet (unparsed len=%d err=%s)", len(rawPacket), err.Error())
				}
			}

			// POSSIBLY BLOCK on writing the packet to the networkio layer.
			// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md

			select {
			case ws.muxerToNetwork <- rawPacket:
				// nothing
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// startHardReset is invoked when we need to perform a HARD RESET.
func (ws *workersState) startHardReset() error {
	// increment the hard reset counter for retries
	ws.hardResetCount++

	// initialize timeout on first attempt (exponential backoff like OpenVPN)
	if ws.hardResetTimeout == 0 {
		ws.hardResetTimeout = 2 * time.Second
	}

	// reset the state to become initial again.
	ws.sessionManager.SetNegotiationState(model.S_PRE_START)

	// Reset the control channel replay filter for the new session.
	ws.sessionManager.ResetControlReplay()

	// emit a CONTROL_HARD_RESET_CLIENT_V2 pkt
	packet := ws.sessionManager.NewHardResetPacket()
	ws.logger.Debugf(
		"packetmuxer: startHardReset count=%d timeout=%v opcode=%s replay=%d ts=%d",
		ws.hardResetCount,
		ws.hardResetTimeout,
		packet.Opcode,
		packet.ReplayPacketID,
		packet.Timestamp,
	)
	if err := ws.serializeAndEmit(packet); err != nil {
		return err
	}

	// resend with exponential backoff if not received the server's reply
	ws.hardResetTicker.Reset(ws.hardResetTimeout)
	ws.hardResetTimeout *= 2 // exponential backoff
	if ws.hardResetTimeout > 64*time.Second {
		ws.hardResetTimeout = 64 * time.Second // cap at 64 seconds
	}

	return nil
}

// handleRawPacket is the code invoked to handle a raw packet.
// The rawPacket is from the bytespool and will be released when the packet is Free()'d.
func (ws *workersState) handleRawPacket(rawPacket []byte) error {
	// Debug: full wire dump of incoming packet
	if debugWireEnabled() {
		log.Printf("[DEBUG-WIRE] <<< RECV raw (%d bytes): %x", len(rawPacket), rawPacket)
		// Break down the packet for tls-auth
		if ws.sessionManager.PacketAuth().Mode == wire.ControlSecurityModeTLSAuth {
			digestSize := ws.sessionManager.PacketAuth().TLSAuthDigest.Size()
			if digestSize == 0 {
				digestSize = 20
			}
			minLen := 9 + digestSize + 8
			if len(rawPacket) >= minLen {
				log.Printf("[DEBUG-WIRE] <<< RECV breakdown (tls-auth):")
				log.Printf("[DEBUG-WIRE]     opcode/key (1): %x", rawPacket[0:1])
				log.Printf("[DEBUG-WIRE]     session_id (8): %x", rawPacket[1:9])
				log.Printf("[DEBUG-WIRE]     hmac (%d): %x", digestSize, rawPacket[9:9+digestSize])
				log.Printf("[DEBUG-WIRE]     replay_id (4): %x", rawPacket[9+digestSize:13+digestSize])
				log.Printf("[DEBUG-WIRE]     timestamp (4): %x", rawPacket[13+digestSize:17+digestSize])
				log.Printf("[DEBUG-WIRE]     rest (%d): %x", len(rawPacket)-(17+digestSize), rawPacket[17+digestSize:])
			}
		}
	}

	ws.logger.Debugf(
		"packetmuxer: raw in len=%d head=%s",
		len(rawPacket),
		bytesx.HexPrefix(rawPacket, 32),
	)
	// make sense of the packet
	packet, err := wire.UnmarshalPacket(rawPacket, ws.sessionManager.PacketAuth())
	if err != nil {
		ws.logger.Warnf(
			"packetmuxer: moveUpWorker: ParsePacket: %s rawlen=%d head=%s",
			err.Error(),
			len(rawPacket),
			bytesx.HexPrefix(rawPacket, 32),
		)
		// Release the buffer back to pool on parse error
		bytespool.Default.Put(rawPacket)
		return nil // keep running
	}

	// Set release callback to return rawPacket to pool when Free() is called.
	// The packet's Payload is a slice of rawPacket, so we must keep rawPacket
	// alive until the packet is fully processed.
	packet.SetReleaseFunc(func() {
		bytespool.Default.Put(rawPacket)
	})
	ws.logger.Debugf(
		"packetmuxer: parsed opcode=%s key=%d peer=%x id=%d replay=%d ts=%d acks=%v payload=%d head=%s",
		packet.Opcode,
		packet.KeyID,
		packet.PeerID,
		packet.ID,
		packet.ReplayPacketID,
		packet.Timestamp,
		packet.ACKs,
		len(packet.Payload),
		bytesx.HexPrefix(packet.Payload, 32),
	)

	if packet.IsData() {
		ws.sessionManager.MaybeSetDataOpcode(packet.Opcode)
		if packet.Opcode == model.P_DATA_V2 {
			peerID := int(packet.PeerID[0])<<16 | int(packet.PeerID[1])<<8 | int(packet.PeerID[2])
			ws.sessionManager.MaybeSetPeerID(peerID)
		}
	}

	// Replay protection check for control channel packets.
	// This validates the ReplayPacketID and Timestamp fields to prevent replay attacks.
	// Only effective when control channel security (tls-auth/tls-crypt) is enabled.
	if packet.IsControl() || packet.Opcode == model.P_ACK_V1 {
		if err := ws.sessionManager.CheckControlReplay(packet.ReplayPacketID, packet.Timestamp); err != nil {
			ws.logger.Warnf(
				"packetmuxer: control channel replay attack detected: %s (replay=%d ts=%d)",
				err.Error(),
				packet.ReplayPacketID,
				packet.Timestamp,
			)
			packet.Free() // release buffer back to pool
			return nil    // drop the packet silently
		}
	}

	// Update last packet time for keepalive tracking.
	// This applies to all valid packets (control and data).
	// Reference: OpenVPN 2.5 src/openvpn/forward.c - any incoming packet resets the timer.
	ws.sessionManager.UpdateLastPacketTime()

	// handle the case where we're performing a HARD_RESET
	if ws.sessionManager.NegotiationState() == model.S_PRE_START &&
		packet.Opcode == model.P_CONTROL_HARD_RESET_SERVER_V2 {
		packet.Log(ws.logger, model.DirectionIncoming)
		ws.hardResetTicker.Stop()
		return ws.finishThreeWayHandshake(packet)
	}

	// multiplex the incoming packet POSSIBLY BLOCKING on delivering it
	if packet.IsControl() || packet.Opcode == model.P_ACK_V1 {
		select {
		case ws.muxerToReliable <- packet:
		case <-ws.workersManager.ShouldShutdown():
			return workers.ErrShutdown
		}
	} else {
		if packet.IsData() && !ws.loggedIncomingDataPacket && ws.sessionManager.NegotiationState() >= model.S_GENERATED_KEYS {
			ws.loggedIncomingDataPacket = true
			ws.logger.Infof(
				"packetmuxer: first incoming data packet (opcode=%s key-id=%d peer-id=%x len=%d)",
				packet.Opcode,
				packet.KeyID,
				packet.PeerID,
				len(rawPacket),
			)
		}
		if ws.sessionManager.NegotiationState() < model.S_GENERATED_KEYS {
			// A well-behaved server should not send us data packets
			// before we have a working session. Under normal operations, the
			// connection in the client side should pick a different port,
			// so that data sent from previous sessions will not be delivered.
			// However, it does not harm to be defensive here. One such case
			// is that we get injected packets intended to mess with the handshake.
			// In this case, the caller will drop and log/trace the event.
			if packet.IsData() {
				ws.logger.Debugf(
					"packetmuxer: moveUpWorker: drop early data packet (opcode=%s key-id=%d peer-id=%x len=%d)",
					packet.Opcode,
					packet.KeyID,
					packet.PeerID,
					len(rawPacket),
				)
				packet.Free() // release buffer back to pool
				return nil
			}
			ws.logger.Warnf("malformed input")
			packet.Free() // release buffer back to pool
			return errors.New("malformed input")
		}
		select {
		case ws.muxerToData <- packet:
		case <-ws.workersManager.ShouldShutdown():
			return workers.ErrShutdown
		}
	}

	return nil
}

// finishThreeWayHandshake responds to the HARD_RESET_SERVER and finishes the handshake.
func (ws *workersState) finishThreeWayHandshake(packet *model.Packet) error {
	// register the server's session (note: the PoV is the server's one)
	ws.sessionManager.SetRemoteSessionID(packet.LocalSessionID)

	// reset exponential backoff state for next connection attempt
	ws.hardResetTimeout = 0
	ws.hardResetCount = 0

	// advance the state
	ws.sessionManager.SetNegotiationState(model.S_START)

	// pass the packet up so that we can ack it properly
	select {
	case ws.muxerToReliable <- packet:
	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	// attempt to tell TLS we want to handshake.
	// This WILL BLOCK if the notifyTLS channel
	// is Full, but we make sure we control that we don't pass spurious soft-reset packets while we're
	// doing a handshake.
	select {
	case ws.notifyTLS <- &model.Notification{Flags: model.NotificationReset}:
		// nothing
	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	return nil
}

// serializeAndEmit will write a serialized packet on the channel going down to the networkio layer.
func (ws *workersState) serializeAndEmit(packet *model.Packet) error {
	// serialize it
	rawPacket, err := wire.MarshalPacket(packet, ws.sessionManager.PacketAuth())
	if err != nil {
		return err
	}

	// Debug: full wire dump of outgoing packet
	if debugWireEnabled() {
		log.Printf("[DEBUG-WIRE] >>> SEND raw (%d bytes): %x", len(rawPacket), rawPacket)
		// Break down the packet for tls-auth
		if ws.sessionManager.PacketAuth().Mode == wire.ControlSecurityModeTLSAuth {
			digestSize := ws.sessionManager.PacketAuth().TLSAuthDigest.Size()
			if digestSize == 0 {
				digestSize = 20
			}
			minLen := 9 + digestSize + 8
			if len(rawPacket) >= minLen {
				log.Printf("[DEBUG-WIRE] >>> SEND breakdown (tls-auth):")
				log.Printf("[DEBUG-WIRE]     opcode/key (1): %x", rawPacket[0:1])
				log.Printf("[DEBUG-WIRE]     session_id (8): %x", rawPacket[1:9])
				log.Printf("[DEBUG-WIRE]     hmac (%d): %x", digestSize, rawPacket[9:9+digestSize])
				log.Printf("[DEBUG-WIRE]     replay_id (4): %x", rawPacket[9+digestSize:13+digestSize])
				log.Printf("[DEBUG-WIRE]     timestamp (4): %x", rawPacket[13+digestSize:17+digestSize])
				log.Printf("[DEBUG-WIRE]     rest (%d): %x", len(rawPacket)-(17+digestSize), rawPacket[17+digestSize:])
			}
		}
	}

	ws.tracer.OnOutgoingPacket(
		packet,
		ws.sessionManager.NegotiationState(),
		ws.hardResetCount,
	)

	// emit the packet. Possibly BLOCK writing to the networkio layer.
	select {
	case ws.muxerToNetwork <- rawPacket:
		// nothing

	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}

	packet.Log(ws.logger, model.DirectionOutgoing)
	return nil
}
