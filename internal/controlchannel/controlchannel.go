// Package controlchannel implements the control channel logic. The control channel sits
// above the reliable transport and below the TLS layer.
package controlchannel

import (
	"fmt"

	"github.com/6ccg/minivpn/internal/bytesx"
	"github.com/6ccg/minivpn/internal/model"
	"github.com/6ccg/minivpn/internal/session"
	"github.com/6ccg/minivpn/internal/workers"
	"github.com/6ccg/minivpn/pkg/config"
)

var (
	serviceName = "controlchannel"
)

// Service is the controlchannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// NotifyTLS is the channel that sends notifications up to the TLS layer.
	NotifyTLS *chan *model.Notification

	// ControlToReliable moves packets from us down to the reliable layer.
	ControlToReliable *chan *model.Packet

	// ReliableToControl moves packets up to us from the reliable layer below.
	ReliableToControl chan *model.Packet

	// TLSRecordToControl moves bytes down to us from the TLS layer above.
	TLSRecordToControl chan []byte

	// TLSRecordFromControl moves bytes from us up to the TLS layer above.
	TLSRecordFromControl *chan []byte
}

// StartWorkers starts the control-channel workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/6ccg/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	config *config.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		logger:               config.Logger(),
		notifyTLS:            *svc.NotifyTLS,
		controlToReliable:    *svc.ControlToReliable,
		reliableToControl:    svc.ReliableToControl,
		tlsRecordToControl:   svc.TLSRecordToControl,
		tlsRecordFromControl: *svc.TLSRecordFromControl,
		sessionManager:       sessionManager,
		workersManager:       workersManager,
	}
	workersManager.StartWorker(ws.moveUpWorker)
	workersManager.StartWorker(ws.moveDownWorker)
}

// workersState contains the control channel state.
type workersState struct {
	logger               model.Logger
	notifyTLS            chan<- *model.Notification
	controlToReliable    chan<- *model.Packet
	reliableToControl    <-chan *model.Packet
	tlsRecordToControl   <-chan []byte
	tlsRecordFromControl chan<- []byte
	sessionManager       *session.Manager
	workersManager       *workers.Manager
}

func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK on reading the packet moving up the stack
		select {
		case packet := <-ws.reliableToControl:
			ws.logger.Debugf(
				"%s: up %s id=%d replay=%d ts=%d acks=%v payload=%d head=%s",
				workerName,
				packet.Opcode,
				packet.ID,
				packet.ReplayPacketID,
				packet.Timestamp,
				packet.ACKs,
				len(packet.Payload),
				bytesx.HexPrefix(packet.Payload, 32),
			)
			// route the packets depending on their opcode
			switch packet.Opcode {

					case model.P_CONTROL_SOFT_RESET_V1:
				// We cannot blindly accept SOFT_RESET requests. They only make sense
				// when we have received the remote's key material (S_GOT_KEY or later).
				// This matches OpenVPN's DECRYPT_KEY_ENABLED check for client mode.
				// Note that a SOFT_RESET returns us to the INITIAL state, therefore,
				// we will not have concurrent resets in place, even if after the first
				// key generation we receive two SOFT_RESET requests back to back.

				if ws.sessionManager.NegotiationState() < model.S_GOT_KEY {
					packet.Free() // release buffer back to pool
					continue
				}

						remoteKeyID := packet.KeyID

						// Perform key soft reset: move current key to lame duck slot,
						// prepare for new key negotiation. This preserves the old key
						// for transition_window seconds to allow in-flight packets.
						if err := ws.sessionManager.KeySoftReset(); err != nil {
							ws.logger.Warnf("%s: soft reset failed: %v", workerName, err)
							packet.Free() // release buffer back to pool
							continue
						}

						// KeySoftReset already advances key_id internally (matching OpenVPN's
						// key_state_init() behavior), so we must NOT call NextKeyID() again.
						newKeyID := ws.sessionManager.CurrentKeyID()
						if newKeyID != uint8(remoteKeyID) {
							ws.logger.Warnf("%s: server-initiated SOFT_RESET key_id mismatch (remote=%d local=%d)", workerName, remoteKeyID, newKeyID)
						}
						ws.logger.Debugf("%s: server-initiated SOFT_RESET, new key_id=%d", workerName, newKeyID)
						ws.sessionManager.SetNegotiationState(model.S_INITIAL)

				// Release buffer now - no longer needed
				packet.Free()

				// notify the TLS layer that it should initiate
				// a TLS handshake and, if successful, generate
				// new keys for the data channel
				select {
				case ws.notifyTLS <- &model.Notification{Flags: model.NotificationReset}:
					// nothing

				case <-ws.workersManager.ShouldShutdown():
					return
				}

			case model.P_CONTROL_V1:
				// send the packet to the TLS layer
				select {
				case ws.tlsRecordFromControl <- packet.Payload:
					ws.logger.Debugf(
						"%s: delivered tls record len=%d head=%s",
						workerName,
						len(packet.Payload),
						bytesx.HexPrefix(packet.Payload, 32),
					)
					// TLS layer copies payload via bytes.Buffer.Write(),
					// so we can safely release the buffer now.
					packet.Free()

				case <-ws.workersManager.ShouldShutdown():
					return
				}
			default:
				// Unknown opcode, release buffer
				packet.Free()
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

func (ws *workersState) moveDownWorker() {
	workerName := fmt.Sprintf("%s: moveDownWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	for {
		// POSSIBLY BLOCK on reading the TLS record moving down the stack
		select {
		case record := <-ws.tlsRecordToControl:
			// Copy the TLS record because upstream may reuse the backing buffer.
			recordCopy := append([]byte(nil), record...)
			ws.logger.Debugf(
				"%s: down tls record len=%d head=%s",
				workerName,
				len(recordCopy),
				bytesx.HexPrefix(recordCopy, 32),
			)
			// transform the record into a control message
			packet, err := ws.sessionManager.NewPacket(model.P_CONTROL_V1, recordCopy)
			if err != nil {
				ws.logger.Warnf("%s: NewPacket: %s", workerName, err.Error())
				return
			}
			ws.logger.Debugf(
				"%s: created control packet id=%d replay=%d ts=%d payload=%d",
				workerName,
				packet.ID,
				packet.ReplayPacketID,
				packet.Timestamp,
				len(packet.Payload),
			)

			// POSSIBLY BLOCK on sending the packet down the stack
			select {
			case ws.controlToReliable <- packet:
				// nothing

			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}
