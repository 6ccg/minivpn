package reliabletransport

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/6ccg/minivpn/internal/model"
	"github.com/6ccg/minivpn/internal/optional"
	"github.com/6ccg/minivpn/internal/session"
)

// moveUpWorker moves packets up the stack (receiver).
// The sender and receiver data structures lack mutexes because they are
// intended to be confined to a single goroutine (one for each worker), and
// the workers SHOULD ONLY communicate via message passing.
func (ws *workersState) moveUpWorker() {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	receiver := newReliableReceiver(ws.logger, ws.incomingSeen)
	lastRemoteSessionID := append([]byte(nil), ws.sessionManager.RemoteSessionID()...)
	lastControlEpoch := ws.sessionManager.ControlEpoch()

	for {
		// POSSIBLY BLOCK reading a packet to move up the stack
		// or POSSIBLY BLOCK waiting for notifications
		select {
		case packet := <-ws.muxerToReliable:
			// Reset per-session reliable sequencing state when the remote session ID changes.
			// This is required for server-initiated HARD_RESET_SERVER_V2 which starts a new session
			// with packet IDs reset to 0/1.
			if current := ws.sessionManager.RemoteSessionID(); !bytes.Equal(current, lastRemoteSessionID) {
				lastRemoteSessionID = append([]byte(nil), current...)
				receiver.Reset()
			}
			if current := ws.sessionManager.ControlEpoch(); current != lastControlEpoch {
				lastControlEpoch = current
				receiver.Reset()
			}

			ws.tracer.OnIncomingPacket(packet, ws.sessionManager.NegotiationState())

			ws.logger.Debugf(
				"reliabletransport: in opcode=%s id=%d replay=%d ts=%d acks=%v payload=%d",
				packet.Opcode,
				packet.ID,
				packet.ReplayPacketID,
				packet.Timestamp,
				packet.ACKs,
				len(packet.Payload),
			)
			if packet.Opcode != model.P_CONTROL_HARD_RESET_SERVER_V2 {
				// the hard reset has already been logged by the layer below
				packet.Log(ws.logger, model.DirectionIncoming)
			}

			// TODO: are we handling a HARD_RESET_V2 while we're doing a handshake?
			// I'm not sure that's a valid behavior for a server.
			// We should be able to deterministically test how this affects the state machine.

			// sanity check incoming packet
			if ok := incomingSanityChecks(ws.logger, workerName, packet, ws.sessionManager); !ok {
				continue
			}

			// notify seen packet to the sender using the lateral channel.
			seen := receiver.newIncomingPacketSeen(packet)
			select {
			case ws.incomingSeen <- seen:
			case <-ws.workersManager.ShouldShutdown():
				return
			}

			// We need to pass both P_CONTROL_V1 and P_CONTROL_SOFT_RESET_V1 to the control channel.
			// P_CONTROL_V1 carries TLS records, while P_CONTROL_SOFT_RESET_V1 signals server-initiated
			// key renegotiation. Filtering out SOFT_RESET here would prevent the control channel from
			// receiving renegotiation requests, causing the connection to hang when the server initiates
			// a soft reset (the subsequent P_CONTROL_V1 packets would block on TLSRecordUp with no reader).
			// Reference: OpenVPN ssl.c:3543-3557 processes P_CONTROL_SOFT_RESET_V1 inline.
			if packet.Opcode != model.P_CONTROL_V1 && packet.Opcode != model.P_CONTROL_SOFT_RESET_V1 {
				continue
			}

			if packet.Opcode == model.P_CONTROL_SOFT_RESET_V1 {
				receiver.ResetWithStartingID(packet.ID)
			}

			if inserted := receiver.MaybeInsertIncoming(packet); !inserted {
				// this packet was not inserted in the queue: we drop it
				// TODO: add reason
				ws.tracer.OnDroppedPacket(
					model.DirectionIncoming,
					ws.sessionManager.NegotiationState(),
					packet)
				ws.logger.Debugf("Dropping packet: %v", packet.ID)
				continue
			}

			ready := receiver.NextIncomingSequence()
			if len(ready) > 0 {
				ws.logger.Debugf("reliabletransport: ready packets=%d first=%d last=%d", len(ready), ready[0].ID, ready[len(ready)-1].ID)
			}
			for _, nextPacket := range ready {
				// POSSIBLY BLOCK delivering to the upper layer
				select {
				case ws.reliableToControl <- nextPacket:
				case <-ws.workersManager.ShouldShutdown():
					return
				}
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

func incomingSanityChecks(logger model.Logger, workerName string, packet *model.Packet, session *session.Manager) bool {
	// drop a packet from a remote session we don't know about.
	if !bytes.Equal(packet.LocalSessionID[:], session.RemoteSessionID()) {
		logger.Warnf(
			"%s: packet with invalid LocalSessionID: got %x; expected %x",
			workerName,
			packet.LocalSessionID,
			session.RemoteSessionID(),
		)
		return false
	}

	if len(packet.ACKs) == 0 {
		return true
	}

	// only if we get incoming ACKs we can also check that the remote session id matches our own
	// (packets with no ack array do not include remoteSessionID)
	if !bytes.Equal(packet.RemoteSessionID[:], session.LocalSessionID()) {
		logger.Warnf(
			"%s: packet with invalid RemoteSessionID: got %x; expected %x",
			workerName,
			packet.RemoteSessionID,
			session.LocalSessionID(),
		)
		return false
	}
	return true
}

//
// incomingPacketHandler implementation.
//

// reliableReceiver is the receiver part that sees incoming packets moving up the stack.
// Please use the constructor `newReliableReceiver()`
type reliableReceiver struct {
	// logger is the logger to use
	logger model.Logger

	// incomingPackets are packets to process (reorder) before they are passed to TLS layer.
	incomingPackets incomingSequence

	// incomingSeen is a channel where we send notifications for incoming packets seen by us.
	incomingSeen chan<- incomingPacketSeen

	// lastConsumed is the last [model.PacketID] that we have passed to the control layer above us.
	lastConsumed model.PacketID
}

func newReliableReceiver(logger model.Logger, ch chan incomingPacketSeen) *reliableReceiver {
	return &reliableReceiver{
		logger:          logger,
		incomingPackets: make([]*model.Packet, 0),
		incomingSeen:    ch,
		lastConsumed:    0,
	}
}

// Reset clears the per-session receiver state (queue + sequencing counters).
// This is used when the remote session ID changes (HARD reset/new session).
func (r *reliableReceiver) Reset() {
	r.resetWithLastConsumed(0)
}

// ResetWithStartingID clears the per-session receiver state (queue + sequencing
// counters) and prepares for a new control sequence that starts at startID.
//
// This is used for SOFT_RESET-triggered renegotiation where packet IDs restart.
func (r *reliableReceiver) ResetWithStartingID(startID model.PacketID) {
	// lastConsumed tracks the last delivered ID; to accept startID next we need
	// lastConsumed=startID-1 (wraparound allowed).
	r.resetWithLastConsumed(startID - 1)
}

func (r *reliableReceiver) resetWithLastConsumed(lastConsumed model.PacketID) {
	for _, p := range r.incomingPackets {
		if p != nil {
			p.Free()
		}
	}
	r.incomingPackets = make(incomingSequence, 0)
	r.lastConsumed = lastConsumed
}

func packetIDLess(a, b model.PacketID) bool {
	// Implements the same wraparound comparison as OpenVPN's reliable_pid_min():
	// a < b (mod 2^32), allowing wraparound.
	return int32(a-b) < 0
}

func (r *reliableReceiver) MaybeInsertIncoming(p *model.Packet) bool {
	// Check 1: drop replay packets (already consumed)
	// This matches OpenVPN's reliable_not_replay() check: id < packet_id
	nextExpected := r.lastConsumed + 1
	if packetIDLess(p.ID, nextExpected) {
		r.logger.Debugf("dropping replay packet: id=%d < nextExpected=%d", p.ID, nextExpected)
		return false
	}

	// Check 1b: drop packets that would break sequentiality (bounded receive window).
	// This matches OpenVPN's reliable_wont_break_sequentiality().
	if uint32(p.ID-nextExpected) >= uint32(RELIABLE_RECV_BUFFER_SIZE) {
		r.logger.Debugf(
			"dropping packet that breaks sequentiality window: id=%d nextExpected=%d window=%d",
			p.ID,
			nextExpected,
			RELIABLE_RECV_BUFFER_SIZE,
		)
		return false
	}

	// Check 2: drop duplicate packets (already in buffer)
	// This matches OpenVPN's reliable_not_replay() check for active entries
	for _, existing := range r.incomingPackets {
		if existing.ID == p.ID {
			r.logger.Debugf("dropping duplicate packet: id=%d", p.ID)
			return false
		}
	}

	// Check 3: drop if at capacity
	if len(r.incomingPackets) >= RELIABLE_RECV_BUFFER_SIZE {
		r.logger.Warnf("dropping packet, buffer full with len %v", len(r.incomingPackets))
		return false
	}

	// insert this one in the queue to pass to TLS.
	r.incomingPackets = append(r.incomingPackets, p)
	return true
}

func (r *reliableReceiver) NextIncomingSequence() incomingSequence {
	last := r.lastConsumed
	ready := make([]*model.Packet, 0, RELIABLE_RECV_BUFFER_SIZE)

	// sort them so that we begin with lower model.PacketID
	sort.Sort(r.incomingPackets)
	var keep incomingSequence

	for i, p := range r.incomingPackets {
		if p.ID-last == 1 {
			ready = append(ready, p)
			last++
		} else if p.ID > last {
			// here we broke sequentiality, but we want
			// to drop anything that is below lastConsumed
			keep = append(keep, r.incomingPackets[i:]...)
			break
		}
	}
	r.lastConsumed = last
	r.incomingPackets = keep
	return ready
}

func (r *reliableReceiver) newIncomingPacketSeen(p *model.Packet) incomingPacketSeen {
	incomingPacket := incomingPacketSeen{keyID: p.KeyID}
	if p.Opcode == model.P_ACK_V1 {
		incomingPacket.acks = optional.Some(p.ACKs)
	} else {
		incomingPacket.id = optional.Some(p.ID)
		incomingPacket.acks = optional.Some(p.ACKs)
	}

	return incomingPacket
}

// assert that reliableReceiver implements incomingPacketHandler
var _ incomingPacketHandler = &reliableReceiver{}
