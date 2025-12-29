package datachannel

//
// OpenVPN data channel
//

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

var (
	serviceName = "datachannel"

	// ErrPingTimeout is the error returned when a ping timeout is detected.
	ErrPingTimeout = errors.New("ping timeout")

	// ErrPingExit is the error returned when ping-exit triggers connection termination.
	ErrPingExit = errors.New("ping-exit timeout")
)

// Service is the datachannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// MuxerToData moves packets up to us
	MuxerToData chan *model.Packet

	// DataOrControlToMuxer is a shared channel to write packets to the muxer layer below
	DataOrControlToMuxer *chan *model.Packet

	// TUNToData moves bytes down from the TUN layer above
	TUNToData chan []byte

	// DataToTUN moves bytes up from us to the TUN layer above us
	DataToTUN chan []byte

	// KeyReady is where the TLSState layer passes us any new keys
	KeyReady chan *session.DataChannelKey

	// NotifyTLS is used to trigger TLS handshake for renegotiation
	NotifyTLS *chan *model.Notification

	// ControlToReliable is used to send control packets (like SOFT_RESET) to reliable transport
	ControlToReliable *chan *model.Packet
}

// StartWorkers starts the data-channel workers.
//
// We start six workers:
//
// 1. moveUpWorker BLOCKS on dataPacketUp to read a packet coming from the muxer and
// eventually BLOCKS on tunUp to deliver it;
//
// 2. moveDownWorker BLOCKS on tunDown to read a packet and
// eventually BLOCKS on dataOrControlToMuxer to deliver it;
//
// 3. keyWorker BLOCKS on keyUp to read a dataChannelKey and
// initializes the internal state with the resulting key;
//
// 4. keepaliveWorker sends periodic ping packets to keep the connection alive.
//
// 5. renegotiationWorker periodically checks if key renegotiation is needed.
//
// 6. lameDuckWorker periodically checks if lame duck keys have expired.
func (s *Service) StartWorkers(
	config *config.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	opts := config.OpenVPNOptions()

	// Initialize fragment master if enabled (UDP only)
	var fm *FragmentMaster
	if !opts.Proto.IsTCP() && opts.Fragment > 0 {
		fm = NewFragmentMaster(config.Logger(), opts.Fragment)
		config.Logger().Infof("Fragment enabled: max_size=%d", opts.Fragment)
	}

	// Get ping configuration from session manager
	pingInterval, pingTimeout, pingTimeoutAction := sessionManager.PingConfig()

	// pingInterval is 0 when ping is disabled (OpenVPN semantics).
	var pingDuration time.Duration
	if pingInterval > 0 {
		pingDuration = time.Duration(pingInterval) * time.Second
	}

	ws := &workersState{
		options:              opts,
		dataOrControlToMuxer: *s.DataOrControlToMuxer,
		dataToTUN:            s.DataToTUN,
		keyReady:             s.KeyReady,
		logger:               config.Logger(),
		muxerToData:          s.MuxerToData,
		sessionManager:       sessionManager,
		tunToData:            s.TUNToData,
		workersManager:       workersManager,
		fragmentMaster:       fm,
		pingInterval:         pingDuration,
		pingTimeout:          time.Duration(pingTimeout) * time.Second,
		pingTimeoutAction:    pingTimeoutAction,
	}

	// Set optional channels for renegotiation support
	if s.NotifyTLS != nil {
		ws.notifyTLS = *s.NotifyTLS
	}
	if s.ControlToReliable != nil {
		ws.controlToReliable = *s.ControlToReliable
	}

	firstKeyReady := make(chan any)

	workersManager.StartWorker(func() { ws.moveUpWorker(firstKeyReady) })
	workersManager.StartWorker(func() { ws.moveDownWorker(firstKeyReady) })
	workersManager.StartWorker(func() { ws.keyWorker(firstKeyReady) })
	workersManager.StartWorker(func() { ws.keepaliveWorker(firstKeyReady) })
	workersManager.StartWorker(func() { ws.renegotiationWorker(firstKeyReady) })
	workersManager.StartWorker(func() { ws.lameDuckWorker(firstKeyReady) })
}

// workersState contains the data channel state.
type workersState struct {
	dataChannel *DataChannel
	// dataChannelMu 保护 dataChannel 实例的访问。
	// 锁顺序约定: 如果需要同时持有 dataChannelMu 和 session.Manager.mu，
	// 必须先获取 dataChannelMu，再获取 Manager.mu，以避免死锁。
	// 当前代码遵守此约定，参见 keyWorker() 实现。
	dataChannelMu        sync.RWMutex
	options              *config.OpenVPNOptions
	dataOrControlToMuxer chan<- *model.Packet
	dataToTUN            chan<- []byte
	keyReady             <-chan *session.DataChannelKey
	logger               model.Logger
	muxerToData          <-chan *model.Packet
	sessionManager       *session.Manager
	tunToData            <-chan []byte
	workersManager       *workers.Manager
	fragmentMaster       *FragmentMaster // Fragment support (nil if disabled)

	// Renegotiation support
	notifyTLS         chan<- *model.Notification // For triggering TLS handshake
	controlToReliable chan<- *model.Packet       // For sending SOFT_RESET packets

	// Ping/keepalive configuration
	pingInterval      time.Duration // Configured --ping interval (0 = disabled)
	pingTimeout       time.Duration // Configured ping-restart or ping-exit timeout (0 = disabled)
	pingTimeoutAction int           // Timeout action (from session.PingTimeoutAction*)
}

// getDataChannel returns the current dataChannel with read lock protection.
// Returns nil if dataChannel is not yet initialized.
func (ws *workersState) getDataChannel() *DataChannel {
	ws.dataChannelMu.RLock()
	defer ws.dataChannelMu.RUnlock()
	return ws.dataChannel
}

// moveDownWorker moves packets down the stack. It will BLOCK on PacketDown
func (ws *workersState) moveDownWorker(firstKeyReady <-chan any) {
	workerName := serviceName + ":moveDownWorker"
	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	select {
	// wait for the first key to be ready
	case <-firstKeyReady:
		for {
			// First, drain any pending fragments
			if ws.fragmentMaster != nil {
				for {
					fragData, ok := ws.fragmentMaster.FragmentReadyToSend()
					if !ok {
						break
					}
					dc := ws.getDataChannel()
					if dc == nil {
						break
					}
					fragPacket := dc.createDataPacket(fragData)
					select {
					case ws.dataOrControlToMuxer <- fragPacket:
					case <-ws.workersManager.ShouldShutdown():
						return
					}
				}
			}

			select {
			case data := <-ws.tunToData:
				dc := ws.getDataChannel()
				if dc == nil {
					ws.logger.Warnf("dataChannel not ready")
					continue
				}
				packet, err := dc.writePacket(data)
				if err != nil {
					ws.logger.Warnf("error encrypting: %v", err)
					continue
				}

				// Track bytes and packets written for renegotiation (per-key counters).
				// Matches OpenVPN ssl.c:3889-3890 where ks->n_packets++ and ks->n_bytes
				// are updated on the send path.
				ws.sessionManager.AddKeyBytes(session.KS_PRIMARY, 0, int64(len(packet.Payload)))
				ws.sessionManager.AddKeyPackets(session.KS_PRIMARY, 0, 1)

				// Event-driven renegotiation check (matches OpenVPN ssl.c:2668-2684)
				ws.checkRenegotiation()

				// Apply fragmentation if enabled
				if ws.fragmentMaster != nil && ws.fragmentMaster.Enabled {
					ws.sendWithFragmentation(packet)
				} else {
					select {
					case ws.dataOrControlToMuxer <- packet:
					case <-ws.workersManager.ShouldShutdown():
						return
					}
				}

			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}

// sendWithFragmentation fragments the encrypted packet and sends all fragments
func (ws *workersState) sendWithFragmentation(packet *model.Packet) {
	// Get the encrypted payload
	encryptedData := packet.Payload

	// Fragment the data
	firstFrag, err := ws.fragmentMaster.FragmentOutgoing(encryptedData)
	if err != nil {
		ws.logger.Warnf("fragment error: %v", err)
		return
	}

	// Send first fragment
	dc := ws.getDataChannel()
	if dc == nil {
		ws.logger.Warnf("dataChannel not ready for fragmentation")
		return
	}
	fragPacket := dc.createDataPacket(firstFrag)
	select {
	case ws.dataOrControlToMuxer <- fragPacket:
	case <-ws.workersManager.ShouldShutdown():
		return
	}

	// Send remaining fragments
	for {
		fragData, ok := ws.fragmentMaster.FragmentReadyToSend()
		if !ok {
			break
		}
		dc := ws.getDataChannel()
		if dc == nil {
			break
		}
		fragPacket := dc.createDataPacket(fragData)
		select {
		case ws.dataOrControlToMuxer <- fragPacket:
		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker(firstKeyReady <-chan any) {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {

		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("%s: started", workerName)

	select {
	// wait for the first key to be ready
	case <-firstKeyReady:
		for {
			select {
			// TODO: opportunistically try to kill lame duck

			case pkt := <-ws.muxerToData:
				// Handle fragmentation if enabled
				payload := pkt.Payload
				if ws.fragmentMaster != nil && ws.fragmentMaster.Enabled {
					reassembled, err := ws.fragmentMaster.FragmentIncoming(payload)
					if err != nil {
						ws.logger.Warnf("fragment reassembly error: %v", err)
						pkt.Free() // release buffer back to pool
						continue
					}
					if reassembled == nil {
						// Reassembly not complete, wait for more fragments
						pkt.Free() // release buffer back to pool
						continue
					}
					// Use reassembled data
					pkt.Payload = reassembled
				}

				dc := ws.getDataChannel()
				if dc == nil {
					ws.logger.Warnf("dataChannel not ready for decryption")
					pkt.Free() // release buffer back to pool
					continue
				}
				decrypted, err := dc.readPacket(pkt)

				// Release original encrypted buffer back to pool.
				// After decryption, the original buffer is no longer needed.
				pkt.Free()

				if err != nil {
					ws.logger.Warnf("error decrypting: %v", err)
					continue
				}

				// Note: per-key byte/packet counters are updated inside ReadPacket()
				// (controller.go:298-299) using AddKeyBytes/AddKeyPackets, which also
				// update the legacy global counters for backward compatibility.

				// Event-driven renegotiation check (matches OpenVPN ssl.c:2668-2684)
				ws.checkRenegotiation()

				if IsPingPacket(decrypted) {
					// OpenVPN keepalive/ping packet received - drop it as it's not real data.
					// Reference: OpenVPN 2.5 src/openvpn/forward.c:1110 is_ping_msg()
					ws.logger.Debugf("datachannel: keepalive packet received")
					continue
				}

				// POSSIBLY BLOCK writing up towards TUN
				ws.dataToTUN <- decrypted
			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}

// keyWorker receives notifications from key ready
func (ws *workersState) keyWorker(firstKeyReady chan<- any) {
	workerName := fmt.Sprintf("%s: keyWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)
	once := &sync.Once{}

	for {
		select {
		case key := <-ws.keyReady:
			// Use write lock to protect dataChannel initialization and key setup
			ws.dataChannelMu.Lock()

			if ws.dataChannel == nil {
				dc, err := NewDataChannelFromOptions(ws.logger, ws.options, ws.sessionManager)
				if err != nil {
					ws.dataChannelMu.Unlock()
					ws.logger.Warnf("cannot initialize channel %v", err)
					select {
					case ws.sessionManager.Failure <- err:
					default:
					}
					return
				}
				ws.dataChannel = dc
			}

			// Use the current key_id (already advanced by KeySoftReset during rotation).
			// This keeps data-channel key material aligned with the session manager.
			keyID := ws.sessionManager.CurrentKeyID()
			err := ws.dataChannel.SetupKeysForSlot(key, session.KS_PRIMARY, keyID)
			ws.dataChannelMu.Unlock()

			if err != nil {
				ws.logger.Warnf("error on key derivation: %v", err)

				// Distinguish between initial key derivation and key rotation.
				// Similar to OpenVPN's handling: fatal error on initial, recoverable on rotation.
				if ws.sessionManager.NegotiationState() < model.S_GENERATED_KEYS {
					// Initial key derivation failed - fatal error, notify upper layer
					ws.sessionManager.SetNegotiationState(model.S_ERROR)
					select {
					case ws.sessionManager.Failure <- fmt.Errorf("key derivation failed: %w", err):
					default:
					}
					return
				}
				// Key rotation failed - old key still usable, wait for next rotation attempt
				ws.logger.Warnf("key rotation failed, continuing with current key")
				continue
			}
			// Mark per-key state as established so DataKeyID() can correctly choose
			// between primary and lame duck during rotation (OpenVPN 2.5 behavior).
			ws.sessionManager.MarkPrimaryKeyEstablished()
			ws.sessionManager.SetNegotiationState(model.S_GENERATED_KEYS)
			once.Do(func() {
				close(firstKeyReady)
			})

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// keepaliveWorker sends periodic ping packets and monitors for inactivity timeout.
// This implements the client-side --ping, --ping-restart, and --ping-exit functionality.
//
// Reference: OpenVPN 2.5 src/openvpn/ping.c check_ping_send_dowork()
// Reference: OpenVPN 2.5 src/openvpn/forward.c check_timeout()
func (ws *workersState) keepaliveWorker(firstKeyReady <-chan any) {
	workerName := fmt.Sprintf("%s: keepaliveWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		// Note: we may trigger shutdown depending on ping-exit
	}()

	ws.logger.Debugf("%s: started (ping=%v, timeout=%v, action=%d)",
		workerName, ws.pingInterval, ws.pingTimeout, ws.pingTimeoutAction)

	select {
	// wait for the first key to be ready
	case <-firstKeyReady:
		// Initialize last packet time now that we have a working connection
		ws.sessionManager.UpdateLastPacketTime()

		// Refresh ping configuration now that the control channel negotiation
		// (including PUSH_REPLY) has completed and may have updated ping options.
		pingIntervalSeconds, pingTimeoutSeconds, pingTimeoutAction := ws.sessionManager.PingConfig()
		ws.pingTimeoutAction = pingTimeoutAction
		ws.pingTimeout = time.Duration(pingTimeoutSeconds) * time.Second
		if pingIntervalSeconds > 0 {
			ws.pingInterval = time.Duration(pingIntervalSeconds) * time.Second
		} else {
			ws.pingInterval = 0
		}

		activityChan := ws.sessionManager.OutgoingPacketActivity()

		// Ping send timer (optional; --ping may be disabled).
		//
		// OpenVPN 2.5 semantics: only send a ping when there has been no
		// outgoing traffic for --ping seconds; any outgoing packet resets the
		// timer (forward.c:1642 event_timeout_reset(&ping_send_interval)).
		var pingTimer *time.Timer
		var pingChan <-chan time.Time
		resetPingTimer := func() {}
		if ws.pingInterval > 0 {
			pingTimer = time.NewTimer(ws.pingInterval)
			defer pingTimer.Stop()
			pingChan = pingTimer.C
			resetPingTimer = func() {
				if !pingTimer.Stop() {
					select {
					case <-pingTimer.C:
					default:
					}
				}
				pingTimer.Reset(ws.pingInterval)
			}
		}

		// Timeout check ticker (separate from ping send)
		var timeoutTicker *time.Ticker
		var timeoutChan <-chan time.Time
		if ws.pingTimeout > 0 {
			// Check for timeout every 1/4 of the timeout period, minimum 1 second
			timeoutCheckInterval := ws.pingTimeout / 4
			if timeoutCheckInterval < time.Second {
				timeoutCheckInterval = time.Second
			}
			timeoutTicker = time.NewTicker(timeoutCheckInterval)
			defer timeoutTicker.Stop()
			timeoutChan = timeoutTicker.C
		}

		for {
			select {
			case <-activityChan:
				resetPingTimer()

			case <-pingChan:
				// Send keepalive ping
				ws.sendPing()
				resetPingTimer()

			case <-timeoutChan:
				// Check for inactivity timeout
				exceeded, action := ws.sessionManager.CheckPingTimeout()
				if exceeded {
					ws.handlePingTimeout(action)
					// For ping-restart/ping-exit we shut down the tunnel.
					// This matches OpenVPN's "restart the daemon" semantics.
					return
				}

			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}

// sendPing sends a keepalive ping packet.
func (ws *workersState) sendPing() {
	dc := ws.getDataChannel()
	if dc == nil {
		return
	}

	pingPayload := PingPayload()
	packet, err := dc.writePacket(pingPayload)
	if err != nil {
		ws.logger.Warnf("keepalive: error creating ping packet: %v", err)
		return
	}

	select {
	case ws.dataOrControlToMuxer <- packet:
		ws.logger.Debugf("keepalive: sent ping packet")
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}

// handlePingTimeout handles a ping timeout event.
func (ws *workersState) handlePingTimeout(action int) {
	switch action {
	case session.PingTimeoutActionRestart:
		ws.logger.Warnf("keepalive: ping-restart timeout, restarting tunnel")
		// Best-effort error reporting; channel may be unbuffered/unread.
		select {
		case ws.sessionManager.Failure <- ErrPingTimeout:
		default:
		}
		ws.workersManager.StartShutdown()

	case session.PingTimeoutActionExit:
		ws.logger.Warnf("keepalive: ping-exit timeout, shutting down connection")
		// Send error to Failure channel to notify upper layer
		select {
		case ws.sessionManager.Failure <- ErrPingExit:
		default:
			// Channel full or closed, proceed with shutdown anyway
		}
		// Trigger worker shutdown
		ws.workersManager.StartShutdown()
	}
}

// minRenegotiationCheckInterval is the minimum interval for renegotiation checks.
// Event-driven checks handle byte/packet triggers immediately, so this is only
// a fallback for time-based triggers on idle connections.
const minRenegotiationCheckInterval = 30 * time.Second

// maxRenegotiationCheckInterval is the maximum interval for renegotiation checks.
const maxRenegotiationCheckInterval = 5 * time.Minute

// renegotiationWorker periodically checks if data channel key renegotiation is needed
// and triggers a SOFT_RESET if the configured reneg-sec threshold is exceeded.
//
// NOTE: This worker now serves as a fallback for time-based (reneg-sec) triggers
// on idle connections. Byte-based and packet-based triggers are handled by
// event-driven checks in moveUpWorker and moveDownWorker (see checkRenegotiation).
//
// This implements client-initiated renegotiation as per OpenVPN 2.5 ssl.c:2668-2682
func (ws *workersState) renegotiationWorker(firstKeyReady <-chan any) {
	workerName := fmt.Sprintf("%s: renegotiationWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		// Note: renegotiation failure shouldn't be fatal - connection may still work
	}()

	ws.logger.Debugf("%s: started", workerName)

	// Check if renegotiation is enabled
	renegSec, renegBytes := ws.sessionManager.RenegotiationConfig()
	if renegSec == 0 && renegBytes <= 0 {
		ws.logger.Debugf("%s: renegotiation disabled (reneg-sec=0, reneg-bytes=%d)", workerName, renegBytes)
		// Just wait for shutdown
		<-ws.workersManager.ShouldShutdown()
		return
	}

	ws.logger.Infof("%s: renegotiation enabled (reneg-sec=%d, reneg-bytes=%d)", workerName, renegSec, renegBytes)

	// Calculate check interval based on reneg-sec.
	// Use reneg-sec/4 similar to OpenVPN's compute_earliest_wakeup() approach,
	// bounded by min/max intervals. Since byte/packet triggers are event-driven,
	// this interval only needs to catch time-based triggers.
	checkInterval := minRenegotiationCheckInterval
	if renegSec > 0 {
		checkInterval = time.Duration(renegSec/4) * time.Second
		if checkInterval < minRenegotiationCheckInterval {
			checkInterval = minRenegotiationCheckInterval
		}
		if checkInterval > maxRenegotiationCheckInterval {
			checkInterval = maxRenegotiationCheckInterval
		}
	}
	ws.logger.Debugf("%s: check interval=%v", workerName, checkInterval)

	select {
	// wait for the first key to be ready
	case <-firstKeyReady:
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if ws.sessionManager.ShouldRenegotiate() {
					ws.logger.Infof("%s: triggering client-initiated renegotiation", workerName)
					if err := ws.triggerRenegotiation(); err != nil {
						ws.logger.Warnf("%s: renegotiation failed: %v", workerName, err)
						// Clear the request so we can retry later
						ws.sessionManager.ClearRenegotiationRequest()
					}
				}

			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}

// checkRenegotiation checks if renegotiation should be triggered and does so if needed.
// This is called after each packet is processed to implement event-driven behavior
// matching OpenVPN's ssl.c:2668-2684.
//
// Event-driven renegotiation ensures that byte-based and packet-based triggers
// are checked immediately when thresholds are crossed, rather than waiting for
// a polling interval.
func (ws *workersState) checkRenegotiation() {
	if ws.sessionManager.ShouldRenegotiate() {
		ws.logger.Infof("datachannel: triggering event-driven renegotiation")
		if err := ws.triggerRenegotiation(); err != nil {
			ws.logger.Warnf("datachannel: renegotiation failed: %v", err)
			ws.sessionManager.ClearRenegotiationRequest()
		}
	}
}

// triggerRenegotiation initiates a client-side key renegotiation by:
// 1. Performing a soft reset (moving current key to lame duck slot)
// 2. Sending a P_CONTROL_SOFT_RESET_V1 packet
// 3. Setting the negotiation state to S_INITIAL
// 4. Notifying the TLS layer to perform a new handshake
func (ws *workersState) triggerRenegotiation() error {
	// Check if we have the required channels
	if ws.controlToReliable == nil {
		return fmt.Errorf("controlToReliable channel not configured")
	}
	if ws.notifyTLS == nil {
		return fmt.Errorf("notifyTLS channel not configured")
	}

	// Perform key soft reset: move current key to lame duck slot,
	// prepare for new key negotiation. This preserves the old key
	// for transition_window seconds to allow in-flight packets.
	if err := ws.sessionManager.KeySoftReset(); err != nil {
		return fmt.Errorf("key soft reset failed: %w", err)
	}

	// KeySoftReset already advances the key ID (matching OpenVPN's
	// key_state_soft_reset() -> key_state_init() behavior), so we must NOT call
	// NextKeyID() again here.
	newKeyID := ws.sessionManager.CurrentKeyID()
	ws.logger.Debugf("renegotiation: new key_id=%d", newKeyID)

	// Create a SOFT_RESET packet (will use the new key ID)
	packet, err := ws.sessionManager.NewPacket(model.P_CONTROL_SOFT_RESET_V1, []byte{})
	if err != nil {
		return fmt.Errorf("failed to create SOFT_RESET packet: %w", err)
	}

	ws.logger.Debugf("renegotiation: sending P_CONTROL_SOFT_RESET_V1 (id=%d, key_id=%d)", packet.ID, packet.KeyID)

	// Send the SOFT_RESET packet through reliable transport
	select {
	case ws.controlToReliable <- packet:
		// packet sent
	case <-ws.workersManager.ShouldShutdown():
		return fmt.Errorf("shutdown during renegotiation")
	}

	// Reset negotiation state to INITIAL
	ws.sessionManager.SetNegotiationState(model.S_INITIAL)

	// Notify TLS layer to start a new handshake
	select {
	case ws.notifyTLS <- &model.Notification{Flags: model.NotificationReset}:
		ws.logger.Debugf("renegotiation: notified TLS layer to start handshake")
	case <-ws.workersManager.ShouldShutdown():
		return fmt.Errorf("shutdown during TLS notification")
	}

	return nil
}

// lameDuckWorker periodically checks if the lame duck key has expired
// and clears it from both session manager and data channel state.
// This implements OpenVPN's transition-window behavior.
func (ws *workersState) lameDuckWorker(firstKeyReady <-chan any) {
	workerName := fmt.Sprintf("%s: lameDuckWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
	}()

	ws.logger.Debugf("%s: started", workerName)

	select {
	// wait for the first key to be ready
	case <-firstKeyReady:
		// Check for lame duck expiry every second
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Check if lame duck key has expired
				if ws.sessionManager.CheckAndExpireLameDuck() {
					// Clear the lame duck key material in data channel
					dc := ws.getDataChannel()
					if dc != nil {
						dc.ExpireLameDuck()
					}
					ws.logger.Debug("lameDuckWorker: lame duck key expired and cleared")
				}

			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}
