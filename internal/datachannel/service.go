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

// Default keepalive interval in seconds.
// OpenVPN servers typically use ping/ping-restart of 10/60 or 10/120.
// We use 10 seconds as the default ping interval.
const defaultKeepaliveInterval = 10 * time.Second

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

	// Use configured ping interval or default (10s)
	var pingDuration time.Duration
	if pingInterval > 0 {
		pingDuration = time.Duration(pingInterval) * time.Second
	} else {
		pingDuration = defaultKeepaliveInterval
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
	dataChannelMu sync.RWMutex
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
	pingInterval      time.Duration // Configured --ping interval (0 = use default)
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

				// Track bytes written for renegotiation
				ws.sessionManager.AddDataChannelBytes(0, int64(len(packet.Payload)))

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

				// Track bytes read for renegotiation
				ws.sessionManager.AddDataChannelBytes(int64(len(pkt.Payload)), 0)

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

			err := ws.dataChannel.setupKeys(key)
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
			ws.sessionManager.SetNegotiationState(model.S_GENERATED_KEYS)
			ws.sessionManager.MarkKeyEstablished()
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

		pingTicker := time.NewTicker(ws.pingInterval)
		defer pingTicker.Stop()

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
			case <-pingTicker.C:
				// Send keepalive ping
				ws.sendPing()

			case <-timeoutChan:
				// Check for inactivity timeout
				exceeded, action := ws.sessionManager.CheckPingTimeout()
				if exceeded {
					ws.handlePingTimeout(action)
					if action == session.PingTimeoutActionExit {
						return // Worker exits, shutdown will be triggered
					}
					// For restart, reset the last packet time so we don't
					// immediately timeout again during renegotiation
					ws.sessionManager.UpdateLastPacketTime()
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
		ws.logger.Warnf("keepalive: ping-restart timeout, triggering SOFT_RESET")
		if err := ws.triggerRenegotiation(); err != nil {
			ws.logger.Warnf("keepalive: failed to trigger renegotiation: %v", err)
		}

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
// 2. Advancing the key ID for the new session
// 3. Sending a P_CONTROL_SOFT_RESET_V1 packet
// 4. Setting the negotiation state to S_INITIAL
// 5. Notifying the TLS layer to perform a new handshake
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

	// Advance the key ID for the new key negotiation.
	// This follows OpenVPN's key_id cycling: 0→1→2→...→7→1→...
	newKeyID := ws.sessionManager.NextKeyID()
	ws.logger.Debugf("renegotiation: advanced to key_id=%d", newKeyID)

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
