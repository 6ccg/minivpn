package session

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/6ccg/minivpn/internal/model"
	"github.com/6ccg/minivpn/internal/optional"
	"github.com/6ccg/minivpn/internal/replay"
	"github.com/6ccg/minivpn/internal/runtimex"
	"github.com/6ccg/minivpn/internal/wire"
	"github.com/6ccg/minivpn/pkg/config"
)

var (
	// ErrExpiredKey is the error we raise when we have an expired key.
	ErrExpiredKey = errors.New("expired key")

	// ErrNoRemoteSessionID indicates we are missing the remote session ID.
	ErrNoRemoteSessionID = errors.New("missing remote session ID")

	// ErrTLSNegotiationTimeout indicates TLS key negotiation exceeded hand-window.
	// This mirrors OpenVPN's "TLS key negotiation failed to occur within ..." failure.
	ErrTLSNegotiationTimeout = errors.New("TLS key negotiation timeout")
)

// Ping timeout action constants
const (
	// PingTimeoutActionNone indicates no action on timeout (disabled)
	PingTimeoutActionNone = 0
	// PingTimeoutActionRestart indicates restart on timeout (ping-restart).
	PingTimeoutActionRestart = 1
	// PingTimeoutActionExit indicates exit on timeout (ping-exit)
	PingTimeoutActionExit = 2
)

// Manager manages the session. The zero value is invalid. Please, construct
// using [NewManager]. This struct is concurrency safe.
type Manager struct {
	keyID                uint8
	keys                 []*DataChannelKey
	localControlPacketID model.PacketID
	// controlEpoch increments whenever control-channel sequencing state is reset
	// (e.g., SOFT_RESET/new key_state). It allows downstream layers such as the
	// reliable transport to reset their per-session queues/counters.
	controlEpoch   uint64
	localSessionID model.SessionID
	logger         model.Logger
	// mu 保护 Manager 的所有可变状态。
	// 锁顺序约定: 如果需要同时持有 datachannel.workersState.dataChannelMu 和此锁，
	// 必须先获取 dataChannelMu，再获取此锁，以避免死锁。
	mu              sync.RWMutex
	negState        model.NegotiationState
	dataOpcode      model.Opcode
	remoteSessionID optional.Value[model.SessionID]
	tunnelInfo      model.TunnelInfo
	tracer          model.HandshakeTracer

	// Additional state required to support tls-auth
	controlChannelSecurity     *wire.ControlChannelSecurity
	localControlReplayPacketID model.PacketID
	// controlReplayTimestamp is the epoch timestamp for control channel replay protection.
	// Following OpenVPN 2.5 packet_id_send semantics: this is set once at epoch start
	// and only updated on packet-id rollover, NOT refreshed on every packet.
	// See .openvpn-ref/src/openvpn/packet_id.c:packet_id_send_update().
	controlReplayTimestamp model.PacketTimestamp

	// controlReplayFilter detects replay attacks on the control channel.
	// This is used to validate incoming ReplayPacketID and Timestamp fields.
	controlReplayFilter *replay.Filter

	// Ready is a channel where we signal that we can start accepting data, because we've
	// successfully generated key material for the data channel.
	Ready chan any

	// Failure is a channel where we receive any unrecoverable error.
	Failure chan error

	// Multi-key slot support for key rotation (lame duck handling)
	// keySlots holds the key state slots: [KS_PRIMARY]=active key, [KS_LAME_DUCK]=retiring key
	keySlots [KS_SIZE]*KeyState

	// transitionWindow is how long a lame duck key stays alive after soft reset.
	// Corresponds to OpenVPN's --transition-window option.
	transitionWindow time.Duration

	// Renegotiation state
	// keyEstablishedTime is the time when the current data channel key was established.
	keyEstablishedTime time.Time

	// dataChannelBytesRead is the total number of bytes read on the data channel
	// since the current key was established.
	dataChannelBytesRead int64

	// dataChannelBytesWritten is the total number of bytes written on the data channel
	// since the current key was established.
	dataChannelBytesWritten int64

	// renegotiateSeconds is the configured maximum time before renegotiation.
	renegotiateSeconds int

	// renegotiateBytes is the configured maximum bytes before renegotiation.
	// -1 means disabled.
	renegotiateBytes int64

	// renegotiatePackets is the configured maximum packets before renegotiation.
	// 0 means disabled.
	renegotiatePackets int64

	// renegotiationRequested indicates that a renegotiation has been triggered
	// and we're waiting for the handshake to complete.
	renegotiationRequested bool

	// Ping/keepalive state
	// lastPacketTime is the time when the last valid packet was received.
	// This is used by ping-restart and ping-exit to detect connection inactivity.
	lastPacketTime time.Time

	// pingSeconds is the configured --ping interval in seconds.
	// 0 means disabled.
	pingSeconds int

	// pingRestartSeconds is the configured --ping-restart timeout in seconds.
	// 0 means disabled.
	pingRestartSeconds int

	// pingExitSeconds is the configured --ping-exit timeout in seconds.
	// 0 means disabled. Takes precedence over pingRestartSeconds.
	pingExitSeconds int

	// handshakeWindow is the time within which the TLS handshake must complete.
	// Corresponds to OpenVPN's --hand-window option (default 60 seconds).
	// Used to set must_negotiate deadline on key states.
	handshakeWindow time.Duration

	// outgoingPacketActivity is notified whenever we successfully send a packet
	// to the network. This is used by the ping/keepalive implementation to
	// match OpenVPN 2.5 behavior where any outgoing packet resets the ping send
	// timer (forward.c:1642 event_timeout_reset(&ping_send_interval)).
	outgoingPacketActivity chan struct{}
}

// NewManager returns a [Manager] ready to be used.
func NewManager(cfg *config.Config) (*Manager, error) {
	key0 := &DataChannelKey{}

	opts := cfg.OpenVPNOptions()

	pingSeconds := opts.Ping
	pingRestartSeconds := opts.PingRestart
	pingExitSeconds := opts.PingExit
	if !opts.Proto.IsTCP() && pingRestartSeconds == 0 && pingExitSeconds == 0 {
		pingRestartSeconds = config.PrePullInitialPingRestart
	}

	sessionManager := &Manager{
		keyID: 0,
		keys:  []*DataChannelKey{key0},
		// localControlPacketID should be initialized to 1 because we handle hard-reset as special cases
		localControlPacketID: 1,
		localSessionID:       [8]byte{},
		logger:               cfg.Logger(),
		mu:                   sync.RWMutex{},
		negState:             model.S_INITIAL,
		dataOpcode:           0,
		remoteSessionID:      optional.None[model.SessionID](),
		tunnelInfo:           model.TunnelInfo{},
		tracer:               cfg.Tracer(),

		// Initialize control channel replay filter (OpenVPN packet_id style).
		// Uses UDP mode (backtrack enabled) since control packets may arrive out of order.
		controlReplayFilter: replay.NewFilter(
			replay.DefaultSeqBacktrack,
			replay.WithBacktrackMode(true),
		),

		Ready:   make(chan any, 1),
		Failure: make(chan error),

		// Initialize renegotiation settings from config
		renegotiateSeconds: opts.RenegotiateSeconds,
		renegotiateBytes:   opts.RenegotiateBytes,
		renegotiatePackets: opts.RenegotiatePackets,

		// Initialize transition window for lame duck keys (default 3600 seconds)
		transitionWindow: time.Duration(opts.TransitionWindow) * time.Second,

		// Initialize ping/keepalive settings from config
		pingSeconds:        pingSeconds,
		pingRestartSeconds: pingRestartSeconds,
		pingExitSeconds:    pingExitSeconds,

		// Initialize handshake window for must_negotiate timeout (default 60 seconds)
		handshakeWindow: time.Duration(opts.HandshakeWindow) * time.Second,

		// Outgoing activity signal used by keepalive ping scheduling.
		outgoingPacketActivity: make(chan struct{}, 1),
	}

	randomBytes, err := randomFn(8)
	if err != nil {
		return sessionManager, err
	}

	sessionManager.localSessionID = (model.SessionID)(randomBytes[:8])

	localKey, err := NewKeySource()
	if err != nil {
		return sessionManager, err
	}

	k, err := sessionManager.ActiveKey()
	if err != nil {
		return sessionManager, err
	}
	k.AddLocalKey(localKey)

	// Initialize the primary key slot with the initial key state
	sessionManager.keySlots[KS_PRIMARY] = &KeyState{
		Key:   key0,
		KeyID: 0,
		State: model.S_INITIAL,
		// Data channel packet ID starts at 1, matching official OpenVPN behavior.
		localDataPacketID: 1,
	}

	// Control channel security options.
	if len(opts.TLSAuth) != 0 {
		direction := -1
		if opts.KeyDirection != nil {
			direction = *opts.KeyDirection
		}
		sessionManager.controlChannelSecurity, err = wire.NewControlChannelSecurityTLSAuth(opts.TLSAuth, direction, opts.Auth)
		if err != nil {
			return sessionManager, err
		}

		// Replay packet ID starts at 1 (OpenVPN 2.5.x packet-id semantics).
		sessionManager.localControlReplayPacketID = 1
	} else if len(opts.TLSCrypt) != 0 {
		sessionManager.controlChannelSecurity, err = wire.NewControlChannelSecurityTLSCrypt(opts.TLSCrypt)
		if err != nil {
			return sessionManager, err
		}

		// Replay packet ID starts at 1 (OpenVPN 2.5.x packet-id semantics).
		sessionManager.localControlReplayPacketID = 1
	} else if len(opts.TLSCryptV2) != 0 {
		sessionManager.controlChannelSecurity, err = wire.NewControlChannelSecurityTLSCryptV2(opts.TLSCryptV2)
		if err != nil {
			return sessionManager, err
		}

		// Replay packet ID starts at 1 (OpenVPN 2.5.x packet-id semantics).
		sessionManager.localControlReplayPacketID = 1
	} else {
		sessionManager.controlChannelSecurity = &wire.ControlChannelSecurity{
			Mode: wire.ControlSecurityModeNone,
		}

	}

	return sessionManager, nil
}

// LocalSessionID gets the local session ID as bytes.
func (m *Manager) LocalSessionID() []byte {
	defer m.mu.RUnlock()
	m.mu.RLock()
	return m.localSessionID[:]
}

// RemoteSessionID gets the remote session ID as bytes.
func (m *Manager) RemoteSessionID() []byte {
	defer m.mu.RUnlock()
	m.mu.RLock()
	rs := m.remoteSessionID
	if !rs.IsNone() {
		val := rs.Unwrap()
		return val[:]
	}
	return nil
}

// ControlEpoch returns the current control-channel epoch.
func (m *Manager) ControlEpoch() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.controlEpoch
}

// IsRemoteSessionIDSet returns whether we've set the remote session ID.
func (m *Manager) IsRemoteSessionIDSet() bool {
	defer m.mu.RUnlock()
	m.mu.RLock()
	return !m.remoteSessionID.IsNone()
}

// HardReset resets session-scoped state so the client can start a new session
// ("hard reset" semantics).
//
// This keeps the local session ID stable while clearing the remote session ID
// and resetting per-session counters and key material.
func (m *Manager) HardReset() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear remote session ID so the next HARD_RESET_SERVER_V2 can install the new
	// session ID via SetRemoteSessionID.
	m.remoteSessionID = optional.None[model.SessionID]()

	// Reset per-session counters. Control packet IDs start at 1.
	m.keyID = 0
	m.localControlPacketID = 1
	m.localControlReplayPacketID = 0
	// Reset epoch timestamp so it will be re-initialized on first packet send.
	// This matches OpenVPN's behavior of starting a fresh packet_id_send epoch.
	m.controlReplayTimestamp = 0
	if m.controlChannelSecurity.Mode != wire.ControlSecurityModeNone {
		m.localControlReplayPacketID = 1
	}

	m.controlEpoch++

	// Reset replay protection for the new session.
	m.controlReplayFilter.Reset()

	// Reset negotiation/data channel state.
	m.negState = model.S_INITIAL
	m.dataOpcode = 0
	m.tunnelInfo = model.TunnelInfo{}
	m.renegotiationRequested = false
	m.keyEstablishedTime = time.Time{}
	m.dataChannelBytesRead = 0
	m.dataChannelBytesWritten = 0
	m.lastPacketTime = time.Time{}

	// Reset key material and key slots.
	key0 := &DataChannelKey{}
	localKey, err := NewKeySource()
	if err != nil {
		return err
	}
	if err := key0.AddLocalKey(localKey); err != nil {
		return err
	}
	m.keys = []*DataChannelKey{key0}
	m.keySlots = [KS_SIZE]*KeyState{}
	m.keySlots[KS_PRIMARY] = &KeyState{
		Key:   key0,
		KeyID: 0,
		State: model.S_INITIAL,
		// Data channel packet ID starts at 1, matching official OpenVPN behavior.
		localDataPacketID: 1,
	}
	m.keySlots[KS_LAME_DUCK] = nil

	return nil
}

// NewACKForPacketIDs creates a new ACK for the given packet IDs.
func (m *Manager) NewACKForPacketIDs(ids []model.PacketID) (*model.Packet, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
	if m.remoteSessionID.IsNone() {
		return nil, ErrNoRemoteSessionID
	}
	// TODO: Could this use NewPacket() instead ?
	p := &model.Packet{
		Opcode:          model.P_ACK_V1,
		KeyID:           m.keyID,
		PeerID:          [3]byte{},
		LocalSessionID:  m.localSessionID,
		ACKs:            ids,
		RemoteSessionID: m.remoteSessionID.Unwrap(),
		ID:              0,
		Payload:         []byte{},
	}
	return p, nil
}

// NewPacket creates a new packet for this session.
func (m *Manager) NewPacket(opcode model.Opcode, payload []byte) (*model.Packet, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
	packet := model.NewPacket(
		opcode,
		m.keyID,
		payload,
	)
	copy(packet.LocalSessionID[:], m.localSessionID[:])
	pid, err := func() (model.PacketID, error) {
		if opcode.IsControl() {
			return m.localControlPacketIDLocked()
		}
		return m.localDataPacketIDLocked()
	}()
	if err != nil {
		return nil, err
	}
	packet.ID = pid
	if !m.remoteSessionID.IsNone() {
		packet.RemoteSessionID = m.remoteSessionID.Unwrap()
	}
	return packet, nil
}

// RefreshControlReplayProtection refreshes the (ReplayPacketID, Timestamp) pair on the
// given packet.
//
// OpenVPN writes a fresh packet-id at the tls-auth/tls-crypt layer at send time and
// does so also on retransmission, so reliable retransmits must refresh these anti-replay fields.
//
// IMPORTANT: Following OpenVPN 2.5 packet_id_send semantics (packet_id.c:326-346):
// - The packet ID increments on every send
// - The timestamp is set ONCE at epoch start and only updated on ID rollover
// - This prevents time-backtrack rejection on the peer when packets arrive out-of-order
func (m *Manager) RefreshControlReplayProtection(packet *model.Packet) error {
	defer m.mu.Unlock()
	m.mu.Lock()

	if m.controlChannelSecurity == nil || m.controlChannelSecurity.Mode == wire.ControlSecurityModeNone {
		return nil
	}

	// Initialize epoch timestamp if not set (first packet of this epoch).
	// This matches OpenVPN's packet_id_send_update: "if (!p->time) p->time = now;"
	if m.controlReplayTimestamp == 0 {
		m.controlReplayTimestamp = model.PacketTimestamp(time.Now().Unix())
	}

	replayID, err := m.localControlReplayPacketIDLocked()
	if err != nil {
		return err
	}
	packet.ReplayPacketID = replayID
	// Use the epoch timestamp, NOT current time.
	// This matches OpenVPN's behavior where packet_id_send.time is stable within an epoch.
	packet.Timestamp = m.controlReplayTimestamp
	return nil
}

// NewHardResetPacket creates a new hard reset packet for this session.
// This packet is a special case because, if we resend, we must not bump
// its packet ID. Normally retransmission is handled at the reliabletransport layer,
// but we send hard resets at the muxer.
func (m *Manager) NewHardResetPacket() *model.Packet {
	var opcode model.Opcode
	if m.controlChannelSecurity.Mode == wire.ControlSecurityModeTLSCryptV2 {
		opcode = model.P_CONTROL_HARD_RESET_CLIENT_V3
	} else {
		opcode = model.P_CONTROL_HARD_RESET_CLIENT_V2
	}
	packet := model.NewPacket(
		opcode,
		m.keyID,
		[]byte{},
	)

	// a hard reset will always have packet ID zero
	packet.ID = 0
	copy(packet.LocalSessionID[:], m.localSessionID[:])

	return packet
}

// LocalDataPacketID returns an unique Packet ID for the Data Channel. It
// increments the counter for the local data packet ID.
func (m *Manager) LocalDataPacketID() (model.PacketID, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.localDataPacketIDLocked()
}

// LocalDataPacketIDAndKeyID returns the next outbound data-channel packet ID
// and the corresponding key ID used to protect the packet.
//
// This mirrors OpenVPN's behavior of selecting a single key_state for outbound
// data during key rotation (lame duck handling) and then using that same state
// for both packet_id and key_id.
func (m *Manager) LocalDataPacketIDAndKeyID() (model.PacketID, uint8, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ks := m.dataKeyStateLocked()
	if ks == nil {
		return 0, 0, errors.New("session: no data key state")
	}
	pid, err := m.localDataPacketIDLocked()
	if err != nil {
		return 0, 0, err
	}
	return pid, ks.KeyID, nil
}

// localDataPacketIDLocked returns an unique Packet ID for the Data Channel. It
// increments the counter for the local data packet ID.
func (m *Manager) localDataPacketIDLocked() (model.PacketID, error) {
	ks := m.dataKeyStateLocked()
	if ks == nil {
		return 0, errors.New("session: no data key state")
	}

	// Defensive: callers/tests might construct a KeyState without initializing
	// the per-key counter. OpenVPN rejects packet-id 0, so start at 1.
	if ks.localDataPacketID == 0 {
		ks.localDataPacketID = 1
	}

	pid := ks.localDataPacketID
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, ErrExpiredKey
	}

	// Check for wrap trigger - matches OpenVPN's packet_id_close_to_wrapping()
	// in packet_id.h:310-314. When packet ID reaches 0xFF000000, we should
	// trigger renegotiation to ensure new keys are ready before ID exhaustion.
	if pid >= packetIDWrapTrigger && !ks.dataPacketIDWrapTriggered {
		ks.dataPacketIDWrapTriggered = true
		m.logger.Warnf("session: data packet ID %d (0x%X) reached wrap trigger, soft reset recommended",
			pid, pid)
	}

	ks.localDataPacketID++
	return pid, nil
}

// dataKeyStateLocked returns the key state currently used for outbound
// data-channel packets.
//
// During a soft reset / key rotation, OpenVPN keeps using the existing (lame duck)
// data key until the new primary key reaches S_GENERATED_KEYS.
//
// The caller must hold m.mu.
func (m *Manager) dataKeyStateLocked() *KeyState {
	if primary := m.keySlots[KS_PRIMARY]; primary != nil && primary.State >= model.S_GENERATED_KEYS {
		return primary
	}
	if lameDuck := m.keySlots[KS_LAME_DUCK]; lameDuck != nil && lameDuck.State >= model.S_GENERATED_KEYS {
		return lameDuck
	}
	// Fallback for early/legacy callers; data channel shouldn't be active yet.
	if primary := m.keySlots[KS_PRIMARY]; primary != nil {
		return primary
	}
	return nil
}

// localControlPacketIDLocked returns an unique Packet ID for the Control Channel. It
// increments the counter for the local control packet ID.
func (m *Manager) localControlPacketIDLocked() (model.PacketID, error) {
	pid := m.localControlPacketID
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, ErrExpiredKey
	}
	m.localControlPacketID++
	return pid, nil
}

// IsDataPacketIDNearWrap returns true if the data packet ID has reached
// the wrap trigger threshold (0xFF000000) and a soft reset should be initiated.
// This matches OpenVPN's packet_id_close_to_wrapping() check.
func (m *Manager) IsDataPacketIDNearWrap() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ks := m.dataKeyStateLocked()
	if ks == nil {
		return false
	}
	return ks.dataPacketIDWrapTriggered
}

// ResetDataPacketIDWrapFlag resets the wrap trigger flag after key rotation.
// Should be called after a successful soft reset/key rotation completes.
func (m *Manager) ResetDataPacketIDWrapFlag() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ks := range m.keySlots {
		if ks == nil {
			continue
		}
		ks.dataPacketIDWrapTriggered = false
	}
}

// NegotiationState returns the state of the negotiation.
func (m *Manager) NegotiationState() model.NegotiationState {
	defer m.mu.RUnlock()
	m.mu.RLock()
	return m.negState
}

// SetNegotiationState sets the state of the negotiation.
func (m *Manager) SetNegotiationState(sns model.NegotiationState) {
	defer m.mu.Unlock()
	m.mu.Lock()
	m.logger.Infof("[@] %s -> %s", m.negState, sns)
	m.tracer.OnStateChange(sns)

	oldState := m.negState
	m.negState = sns

	// Handle must_negotiate deadline based on state transitions
	// This matches OpenVPN's ssl.c behavior
	if primary := m.keySlots[KS_PRIMARY]; primary != nil {
		// Keep per-key state aligned with the current negotiation state.
		// This matches OpenVPN's key_state.state transitions.
		primary.State = sns

		// Set must_negotiate when starting negotiation (entering S_PRE_START)
		// This matches ssl.c:2719: ks->must_negotiate = now + session->opt->handshake_window
		if oldState == model.S_INITIAL && sns == model.S_PRE_START {
			if m.handshakeWindow > 0 {
				primary.SetNegotiationDeadline(m.handshakeWindow)
				m.logger.Debugf("session: set must_negotiate deadline to %v", m.handshakeWindow)
			}
		}

		// Clear must_negotiate when negotiation completes successfully
		// This matches ssl.c:2793: ks->must_negotiate = 0 when reaching S_ACTIVE.
		if sns >= model.S_ACTIVE && oldState < model.S_ACTIVE {
			primary.ClearNegotiationDeadline()
			m.logger.Debugf("session: cleared must_negotiate deadline")
		}
	}

	if sns == model.S_GENERATED_KEYS {
		// Ready is primarily used during initial tunnel bring-up (StartTUN).
		// After the tunnel is established, we may reach S_GENERATED_KEYS again
		// during key rotation; avoid blocking if nobody is listening.
		select {
		case m.Ready <- true:
		default:
		}
	}
}

// ActiveKey returns the dataChannelKey that is actively being used.
func (m *Manager) ActiveKey() (*DataChannelKey, error) {
	defer m.mu.RUnlock()
	m.mu.RLock()
	if len(m.keys) > math.MaxUint8 || m.keyID >= uint8(len(m.keys)) {
		return nil, fmt.Errorf("%w: %s", ErrDataChannelKey, "no such key id")
	}
	dck := m.keys[m.keyID]
	return dck, nil
}

// SetRemoteSessionID sets the remote session ID.
func (m *Manager) SetRemoteSessionID(remoteSessionID model.SessionID) {
	defer m.mu.Unlock()
	m.mu.Lock()
	runtimex.Assert(m.remoteSessionID.IsNone(), "SetRemoteSessionID called more than once")
	m.remoteSessionID = optional.Some(remoteSessionID)
}

// CurrentKeyID returns the key ID currently in use.
func (m *Manager) CurrentKeyID() uint8 {
	defer m.mu.RUnlock()
	m.mu.RLock()
	return m.keyID
}

// DataKeyID returns the key_id that should be used for data-channel packets.
//
// During a soft reset / key rotation, OpenVPN keeps using the existing (lame duck)
// data key until the new primary key reaches S_GENERATED_KEYS.
func (m *Manager) DataKeyID() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if primary := m.keySlots[KS_PRIMARY]; primary != nil && primary.State >= model.S_GENERATED_KEYS {
		return primary.KeyID
	}
	if lameDuck := m.keySlots[KS_LAME_DUCK]; lameDuck != nil && lameDuck.State >= model.S_GENERATED_KEYS {
		return lameDuck.KeyID
	}
	// Fallback for early/legacy callers before per-key state is established.
	return m.keyID
}

// keyIDMask is used to cycle key IDs within the valid range (0-7).
// Key ID occupies the lower 3 bits of the packet header.
const keyIDMask = 0x07

// packetIDWrapTrigger matches OpenVPN's PACKET_ID_WRAP_TRIGGER (packet_id.h:58).
// When packet ID reaches this value, a soft reset should be initiated
// to ensure new keys are ready before ID exhaustion.
// 官方值：0xFF000000，预留约 1600 万个包的缓冲空间用于完成新密钥协商。
const packetIDWrapTrigger = 0xFF000000

// NextKeyID advances the key ID following OpenVPN's cycling rules.
// The key ID cycles: 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 1 → 2 → ...
// Note that after the first key (id=0), subsequent keys skip 0
// so that key_id=0 always indicates the initial key.
// This matches the official OpenVPN implementation in ssl.c:937-941.
func (m *Manager) NextKeyID() uint8 {
	defer m.mu.Unlock()
	m.mu.Lock()
	m.keyID++
	m.keyID &= keyIDMask
	if m.keyID == 0 {
		m.keyID = 1
	}
	return m.keyID
}

// DataOpcode returns the last seen data packet opcode (P_DATA_V1 or P_DATA_V2).
// The zero value means we haven't inferred it yet.
func (m *Manager) DataOpcode() model.Opcode {
	defer m.mu.RUnlock()
	m.mu.RLock()
	return m.dataOpcode
}

// MaybeSetDataOpcode sets the data packet opcode if it's still unknown.
func (m *Manager) MaybeSetDataOpcode(op model.Opcode) {
	if !op.IsData() {
		return
	}
	defer m.mu.Unlock()
	m.mu.Lock()
	if m.dataOpcode != 0 {
		return
	}
	m.dataOpcode = op
}

// MaybeSetPeerID sets the tunnel peer-id if we don't have one yet.
func (m *Manager) MaybeSetPeerID(peerID int) {
	if peerID == 0 {
		return
	}
	defer m.mu.Unlock()
	m.mu.Lock()
	if m.tunnelInfo.PeerID != 0 {
		return
	}
	m.tunnelInfo.PeerID = peerID
}

// InitTunnelInfo initializes TunnelInfo from data obtained from the auth response.
func (m *Manager) InitTunnelInfo(remoteOption string) error {
	defer m.mu.Unlock()
	m.mu.Lock()
	ti, err := newTunnelInfoFromRemoteOptionsString(remoteOption)
	if err != nil {
		return err
	}
	m.tunnelInfo = *ti
	m.logger.Infof("Tunnel MTU: %v", m.tunnelInfo.MTU)
	return nil
}

// newTunnelInfoFromRemoteOptionsString parses the options string returned by
// server. It returns a new tunnelInfo object where the needed fields have been
// updated. At the moment, we only parse the tun-mtu parameter.
func newTunnelInfoFromRemoteOptionsString(remoteOpts string) (*model.TunnelInfo, error) {
	t := &model.TunnelInfo{}
	opts := strings.Split(remoteOpts, ",")
	for _, opt := range opts {
		vals := strings.Split(opt, " ")
		if len(vals) < 2 {
			continue
		}
		k, v := vals[0], vals[1:]
		if k == "tun-mtu" {
			mtu, err := strconv.Atoi(v[0])
			if err != nil {
				return nil, err
			}
			t.MTU = mtu
		}
		if k == "peer-id" {
			peer, err := strconv.Atoi(v[0])
			if err != nil {
				return nil, err
			}
			t.PeerID = peer
		}
	}
	return t, nil
}

// UpdateTunnelInfo updates the internal tunnel info from the push response message
func (m *Manager) UpdateTunnelInfo(ti *model.TunnelInfo) {
	defer m.mu.Unlock()
	m.mu.Lock()

	m.tunnelInfo.IP = ti.IP
	m.tunnelInfo.GW = ti.GW
	if ti.PeerID != 0 {
		m.tunnelInfo.PeerID = ti.PeerID
	}
	m.tunnelInfo.NetMask = ti.NetMask

	m.logger.Infof("Tunnel IP: %s", ti.IP)
	m.logger.Infof("Gateway IP: %s", ti.GW)
	m.logger.Infof("Peer ID: %d", m.tunnelInfo.PeerID)
}

// TunnelInfo returns a copy the current TunnelInfo
func (m *Manager) TunnelInfo() model.TunnelInfo {
	defer m.mu.RUnlock()
	m.mu.RLock()
	return model.TunnelInfo{
		GW:      m.tunnelInfo.GW,
		IP:      m.tunnelInfo.IP,
		MTU:     m.tunnelInfo.MTU,
		NetMask: m.tunnelInfo.NetMask,
		PeerID:  m.tunnelInfo.PeerID,
	}
}

// Defines how control packets are authenticated (e.g. tls-auth)
func (m *Manager) PacketAuth() *wire.ControlChannelSecurity {
	return m.controlChannelSecurity
}

// CheckControlReplay validates that an incoming control packet is not a replay.
// It checks the ReplayPacketID and Timestamp fields against the sliding window.
// Returns nil if the packet is valid, or an error if it should be rejected.
// This method is only effective when control channel security (tls-auth/tls-crypt) is enabled.
func (m *Manager) CheckControlReplay(replayID model.PacketID, timestamp model.PacketTimestamp) error {
	// Only perform replay check when control channel security is enabled
	if m.controlChannelSecurity.Mode == wire.ControlSecurityModeNone {
		return nil
	}
	return m.controlReplayFilter.CheckWithTimestamp(replayID, timestamp)
}

// ResetControlReplay resets the control channel replay filter.
// This should be called when a new session is established.
func (m *Manager) ResetControlReplay() {
	m.controlReplayFilter.Reset()
}

// ResetForNewSession resets the session manager state for a new OpenVPN session.
//
// This is used when we need to "usurp" an existing session (e.g., when the
// server restarts and sends a HARD_RESET with a new session-id).
//
// It clears the remote session ID, resets packet counters and replay state,
// and replaces data-channel key material so a fresh key exchange can occur.
func (m *Manager) ResetForNewSession() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate a new local session-id for the new session (OpenVPN behavior).
	randomBytes, err := randomFn(8)
	if err != nil {
		return err
	}
	copy(m.localSessionID[:], randomBytes[:8])

	// Clear the remote session-id so it can be set again when we receive the
	// peer's HARD_RESET.
	m.remoteSessionID = optional.None[model.SessionID]()

	// Reset protocol/session negotiation state and inferred values.
	m.negState = model.S_INITIAL
	m.dataOpcode = 0
	m.tunnelInfo = model.TunnelInfo{}

	// Reset control-channel replay and counters.
	if m.controlReplayFilter != nil {
		m.controlReplayFilter.Reset()
	}
	m.localControlPacketID = 1
	m.localControlReplayPacketID = 1
	// Reset epoch timestamp for the new session.
	m.controlReplayTimestamp = 0

	m.controlEpoch++

	// Reset key material and key state slots.
	m.keyID = 0
	newLocalKey, err := NewKeySource()
	if err != nil {
		return err
	}
	key0 := &DataChannelKey{}
	_ = key0.AddLocalKey(newLocalKey)
	m.keys = []*DataChannelKey{key0}
	m.keySlots = [KS_SIZE]*KeyState{}
	m.keySlots[KS_PRIMARY] = &KeyState{
		Key:               key0,
		KeyID:             0,
		State:             model.S_INITIAL,
		localDataPacketID: 1,
	}

	// Reset renegotiation counters and keepalive timers (new session begins).
	m.keyEstablishedTime = time.Time{}
	m.dataChannelBytesRead = 0
	m.dataChannelBytesWritten = 0
	m.renegotiationRequested = false
	m.lastPacketTime = time.Time{}

	return nil
}

// Very similar to the localControlPacketID, but includes ACKs as well
func (m *Manager) localControlReplayPacketIDLocked() (model.PacketID, error) {
	pid := m.localControlReplayPacketID

	// TODO, should we have a seperate error for this case??
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, ErrExpiredKey
	}
	m.localControlReplayPacketID++
	return pid, nil
}

// MarkKeyEstablished should be called when data channel keys are successfully derived.
// This resets the renegotiation counters and records the establishment time.
func (m *Manager) MarkKeyEstablished() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyEstablishedTime = time.Now()
	m.dataChannelBytesRead = 0
	m.dataChannelBytesWritten = 0
	m.renegotiationRequested = false
	m.logger.Debugf("session: key established, renegotiation counters reset (reneg-sec=%d, reneg-bytes=%d)",
		m.renegotiateSeconds, m.renegotiateBytes)
}

// AddDataChannelBytes adds the given byte counts to the data channel counters.
// This should be called after each successful read/write on the data channel.
func (m *Manager) AddDataChannelBytes(read, written int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dataChannelBytesRead += read
	m.dataChannelBytesWritten += written
}

// DataChannelBytes returns the current byte counters for the data channel.
func (m *Manager) DataChannelBytes() (read, written int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dataChannelBytesRead, m.dataChannelBytesWritten
}

// ShouldRenegotiate checks if a data channel key renegotiation should be triggered.
// It returns true if either:
// - The configured reneg-sec time has elapsed since key establishment
// - The configured reneg-bytes limit has been exceeded
// - The configured reneg-pkts limit has been exceeded
// It also marks that renegotiation was requested to avoid duplicate triggers.
func (m *Manager) ShouldRenegotiate() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Don't trigger if we haven't established keys yet
	if m.negState < model.S_GENERATED_KEYS {
		return false
	}

	// Don't trigger if we already requested renegotiation
	if m.renegotiationRequested {
		return false
	}

	// Don't trigger if key establishment time is zero (not yet established)
	if m.keyEstablishedTime.IsZero() {
		return false
	}

	shouldReneg := false

	// Check time-based renegotiation
	if m.renegotiateSeconds > 0 {
		elapsed := time.Since(m.keyEstablishedTime)
		if elapsed >= time.Duration(m.renegotiateSeconds)*time.Second {
			m.logger.Infof("session: renegotiation triggered by time (elapsed=%v, limit=%ds)",
				elapsed.Round(time.Second), m.renegotiateSeconds)
			shouldReneg = true
		}
	}

	// Check bytes-based renegotiation (only if > 0; -1 means disabled).
	// Uses per-key byte counters to match OpenVPN ssl.c:2671-2672:
	// "ks->n_bytes >= session->opt->renegotiate_bytes"
	if m.renegotiateBytes > 0 {
		var totalBytes int64
		if primary := m.keySlots[KS_PRIMARY]; primary != nil {
			totalBytes = primary.TotalBytes()
		}
		if totalBytes >= m.renegotiateBytes {
			m.logger.Infof("session: renegotiation triggered by bytes (total=%d, limit=%d)",
				totalBytes, m.renegotiateBytes)
			shouldReneg = true
		}
	}

	// Check packet-based renegotiation (only if > 0; 0 means disabled)
	if m.renegotiatePackets > 0 {
		var totalPackets int64
		if primary := m.keySlots[KS_PRIMARY]; primary != nil {
			totalPackets = primary.TotalPackets()
		}
		if totalPackets >= m.renegotiatePackets {
			m.logger.Infof("session: renegotiation triggered by packets (total=%d, limit=%d)",
				totalPackets, m.renegotiatePackets)
			shouldReneg = true
		}
	}

	// Check for packet-id wrap trigger renegotiation. This matches OpenVPN's
	// packet_id_close_to_wrapping() soft-reset behavior (ssl.c:2675).
	if ks := m.dataKeyStateLocked(); ks != nil && ks.dataPacketIDWrapTriggered {
		m.logger.Infof("session: renegotiation triggered by packet-id wrap threshold (key-id=%d)", ks.KeyID)
		shouldReneg = true
	}

	if shouldReneg {
		m.renegotiationRequested = true
	}

	return shouldReneg
}

// RenegotiationRequested returns whether a renegotiation has been requested.
func (m *Manager) RenegotiationRequested() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.renegotiationRequested
}

// ClearRenegotiationRequest clears the renegotiation requested flag.
// This should be called if the renegotiation fails and needs to be retried.
func (m *Manager) ClearRenegotiationRequest() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renegotiationRequested = false
}

// RenegotiationConfig returns the current renegotiation configuration.
func (m *Manager) RenegotiationConfig() (seconds int, bytes int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.renegotiateSeconds, m.renegotiateBytes
}

// KeyEstablishedTime returns the time when the current key was established.
func (m *Manager) KeyEstablishedTime() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keyEstablishedTime
}

// UpdateLastPacketTime updates the last packet received time.
// This should be called whenever any valid packet is received from the server.
func (m *Manager) UpdateLastPacketTime() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastPacketTime = time.Now()
}

// NotifyOutgoingPacket records a successful packet send to the network.
// This mirrors OpenVPN's behavior of resetting the ping send timer on any
// outgoing packet.
func (m *Manager) NotifyOutgoingPacket() {
	select {
	case m.outgoingPacketActivity <- struct{}{}:
	default:
	}
}

// OutgoingPacketActivity returns a channel that is signaled when a packet is
// successfully sent to the network.
func (m *Manager) OutgoingPacketActivity() <-chan struct{} {
	return m.outgoingPacketActivity
}

// LastPacketTime returns the time when the last packet was received.
func (m *Manager) LastPacketTime() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPacketTime
}

// SetPingOptions updates the ping/keepalive settings.
// This is used to apply ping options received from the server via PUSH_REPLY.
func (m *Manager) SetPingOptions(pingSeconds, pingRestartSeconds, pingExitSeconds int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pingSeconds = pingSeconds
	m.pingRestartSeconds = pingRestartSeconds
	m.pingExitSeconds = pingExitSeconds
}

// PingConfig returns the ping configuration.
// Returns: pingInterval (0 = disabled), timeoutSeconds, timeoutAction
func (m *Manager) PingConfig() (interval int, timeout int, action int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	interval = m.pingSeconds

	// PingExit takes precedence over PingRestart
	if m.pingExitSeconds > 0 {
		timeout = m.pingExitSeconds
		action = PingTimeoutActionExit
	} else if m.pingRestartSeconds > 0 {
		timeout = m.pingRestartSeconds
		action = PingTimeoutActionRestart
	} else {
		timeout = 0
		action = PingTimeoutActionNone
	}
	return
}

// CheckPingTimeout checks if the ping timeout has been exceeded.
// Returns: exceeded bool, action int (0=none, 1=restart, 2=exit)
func (m *Manager) CheckPingTimeout() (exceeded bool, action int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Can't timeout if we haven't received any packets yet
	if m.lastPacketTime.IsZero() {
		return false, PingTimeoutActionNone
	}

	// Determine which timeout applies (ping-exit takes precedence)
	var timeout int
	if m.pingExitSeconds > 0 {
		timeout = m.pingExitSeconds
		action = PingTimeoutActionExit
	} else if m.pingRestartSeconds > 0 {
		timeout = m.pingRestartSeconds
		action = PingTimeoutActionRestart
	} else {
		return false, PingTimeoutActionNone
	}

	elapsed := time.Since(m.lastPacketTime)
	if elapsed >= time.Duration(timeout)*time.Second {
		return true, action
	}
	return false, PingTimeoutActionNone
}

// ============================================================================
// Multi-Key Slot Management (for Key Rotation / Lame Duck Support)
// ============================================================================

// KeySoftReset performs a soft reset, moving the current primary key to the
// lame duck slot and preparing for a new key negotiation.
// This implements OpenVPN's key_state_soft_reset() from ssl.c:2127-2138.
func (m *Manager) KeySoftReset() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	primary := m.keySlots[KS_PRIMARY]
	if primary == nil {
		return errors.New("session: no primary key to soft reset")
	}

	// Set must_die for the retiring key
	primary.MustDie = time.Now().Add(m.transitionWindow)
	m.logger.Infof("session: key %d moving to lame duck (must_die in %v)",
		primary.KeyID, m.transitionWindow)

	// Free any existing lame duck key (already expired or previous rotation)
	if m.keySlots[KS_LAME_DUCK] != nil {
		m.logger.Debugf("session: freeing old lame duck key %d",
			m.keySlots[KS_LAME_DUCK].KeyID)
		m.keySlots[KS_LAME_DUCK] = nil
	}

	// Move primary to lame duck
	m.keySlots[KS_LAME_DUCK] = primary

	// Advance key ID (0→1→2→...→7→1→...)
	m.keyID++
	m.keyID &= keyIDMask
	if m.keyID == 0 {
		m.keyID = 1
	}

	// Create new primary key state with fresh DataChannelKey
	newLocalKey, err := NewKeySource()
	if err != nil {
		return fmt.Errorf("session: failed to create new key source: %w", err)
	}

	newDCK := &DataChannelKey{}
	newDCK.AddLocalKey(newLocalKey)

	// Preserve remote session ID from the old key
	newKey := &KeyState{
		Key:               newDCK,
		KeyID:             m.keyID,
		State:             model.S_INITIAL,
		RemoteSessionID:   primary.RemoteSessionID,
		localDataPacketID: 1,
	}
	// Set must_negotiate for the new key state (key_state_init behavior).
	// This matches OpenVPN's ks->must_negotiate = now + handshake_window (ssl.c:2719).
	if m.handshakeWindow > 0 {
		newKey.SetNegotiationDeadline(m.handshakeWindow)
	}
	m.keySlots[KS_PRIMARY] = newKey

	// Reset control-channel sequencing state, matching OpenVPN's key_state_init()
	// behavior where reliable_init() restarts packet_id and ACK/queue state.
	m.controlEpoch++
	m.localControlPacketID = 1
	// Reset epoch timestamp for the new key epoch.
	m.controlReplayTimestamp = 0
	if m.controlChannelSecurity != nil && m.controlChannelSecurity.Mode != wire.ControlSecurityModeNone {
		// Unlike the initial hard reset, SOFT_RESET renegotiation does not reserve
		// replay_id=1 for a hard reset packet, so restart from 1.
		m.localControlReplayPacketID = 1
	}
	if m.controlReplayFilter != nil {
		m.controlReplayFilter.Reset()
	}

	// Also update the legacy keys slice for backward compatibility
	if int(m.keyID) >= len(m.keys) {
		// Extend the slice if needed
		for len(m.keys) <= int(m.keyID) {
			m.keys = append(m.keys, &DataChannelKey{})
		}
	}
	m.keys[m.keyID] = newDCK

	m.logger.Infof("session: new primary key %d created", m.keyID)
	return nil
}

// KeyByID returns the KeyState for a given key ID, checking both slots.
// Used for multi-key scanning during decryption.
func (m *Manager) KeyByID(keyID uint8) *KeyState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for i := 0; i < KS_SIZE; i++ {
		if ks := m.keySlots[i]; ks != nil && ks.KeyID == keyID {
			return ks
		}
	}
	return nil
}

// KeysForScan returns both key slots for decryption scanning.
// Index 0 = primary, Index 1 = lame duck (may be nil).
func (m *Manager) KeysForScan() [KS_SIZE]*KeyState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result [KS_SIZE]*KeyState
	result[KS_PRIMARY] = m.keySlots[KS_PRIMARY]
	result[KS_LAME_DUCK] = m.keySlots[KS_LAME_DUCK]
	return result
}

// PrimaryKey returns the primary KeyState.
func (m *Manager) PrimaryKey() *KeyState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keySlots[KS_PRIMARY]
}

// LameDuckKey returns the lame duck KeyState (may be nil).
func (m *Manager) LameDuckKey() *KeyState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keySlots[KS_LAME_DUCK]
}

// CheckAndExpireLameDuck checks if the lame duck key should be expired.
// Returns true if a key was expired.
func (m *Manager) CheckAndExpireLameDuck() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	lameDuck := m.keySlots[KS_LAME_DUCK]
	if lameDuck == nil {
		return false
	}

	if lameDuck.IsExpired() {
		m.logger.Infof("session: lame duck key %d expired and removed", lameDuck.KeyID)
		m.keySlots[KS_LAME_DUCK] = nil
		return true
	}
	return false
}

// LameDuckWakeup returns time until lame duck must die.
// Returns 0 if no lame duck key or no must_die set.
func (m *Manager) LameDuckWakeup() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lameDuck := m.keySlots[KS_LAME_DUCK]
	if lameDuck == nil || lameDuck.MustDie.IsZero() {
		return 0
	}

	remaining := time.Until(lameDuck.MustDie)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// MarkPrimaryKeyEstablished marks the primary key as established.
// This should be called when data channel keys are successfully derived.
func (m *Manager) MarkPrimaryKeyEstablished() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if primary := m.keySlots[KS_PRIMARY]; primary != nil {
		primary.EstablishedTime = time.Now()
		primary.State = model.S_GENERATED_KEYS
		primary.BytesRead = 0
		primary.BytesWritten = 0
		primary.PacketsRead = 0
		primary.PacketsWritten = 0
	}

	// Also update legacy fields for backward compatibility
	m.keyEstablishedTime = time.Now()
	m.dataChannelBytesRead = 0
	m.dataChannelBytesWritten = 0
	m.renegotiationRequested = false
	m.logger.Debugf("session: primary key established, renegotiation counters reset")
}

// AddKeyBytes adds bytes to the primary key slot counters.
func (m *Manager) AddKeyBytes(slotIdx int, read, written int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if slotIdx >= 0 && slotIdx < KS_SIZE && m.keySlots[slotIdx] != nil {
		m.keySlots[slotIdx].AddBytes(read, written)
	}

	// Also update legacy counters for backward compatibility
	m.dataChannelBytesRead += read
	m.dataChannelBytesWritten += written
}

// AddKeyPackets adds packets to the specified key slot counters.
func (m *Manager) AddKeyPackets(slotIdx int, read, written int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if slotIdx >= 0 && slotIdx < KS_SIZE && m.keySlots[slotIdx] != nil {
		m.keySlots[slotIdx].AddPackets(read, written)
	}
}

// GetKeySlotByKeyID finds the slot index for a given key ID.
// Returns -1 if not found.
func (m *Manager) GetKeySlotByKeyID(keyID uint8) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for i := 0; i < KS_SIZE; i++ {
		if ks := m.keySlots[i]; ks != nil && ks.KeyID == keyID {
			return i
		}
	}
	return -1
}

// CheckNegotiationTimeout checks if the primary key's negotiation has timed out.
// Returns true if the handshake has exceeded its must_negotiate deadline.
// This matches OpenVPN's check in ssl.c:2747:
// if (now >= ks->must_negotiate && ks->state < S_ACTIVE)
func (m *Manager) CheckNegotiationTimeout() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	primary := m.keySlots[KS_PRIMARY]
	if primary == nil {
		return false
	}

	return primary.IsNegotiationTimedOut()
}

// NegotiationTimeRemaining returns the time remaining until negotiation timeout.
// Returns 0 if no deadline is set or if already timed out.
func (m *Manager) NegotiationTimeRemaining() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	primary := m.keySlots[KS_PRIMARY]
	if primary == nil || primary.MustNegotiate.IsZero() {
		return 0
	}

	// Already completed negotiation
	if primary.State >= model.S_ACTIVE {
		return 0
	}

	remaining := time.Until(primary.MustNegotiate)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// HandshakeWindow returns the configured handshake window duration.
func (m *Manager) HandshakeWindow() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.handshakeWindow
}
