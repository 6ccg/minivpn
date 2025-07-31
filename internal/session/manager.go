package session

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/optional"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/wire"
	"github.com/ooni/minivpn/pkg/config"
)

var (
	// ErrExpiredKey is the error we raise when we have an expired key.
	ErrExpiredKey = errors.New("expired key")

	// ErrNoRemoteSessionID indicates we are missing the remote session ID.
	ErrNoRemoteSessionID = errors.New("missing remote session ID")
)

// Manager manages the session. The zero value is invalid. Please, construct
// using [NewManager]. This struct is concurrency safe.
type Manager struct {
	keyID                uint8
	keys                 []*DataChannelKey
	localControlPacketID model.PacketID
	localDataPacketID    model.PacketID
	localSessionID       model.SessionID
	logger               model.Logger
	mu                   sync.Mutex
	negState             model.NegotiationState
	dataOpcode           model.Opcode
	remoteSessionID      optional.Value[model.SessionID]
	tunnelInfo           model.TunnelInfo
	tracer               model.HandshakeTracer

	// Additional state required to support tls-auth
	controlChannelSecurity     *wire.ControlChannelSecurity
	localControlReplayPacketID model.PacketID

	// Ready is a channel where we signal that we can start accepting data, because we've
	// successfully generated key material for the data channel.
	Ready chan any

	// Failure is a channel where we receive any unrecoverable error.
	Failure chan error
}

// NewManager returns a [Manager] ready to be used.
func NewManager(config *config.Config) (*Manager, error) {
	key0 := &DataChannelKey{}

	sessionManager := &Manager{
		keyID: 0,
		keys:  []*DataChannelKey{key0},
		// localControlPacketID should be initialized to 1 because we handle hard-reset as special cases
		localControlPacketID: 1,
		localSessionID:       [8]byte{},
		logger:               config.Logger(),
		mu:                   sync.Mutex{},
		negState:             0,
		dataOpcode:           0,
		remoteSessionID:      optional.None[model.SessionID](),
		tunnelInfo:           model.TunnelInfo{},
		tracer:               config.Tracer(),

		// empirically, it seems that the reference OpenVPN server misbehaves if we initialize
		// the data packet ID counter to zero.
		localDataPacketID: 1,

		Ready:   make(chan any),
		Failure: make(chan error),
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

	// Need to load tls-auth from file
	if len(config.OpenVPNOptions().TLSAuthPath) != 0 {
		authData, err := os.ReadFile(config.OpenVPNOptions().TLSAuthPath)
		if err != nil {
			return sessionManager, err
		}

		// TODO: provide ability to pass in key direction
		sessionManager.controlChannelSecurity, err = wire.NewControlChannelSecurityTLSAuth(authData, 1)
		if err != nil {
			return sessionManager, err
		}

		// replay packet id starts at 1 but is offset here becuase the first packet is always a hard reset packet which is hardcoded to 1
		sessionManager.localControlReplayPacketID = 2
	} else if len(config.OpenVPNOptions().TLSCryptPath) != 0 {
		authData, err := os.ReadFile(config.OpenVPNOptions().TLSCryptPath)
		if err != nil {
			return sessionManager, err
		}

		sessionManager.controlChannelSecurity, err = wire.NewControlChannelSecurityTLSCrypt(authData)
		if err != nil {
			return sessionManager, err
		}

		// replay packet id starts at 1 but is offset here becuase the first packet is always a hard reset packet which is hardcoded to 1
		sessionManager.localControlReplayPacketID = 2
	} else if len(config.OpenVPNOptions().TLSCryptV2Path) != 0 {
		authData, err := os.ReadFile(config.OpenVPNOptions().TLSCryptV2Path)
		if err != nil {
			return sessionManager, err
		}

		sessionManager.controlChannelSecurity, err = wire.NewControlChannelSecurityTLSCryptV2(authData)
		if err != nil {
			return sessionManager, err
		}

		// replay packet id starts at 1 but is offset here becuase the first packet is always a hard reset packet which is hardcoded to 1
		sessionManager.localControlReplayPacketID = 2
	} else {
		sessionManager.controlChannelSecurity = &wire.ControlChannelSecurity{
			Mode: wire.ControlSecurityModeNone,
		}

	}

	return sessionManager, nil
}

// LocalSessionID gets the local session ID as bytes.
func (m *Manager) LocalSessionID() []byte {
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.localSessionID[:]
}

// RemoteSessionID gets the remote session ID as bytes.
func (m *Manager) RemoteSessionID() []byte {
	defer m.mu.Unlock()
	m.mu.Lock()
	rs := m.remoteSessionID
	if !rs.IsNone() {
		val := rs.Unwrap()
		return val[:]
	}
	return nil
}

// IsRemoteSessionIDSet returns whether we've set the remote session ID.
func (m *Manager) IsRemoteSessionIDSet() bool {
	defer m.mu.Unlock()
	m.mu.Lock()
	return !m.remoteSessionID.IsNone()
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

	if m.controlChannelSecurity.Mode != wire.ControlSecurityModeNone {
		replayId, err := m.localControlReplayPacketIDLocked()
		if err != nil {
			return nil, err
		}
		p.ReplayPacketID = replayId
		p.Timestamp = model.PacketTimestamp(time.Now().Unix())
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

	if m.controlChannelSecurity.Mode != wire.ControlSecurityModeNone {
		replayId, err := m.localControlReplayPacketIDLocked()
		if err != nil {
			return nil, err
		}
		packet.ReplayPacketID = replayId
		packet.Timestamp = model.PacketTimestamp(time.Now().Unix())
	}
	return packet, nil
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

	// additional fields required by tls-auth mode
	if m.controlChannelSecurity.Mode != wire.ControlSecurityModeNone {
		packet.Timestamp = model.PacketTimestamp(time.Now().Unix())
		packet.ReplayPacketID = 1 // Always 1 for a reset???
	}
	return packet
}

// LocalDataPacketID returns an unique Packet ID for the Data Channel. It
// increments the counter for the local data packet ID.
func (m *Manager) LocalDataPacketID() (model.PacketID, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.localDataPacketIDLocked()
}

// localDataPacketIDLocked returns an unique Packet ID for the Data Channel. It
// increments the counter for the local data packet ID.
func (m *Manager) localDataPacketIDLocked() (model.PacketID, error) {
	pid := m.localDataPacketID
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, ErrExpiredKey
	}
	m.localDataPacketID++
	return pid, nil
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

// NegotiationState returns the state of the negotiation.
func (m *Manager) NegotiationState() model.NegotiationState {
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.negState
}

// SetNegotiationState sets the state of the negotiation.
func (m *Manager) SetNegotiationState(sns model.NegotiationState) {
	defer m.mu.Unlock()
	m.mu.Lock()
	m.logger.Infof("[@] %s -> %s", m.negState, sns)
	m.tracer.OnStateChange(sns)
	m.negState = sns
	if sns == model.S_GENERATED_KEYS {
		m.Ready <- true
	}
}

// ActiveKey returns the dataChannelKey that is actively being used.
func (m *Manager) ActiveKey() (*DataChannelKey, error) {
	defer m.mu.Unlock()
	m.mu.Lock()
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
	defer m.mu.Unlock()
	m.mu.Lock()
	return m.keyID
}

// DataOpcode returns the last seen data packet opcode (P_DATA_V1 or P_DATA_V2).
// The zero value means we haven't inferred it yet.
func (m *Manager) DataOpcode() model.Opcode {
	defer m.mu.Unlock()
	m.mu.Lock()
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
	defer m.mu.Unlock()
	m.mu.Lock()
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
