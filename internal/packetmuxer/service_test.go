package packetmuxer

import (
	"bytes"
	"testing"
	"time"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/wire"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

const ovpnStaticKeyAuth = `
-----BEGIN OpenVPN Static key V1-----
924a040a27a5c4295447269a187881ae
26ae188b79b0c803ccdb42540893ce44
af970a6b0e57ac769dfbfcac741d6ac1
91e801ff587c8a932665dc615b3a95bc
1326c23ddf2f1790a943ee0b8bce8a44
15722fadb5efad8d906b04b562845439
791353992e19de0c914b56cc561737a5
750bb1c48ce0bac3497d59c80f4b273b
73a0f983fae3ee3e8ea45dc71fdf68d0
fbd71cd43652f5c14e57d2038c147077
61f448d3a4cf7d7b6a3fcfae36ab297f
7e8fdc44140349ef934f350abb90d201
12919f79d9a2f05f5999e08c2df5a102
9d1a67a964932b774da964a24523a5f8
234dc1c3dc15ceb459c1b68a321a3153
6a4dac97daef6c81d6ac870acf97f29c
-----END OpenVPN Static key V1-----
`

func newTestWorkersState(t *testing.T, sm *session.Manager, logger model.Logger) (*workersState, <-chan *model.Packet, <-chan *model.Notification) {
	t.Helper()

	muxerToReliable := make(chan *model.Packet, 1)
	muxerToData := make(chan *model.Packet, 1)
	notifyTLS := make(chan *model.Notification, 1)

	ws := &workersState{
		logger:          logger,
		hardResetTicker: time.NewTicker(longWakeup),
		handshakeTimer:  time.NewTimer(longWakeup),
		notifyTLS:       notifyTLS,
		muxerToReliable: muxerToReliable,
		muxerToData:     muxerToData,
		sessionManager:  sm,
		workersManager:  workers.NewManager(logger),
	}

	t.Cleanup(func() {
		ws.hardResetTicker.Stop()
		if ws.handshakeTimer != nil {
			ws.handshakeTimer.Stop()
		}
	})

	return ws, muxerToReliable, notifyTLS
}

func newTestSessionManager(t *testing.T, opts *config.OpenVPNOptions) (*session.Manager, model.Logger) {
	t.Helper()

	logger := model.NewTestLogger()
	cfg := config.NewConfig(
		config.WithLogger(logger),
		config.WithOpenVPNOptions(opts),
	)
	sm, err := session.NewManager(cfg)
	if err != nil {
		t.Fatalf("session.NewManager() failed: %v", err)
	}
	return sm, logger
}

func mustMarshalPacket(t *testing.T, packet *model.Packet, packetAuth *wire.ControlChannelSecurity) []byte {
	t.Helper()
	raw, err := wire.MarshalPacket(packet, packetAuth)
	if err != nil {
		t.Fatalf("wire.MarshalPacket() failed: %v", err)
	}
	return raw
}

func mustSessionID(b byte) model.SessionID {
	return model.SessionID{b, b, b, b, b, b, b, b}
}

func TestHandleRawPacket_HardResetServerV2StartsNewSessionMidHandshake(t *testing.T) {
	opts := &config.OpenVPNOptions{}
	sm, logger := newTestSessionManager(t, opts)

	oldRemoteSessionID := mustSessionID(0x11)
	newRemoteSessionID := mustSessionID(0x22)

	sm.SetRemoteSessionID(oldRemoteSessionID)
	sm.SetNegotiationState(model.S_ACTIVE)

	ws, muxerToReliable, notifyTLS := newTestWorkersState(t, sm, logger)

	p := &model.Packet{
		Opcode:         model.P_CONTROL_HARD_RESET_SERVER_V2,
		KeyID:          0,
		LocalSessionID: newRemoteSessionID,
		ACKs:           nil,
		ID:             1,
		Payload:        nil,
	}
	raw := mustMarshalPacket(t, p, sm.PacketAuth())

	if err := ws.handleRawPacket(raw); err != nil {
		t.Fatalf("handleRawPacket() failed: %v", err)
	}

	select {
	case pkt := <-muxerToReliable:
		pkt.Free()
	default:
		t.Fatalf("expected HARD_RESET to be forwarded to reliabletransport")
	}

	select {
	case <-notifyTLS:
		// ok
	default:
		t.Fatalf("expected TLS reset notification for mid-session HARD_RESET")
	}

	if got := sm.NegotiationState(); got != model.S_START {
		t.Fatalf("expected negotiation state %s, got %s", model.S_START, got)
	}
	if got := sm.RemoteSessionID(); !bytes.Equal(got, newRemoteSessionID[:]) {
		t.Fatalf("expected remote session id to be replaced, got=%x want=%x", got, newRemoteSessionID[:])
	}
}

func TestSerializeAndEmit_RefreshesControlReplayFieldsOnEachSend(t *testing.T) {
	opts := &config.OpenVPNOptions{
		TLSAuth: []byte(ovpnStaticKeyAuth),
	}
	sm, logger := newTestSessionManager(t, opts)

	muxerToNetwork := make(chan []byte, 2)
	ws := &workersState{
		logger:         logger,
		muxerToNetwork: muxerToNetwork,
		sessionManager: sm,
		tracer:         &model.DummyTracer{},
		workersManager: workers.NewManager(logger),
	}

	packet := sm.NewHardResetPacket()
	if err := ws.serializeAndEmit(packet); err != nil {
		t.Fatalf("serializeAndEmit() failed: %v", err)
	}
	raw1 := <-muxerToNetwork

	if err := ws.serializeAndEmit(packet); err != nil {
		t.Fatalf("serializeAndEmit() failed: %v", err)
	}
	raw2 := <-muxerToNetwork

	pa := sm.PacketAuth()
	if pa.Mode != wire.ControlSecurityModeTLSAuth {
		t.Fatalf("expected tls-auth mode in test, got %v", pa.Mode)
	}

	digestSize := pa.TLSAuthDigest.Size()
	if digestSize == 0 {
		digestSize = 20
	}
	replayOffset := 9 + digestSize
	replay1 := raw1[replayOffset : replayOffset+8]
	replay2 := raw2[replayOffset : replayOffset+8]
	if bytes.Equal(replay1, replay2) {
		t.Fatalf("expected replay bytes to differ between sends, got %x", replay1)
	}
}

func TestMoveDownWorker_RefreshesControlReplayFieldsOnEachSend(t *testing.T) {
	opts := &config.OpenVPNOptions{
		TLSAuth: []byte(ovpnStaticKeyAuth),
	}
	sm, logger := newTestSessionManager(t, opts)

	dataOrControlToMuxer := make(chan *model.Packet, 2)
	muxerToNetwork := make(chan []byte, 2)
	workersManager := workers.NewManager(logger)

	ws := &workersState{
		logger:                   logger,
		dataOrControlToMuxer:     dataOrControlToMuxer,
		muxerToNetwork:           muxerToNetwork,
		sessionManager:           sm,
		tracer:                   &model.DummyTracer{},
		workersManager:           workersManager,
		loggedOutgoingDataPacket: false,
	}

	workersManager.StartWorker(ws.moveDownWorker)
	t.Cleanup(func() {
		workersManager.StartShutdown()
		workersManager.WaitWorkersShutdown()
	})

	packet := &model.Packet{
		Opcode:         model.P_CONTROL_V1,
		KeyID:          0,
		LocalSessionID: mustSessionID(0x11),
		ID:             1,
		Payload:        []byte("payload"),
	}
	dataOrControlToMuxer <- packet
	dataOrControlToMuxer <- packet

	raw1 := <-muxerToNetwork
	raw2 := <-muxerToNetwork

	pa := sm.PacketAuth()
	if pa.Mode != wire.ControlSecurityModeTLSAuth {
		t.Fatalf("expected tls-auth mode in test, got %v", pa.Mode)
	}

	digestSize := pa.TLSAuthDigest.Size()
	if digestSize == 0 {
		digestSize = 20
	}
	replayOffset := 9 + digestSize
	replay1 := raw1[replayOffset : replayOffset+8]
	replay2 := raw2[replayOffset : replayOffset+8]
	if bytes.Equal(replay1, replay2) {
		t.Fatalf("expected replay bytes to differ between sends, got %x", replay1)
	}
}

func TestHandleRawPacket_HardResetServerV2NotDroppedByControlReplayOnNewSession(t *testing.T) {
	opts := &config.OpenVPNOptions{
		TLSAuth: []byte(ovpnStaticKeyAuth),
	}
	sm, logger := newTestSessionManager(t, opts)

	oldRemoteSessionID := mustSessionID(0x33)
	newRemoteSessionID := mustSessionID(0x44)

	sm.SetRemoteSessionID(oldRemoteSessionID)
	sm.SetNegotiationState(model.S_ACTIVE)

	// Prime the control replay filter with a high maxID so that a new session's
	// initial replay_id=1 would be rejected if we apply replay checks before
	// session matching / reset.
	ts := model.PacketTimestamp(uint32(time.Now().Unix()))
	for i := model.PacketID(1); i <= 100; i++ {
		if err := sm.CheckControlReplay(i, ts); err != nil {
			t.Fatalf("CheckControlReplay(%d) unexpected error: %v", i, err)
		}
	}

	ws, muxerToReliable, notifyTLS := newTestWorkersState(t, sm, logger)

	p := &model.Packet{
		Opcode:         model.P_CONTROL_HARD_RESET_SERVER_V2,
		KeyID:          0,
		LocalSessionID: newRemoteSessionID,
		ReplayPacketID: 1,
		Timestamp:      ts,
		ACKs:           nil,
		ID:             1,
		Payload:        nil,
	}
	raw := mustMarshalPacket(t, p, sm.PacketAuth())

	if err := ws.handleRawPacket(raw); err != nil {
		t.Fatalf("handleRawPacket() failed: %v", err)
	}

	select {
	case pkt := <-muxerToReliable:
		pkt.Free()
	default:
		t.Fatalf("expected HARD_RESET to be forwarded to reliabletransport")
	}

	select {
	case <-notifyTLS:
		// ok
	default:
		t.Fatalf("expected TLS reset notification for new-session HARD_RESET")
	}

	if got := sm.NegotiationState(); got != model.S_START {
		t.Fatalf("expected negotiation state %s, got %s", model.S_START, got)
	}
	if got := sm.RemoteSessionID(); !bytes.Equal(got, newRemoteSessionID[:]) {
		t.Fatalf("expected remote session id to be replaced, got=%x want=%x", got, newRemoteSessionID[:])
	}
}

func TestStartHardReset_RetransmissionUsesFreshReplayID(t *testing.T) {
	opts := &config.OpenVPNOptions{TLSAuth: []byte(ovpnStaticKeyAuth)}
	sm, logger := newTestSessionManager(t, opts)

	muxerToNetwork := make(chan []byte, 2)
	ws := &workersState{
		logger:          logger,
		hardResetTicker: time.NewTicker(longWakeup),
		handshakeTimer:  time.NewTimer(longWakeup),
		muxerToNetwork:  muxerToNetwork,
		sessionManager:  sm,
		tracer:          &model.DummyTracer{},
		workersManager:  workers.NewManager(logger),
	}
	t.Cleanup(func() {
		ws.hardResetTicker.Stop()
		if ws.handshakeTimer != nil {
			ws.handshakeTimer.Stop()
		}
	})

	if err := ws.startHardReset(); err != nil {
		t.Fatalf("startHardReset (first) failed: %v", err)
	}
	raw1 := <-muxerToNetwork
	p1, err := wire.UnmarshalPacket(raw1, sm.PacketAuth())
	if err != nil {
		t.Fatalf("wire.UnmarshalPacket (first) failed: %v", err)
	}

	if err := ws.startHardReset(); err != nil {
		t.Fatalf("startHardReset (retransmit) failed: %v", err)
	}
	raw2 := <-muxerToNetwork
	p2, err := wire.UnmarshalPacket(raw2, sm.PacketAuth())
	if err != nil {
		t.Fatalf("wire.UnmarshalPacket (retransmit) failed: %v", err)
	}

	if p1.ReplayPacketID == p2.ReplayPacketID {
		t.Fatalf("expected hard reset replay-id to change across retransmits, got %d then %d", p1.ReplayPacketID, p2.ReplayPacketID)
	}
	if p2.ReplayPacketID <= p1.ReplayPacketID {
		t.Fatalf("expected hard reset replay-id to increase: %d -> %d", p1.ReplayPacketID, p2.ReplayPacketID)
	}
}

func TestMoveDownWorker_ControlRetransmitUsesFreshReplayID(t *testing.T) {
	opts := &config.OpenVPNOptions{TLSAuth: []byte(ovpnStaticKeyAuth)}
	sm, logger := newTestSessionManager(t, opts)

	dataOrControlToMuxer := make(chan *model.Packet, 2)
	muxerToNetwork := make(chan []byte, 2)

	ws := &workersState{
		logger:               logger,
		dataOrControlToMuxer: dataOrControlToMuxer,
		muxerToNetwork:       muxerToNetwork,
		sessionManager:       sm,
		workersManager:       workers.NewManager(logger),
	}

	ws.workersManager.StartWorker(ws.moveDownWorker)
	t.Cleanup(func() {
		ws.workersManager.StartShutdown()
		ws.workersManager.WaitWorkersShutdown()
	})

	// Create one control packet and send it twice to simulate reliable transport retransmission.
	packet, err := sm.NewPacket(model.P_CONTROL_V1, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("session.Manager.NewPacket() failed: %v", err)
	}
	dataOrControlToMuxer <- packet
	dataOrControlToMuxer <- packet

	var raw1, raw2 []byte
	select {
	case raw1 = <-muxerToNetwork:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first outgoing packet")
	}
	select {
	case raw2 = <-muxerToNetwork:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for second outgoing packet")
	}

	// TLS-AUTH format: header(9) || hmac(digest) || replay(8) || ctrl.
	digestSize := sm.PacketAuth().TLSAuthDigest.Size()
	if digestSize == 0 {
		digestSize = 20
	}
	off := 9 + digestSize
	if len(raw1) < off+8 || len(raw2) < off+8 {
		t.Fatalf("serialized packets too short for tls-auth replay fields (len1=%d len2=%d)", len(raw1), len(raw2))
	}
	replay1 := binary.BigEndian.Uint32(raw1[off : off+4])
	replay2 := binary.BigEndian.Uint32(raw2[off : off+4])
	if replay1 == replay2 {
		t.Fatalf("expected replay_id to change across retransmits, got %d then %d", replay1, replay2)
	}
	if replay2 <= replay1 {
		t.Fatalf("expected replay_id to increase across retransmits, got %d then %d", replay1, replay2)
	}
}
