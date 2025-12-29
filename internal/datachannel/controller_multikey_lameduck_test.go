package datachannel

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

func TestDataChannel_SetupKeysForSlot_PrimaryRotationMovesOldToLameDuck(t *testing.T) {
	dc := &DataChannel{
		log:            log.Log,
		options:        &config.OpenVPNOptions{Compress: config.CompressionEmpty},
		sessionManager: makeTestingSession(),
		state:          makeTestingStateAEAD(),
	}

	dck := makeTestingDataChannelKey()

	if err := dc.SetupKeysForSlot(dck, session.KS_PRIMARY, 1); err != nil {
		t.Fatalf("SetupKeysForSlot(primary, key_id=1): %v", err)
	}
	km1, slot := dc.state.GetKeyMaterialByID(1)
	if km1 == nil {
		t.Fatal("expected key material for key_id=1")
	}
	if slot != session.KS_PRIMARY {
		t.Fatalf("slot=%d, want %d", slot, session.KS_PRIMARY)
	}

	if err := dc.SetupKeysForSlot(dck, session.KS_PRIMARY, 2); err != nil {
		t.Fatalf("SetupKeysForSlot(primary, key_id=2): %v", err)
	}
	km2, slot := dc.state.GetKeyMaterialByID(2)
	if km2 == nil {
		t.Fatal("expected key material for key_id=2")
	}
	if slot != session.KS_PRIMARY {
		t.Fatalf("slot=%d, want %d", slot, session.KS_PRIMARY)
	}

	km1After, slot := dc.state.GetKeyMaterialByID(1)
	if km1After == nil {
		t.Fatal("expected key material for key_id=1 after rotation")
	}
	if km1After != km1 {
		t.Fatal("expected the old primary key material to be preserved as lame duck")
	}
	if slot != session.KS_LAME_DUCK {
		t.Fatalf("slot=%d, want %d", slot, session.KS_LAME_DUCK)
	}
}

func TestDataChannelReadPacket_MultiKey_LameDuck_AEAD_UsesKeyMaterial(t *testing.T) {
	// Arrange a session where DataKeyID() is on the new primary key, while we
	// still receive packets using the retiring (lame duck) key.
	sm := makeTestingSession()
	sm.MarkPrimaryKeyEstablished()
	if err := sm.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset #1: %v", err)
	}
	sm.MarkPrimaryKeyEstablished()
	if err := sm.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset #2: %v", err)
	}
	sm.MarkPrimaryKeyEstablished()

	state := makeTestingStateAEAD()

	dc := &DataChannel{
		log:            log.Log,
		options:        &config.OpenVPNOptions{Compress: config.CompressionEmpty},
		sessionManager: sm,
		state:          state,
		decodeFn:       decodeEncryptedPayloadAEAD,
	}

	dckOld := makeTestingDataChannelKey()
	dckNew := makeTestingDataChannelKey()
	dckNew.Local().PreMaster[0] ^= 0xFF // ensure distinct key material

	kmOld := NewKeyMaterial(1)
	if err := kmOld.DeriveKeys(dckOld, sm.LocalSessionID(), sm.RemoteSessionID(), state.dataCipher, state.hash, true); err != nil {
		t.Fatalf("kmOld.DeriveKeys: %v", err)
	}
	kmNew := NewKeyMaterial(2)
	if err := kmNew.DeriveKeys(dckNew, sm.LocalSessionID(), sm.RemoteSessionID(), state.dataCipher, state.hash, true); err != nil {
		t.Fatalf("kmNew.DeriveKeys: %v", err)
	}

	// Simulate post-rotation legacy state being set to the new primary key.
	state.cipherKeyLocal = kmNew.GetCipherKeyLocal()
	state.hmacKeyLocal = kmNew.GetHmacKeyLocal()
	state.cipherKeyRemote = kmNew.GetCipherKeyRemote()
	state.hmacKeyRemote = kmNew.GetHmacKeyRemote()
	state.hmacLocal = kmNew.HmacLocal()
	state.hmacRemote = kmNew.HmacRemote()

	dc.state.SetKeyMaterial(session.KS_PRIMARY, kmNew)
	dc.state.SetKeyMaterial(session.KS_LAME_DUCK, kmOld)

	packetID := model.PacketID(1)
	packetIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(packetIDBytes, uint32(packetID))
	tag := bytes.Repeat([]byte{0xAA}, 16)
	ciphertext := []byte{0xBB}
	encryptedPayload := make([]byte, 0, len(packetIDBytes)+len(tag)+len(ciphertext))
	encryptedPayload = append(encryptedPayload, packetIDBytes...)
	encryptedPayload = append(encryptedPayload, tag...)
	encryptedPayload = append(encryptedPayload, ciphertext...)

	hmacKeyRemote := kmOld.GetHmacKeyRemote()
	expectedIV := make([]byte, 12)
	copy(expectedIV[:4], packetIDBytes)
	copy(expectedIV[4:], hmacKeyRemote[:8])

	expectedAAD := make([]byte, 0, 8)
	expectedAAD = append(expectedAAD, byte((byte(model.P_DATA_V2)<<3)|(1&0x07)))
	expectedAAD = append(expectedAAD, 0x00, 0x00, 0x00) // peer-id defaults to 0 in tests
	expectedAAD = append(expectedAAD, packetIDBytes...)

	expectedCipherKey := kmOld.GetCipherKeyRemote()
	dc.decryptFn = func(key []byte, ed *encryptedData) ([]byte, error) {
		if !bytes.Equal(key, expectedCipherKey[:]) {
			t.Fatalf("decrypt key mismatch")
		}
		if !bytes.Equal(ed.iv, expectedIV) {
			t.Fatalf("iv mismatch: got %x, want %x", ed.iv, expectedIV)
		}
		if !bytes.Equal(ed.aead, expectedAAD) {
			t.Fatalf("aead mismatch: got %x, want %x", ed.aead, expectedAAD)
		}
		defaultSlicePool.putSlice(ed.ciphertext)
		// CompressionEmpty uses stub+swap: 0xFB prefix + payload with first byte moved to end
		// "hello" -> 0xFB + "ello" + 'h'
		return []byte{0xFB, 'e', 'l', 'l', 'o', 'h'}, nil
	}

	p := &model.Packet{
		Opcode:  model.P_DATA_V2,
		KeyID:   1,
		Payload: encryptedPayload,
	}

	got, err := dc.readPacket(p)
	if err != nil {
		t.Fatalf("readPacket() error = %v, want nil", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("readPacket() = %q, want %q", got, "hello")
	}
}

func TestDataChannelReadPacket_MultiKey_LameDuck_NonAEAD_UsesKeyMaterial(t *testing.T) {
	sm := makeTestingSession()
	sm.MarkPrimaryKeyEstablished()
	if err := sm.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset #1: %v", err)
	}
	sm.MarkPrimaryKeyEstablished()
	if err := sm.KeySoftReset(); err != nil {
		t.Fatalf("KeySoftReset #2: %v", err)
	}
	sm.MarkPrimaryKeyEstablished()

	state := makeTestingStateNonAEAD()

	dc := &DataChannel{
		log:            log.Log,
		options:        &config.OpenVPNOptions{Compress: config.CompressionEmpty},
		sessionManager: sm,
		state:          state,
		decodeFn:       decodeEncryptedPayloadNonAEAD,
	}

	dckOld := makeTestingDataChannelKey()
	dckNew := makeTestingDataChannelKey()
	dckNew.Local().PreMaster[0] ^= 0xFF // ensure distinct key material

	kmOld := NewKeyMaterial(1)
	if err := kmOld.DeriveKeys(dckOld, sm.LocalSessionID(), sm.RemoteSessionID(), state.dataCipher, state.hash, true); err != nil {
		t.Fatalf("kmOld.DeriveKeys: %v", err)
	}
	kmNew := NewKeyMaterial(2)
	if err := kmNew.DeriveKeys(dckNew, sm.LocalSessionID(), sm.RemoteSessionID(), state.dataCipher, state.hash, true); err != nil {
		t.Fatalf("kmNew.DeriveKeys: %v", err)
	}

	// Simulate post-rotation legacy state being set to the new primary key.
	state.cipherKeyLocal = kmNew.GetCipherKeyLocal()
	state.hmacKeyLocal = kmNew.GetHmacKeyLocal()
	state.cipherKeyRemote = kmNew.GetCipherKeyRemote()
	state.hmacKeyRemote = kmNew.GetHmacKeyRemote()
	state.hmacLocal = kmNew.HmacLocal()
	state.hmacRemote = kmNew.HmacRemote()

	dc.state.SetKeyMaterial(session.KS_PRIMARY, kmNew)
	dc.state.SetKeyMaterial(session.KS_LAME_DUCK, kmOld)

	expectedCipherKey := kmOld.GetCipherKeyRemote()
	dc.decryptFn = func(key []byte, ed *encryptedData) ([]byte, error) {
		if !bytes.Equal(key, expectedCipherKey[:]) {
			t.Fatalf("decrypt key mismatch")
		}
		// Non-AEAD: decrypted payload = packet_id (4 bytes) + compression byte + payload
		// CompressionEmpty uses stub+swap: 0xFB prefix + payload with first byte moved to end
		// "hello" -> packet_id + 0xFB + "ello" + 'h'
		return []byte{0x00, 0x00, 0x00, 0x01, 0xFB, 'e', 'l', 'l', 'o', 'h'}, nil
	}

	iv := bytes.Repeat([]byte{0x01}, int(state.dataCipher.blockSize()))
	cipherText := []byte{0x02}
	h := kmOld.HmacRemote()
	h.Reset()
	h.Write(iv)
	h.Write(cipherText)
	mac := h.Sum(nil)

	encryptedPayload := make([]byte, 0, len(mac)+len(iv)+len(cipherText))
	encryptedPayload = append(encryptedPayload, mac...)
	encryptedPayload = append(encryptedPayload, iv...)
	encryptedPayload = append(encryptedPayload, cipherText...)

	p := &model.Packet{
		Opcode:  model.P_DATA_V2,
		KeyID:   1,
		Payload: encryptedPayload,
	}

	got, err := dc.readPacket(p)
	if err != nil {
		t.Fatalf("readPacket() error = %v, want nil", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("readPacket() = %q, want %q", got, "hello")
	}
}
