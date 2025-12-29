package datachannel

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"testing"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

func TestDataChannelReadPacket_MultiKey_NonAEAD_ReplayIsPerKey(t *testing.T) {
	// Non-AEAD: decrypted payload = packet_id (4 bytes) + compression byte + payload
	// CompressionEmpty uses stub+swap: 0xFB prefix + payload with first byte moved to end
	// "hello" -> packet_id + 0xFB + "ello" + 'h'
	plaintext := []byte{0x00, 0x00, 0x00, 0x01, 0xFB, 'e', 'l', 'l', 'o', 'h'}

	dc := &DataChannel{
		options:        &config.OpenVPNOptions{Compress: config.CompressionEmpty},
		sessionManager: makeTestingSession(),
		state:          makeTestingStateNonAEAD(),
		decodeFn: func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error) {
			return &encryptedData{ciphertext: []byte{0x01}}, nil
		},
		decryptFn: func([]byte, *encryptedData) ([]byte, error) {
			return plaintext, nil
		},
	}

	// Simulate a previous key having advanced the shared replay window.
	// If the code incorrectly uses the shared replay filter for multi-key
	// decryption, packet_id=1 would be rejected as a replay.
	dc.state.setInitialPacketIDForTest(model.PacketID(1000))

	km := NewKeyMaterial(1)
	// Prepare minimum per-key auth material so multi-key decode succeeds.
	km.hmacKeyRemote = dc.state.hmacKeyRemote
	km.hmacRemote = hmac.New(sha1.New, km.hmacKeyRemote[:sha1.Size])
	km.replayFilter = newReplayFilter(DefaultSeqBacktrack, true) // UDP/backtrack mode
	km.SetReady(true)
	dc.state.SetKeyMaterial(session.KS_PRIMARY, km)

	// Build a minimal non-AEAD payload: HMAC(IV|ciphertext) | IV | ciphertext.
	blockSize := dc.state.dataCipher.blockSize()
	iv := bytes.Repeat([]byte{0x01}, int(blockSize))
	cipherText := []byte{0x02}
	h := hmac.New(sha1.New, km.hmacKeyRemote[:sha1.Size])
	h.Write(iv)
	h.Write(cipherText)
	receivedHMAC := h.Sum(nil)
	encryptedPayload := append(append(receivedHMAC, iv...), cipherText...)

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

	// Same packet_id again should be rejected, proving replay is tracked per key.
	_, err = dc.readPacket(p)
	if !errors.Is(err, ErrReplayAttack) {
		t.Fatalf("readPacket() error = %v, want %v", err, ErrReplayAttack)
	}
}
