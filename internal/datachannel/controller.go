package datachannel

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

// dataChannelHandler manages the data "channel".
type dataChannelHandler interface {
	setupKeys(*session.DataChannelKey) error
	writePacket([]byte) (*model.Packet, error)
	readPacket(*model.Packet) ([]byte, error)
	decodeEncryptedPayload([]byte, *dataChannelState) (*encryptedData, error)
	encryptAndEncodePayload([]byte, *dataChannelState) ([]byte, error)
}

// DataChannel represents the data "channel", that will encrypt and decrypt the tunnel payloads.
// data implements the dataHandler interface.
type DataChannel struct {
	options         *config.OpenVPNOptions
	sessionManager  *session.Manager
	state           *dataChannelState
	decodeFn        func(model.Logger, []byte, *session.Manager, *dataChannelState) (*encryptedData, error)
	encryptEncodeFn func(model.Logger, []byte, *session.Manager, *dataChannelState) ([]byte, error)
	decryptFn       func([]byte, *encryptedData) ([]byte, error)
	log             model.Logger
}

var _ dataChannelHandler = &DataChannel{} // Ensure that we implement dataChannelHandler

// NewDataChannelFromOptions returns a new data object, initialized with the
// options given. it also returns any error raised.
func NewDataChannelFromOptions(logger model.Logger,
	opt *config.OpenVPNOptions,
	sessionManager *session.Manager) (*DataChannel, error) {
	runtimex.Assert(opt != nil, "openvpn datachannel: opts cannot be nil")
	runtimex.Assert(len(opt.Cipher) != 0, "need a configured cipher option")
	runtimex.Assert(len(opt.Auth) != 0, "need a configured auth option")

	state := &dataChannelState{}
	// Initialize replay filter with appropriate mode:
	// - UDP: backtrack mode (allows out-of-order packets within window)
	// - TCP: sequential mode (requires strictly increasing packet IDs)
	state.initReplayFilter(!opt.Proto.IsTCP())
	data := &DataChannel{
		options:        opt,
		sessionManager: sessionManager,
		state:          state,
		log:            logger,
	}

	dataCipher, err := newDataCipherFromCipherSuite(opt.Cipher)
	if err != nil {
		return data, err
	}
	data.state.dataCipher = dataCipher
	switch dataCipher.isAEAD() {
	case true:
		data.decodeFn = decodeEncryptedPayloadAEAD
		data.encryptEncodeFn = encryptAndEncodePayloadAEAD
	case false:
		data.decodeFn = decodeEncryptedPayloadNonAEAD
		data.encryptEncodeFn = encryptAndEncodePayloadNonAEAD
	}

	hmacHash, ok := newHMACFactory(strings.ToLower(opt.Auth))
	if !ok {
		return data, fmt.Errorf("%w: %s", ErrInitError, fmt.Sprintf("no such mac: %v", opt.Auth))
	}
	data.state.hash = hmacHash
	data.decryptFn = state.dataCipher.decrypt

	logger.Info(fmt.Sprintf("Cipher: %s", opt.Cipher))
	logger.Info(fmt.Sprintf("Auth:   %s", opt.Auth))

	return data, nil
}

// DecodeEncryptedPayload calls the corresponding function for AEAD or Non-AEAD decryption.
func (d *DataChannel) decodeEncryptedPayload(b []byte, dcs *dataChannelState) (*encryptedData, error) {
	return d.decodeFn(d.log, b, d.sessionManager, dcs)
}

// setSetupKeys performs the key expansion from the local and remote
// keySources, initializing the data channel state.
func (d *DataChannel) setupKeys(dck *session.DataChannelKey) error {
	runtimex.Assert(dck != nil, "data channel key cannot be nil")
	if !dck.Ready() {
		return fmt.Errorf("%w: %s", errDataChannelKey, "key not ready")
	}
	master := prf(
		dck.Local().PreMaster[:],
		[]byte("OpenVPN master secret"),
		dck.Local().R1[:],
		dck.Remote().R1[:],
		[]byte{}, []byte{},
		48)

	keys := prf(
		master,
		[]byte("OpenVPN key expansion"),
		dck.Local().R2[:],
		dck.Remote().R2[:],
		d.sessionManager.LocalSessionID(),
		d.sessionManager.RemoteSessionID(),
		256)

	var keyLocal, hmacLocal, keyRemote, hmacRemote keySlot
	copy(keyLocal[:], keys[0:64])
	copy(hmacLocal[:], keys[64:128])
	copy(keyRemote[:], keys[128:192])
	copy(hmacRemote[:], keys[192:256])

	d.state.cipherKeyLocal = keyLocal
	d.state.hmacKeyLocal = hmacLocal
	d.state.cipherKeyRemote = keyRemote
	d.state.hmacKeyRemote = hmacRemote

	log.Debugf("Cipher key local:  %x", keyLocal)
	log.Debugf("Cipher key remote: %x", keyRemote)
	log.Debugf("Hmac key local:    %x", hmacLocal)
	log.Debugf("Hmac key remote:   %x", hmacRemote)

	hashSize := d.state.hash().Size()
	d.state.hmacLocal = hmac.New(d.state.hash, hmacLocal[:hashSize])
	d.state.hmacRemote = hmac.New(d.state.hash, hmacRemote[:hashSize])

	log.Info("Key derivation OK")
	if d.log != nil && d.sessionManager != nil {
		ti := d.sessionManager.TunnelInfo()
		d.log.Infof("Data channel packet format: %s (peer-id=%d)", dataOpcode(d.sessionManager), ti.PeerID)
	}
	return nil
}

// SetupKeysForSlot derives keys for a specific slot and key ID.
// This is used during key renegotiation to set up the new key in KS_PRIMARY
// while the old key remains in KS_LAME_DUCK.
func (d *DataChannel) SetupKeysForSlot(dck *session.DataChannelKey, slot int, keyID uint8) error {
	runtimex.Assert(dck != nil, "data channel key cannot be nil")
	if !dck.Ready() {
		return fmt.Errorf("%w: %s", errDataChannelKey, "key not ready")
	}

	km := NewKeyMaterial(keyID)
	backtrackMode := !d.options.Proto.IsTCP()

	err := km.DeriveKeys(
		dck,
		d.sessionManager.LocalSessionID(),
		d.sessionManager.RemoteSessionID(),
		d.state.dataCipher,
		d.state.hash,
		backtrackMode,
	)
	if err != nil {
		return err
	}

	d.state.SetKeyMaterial(slot, km)

	// Also update legacy fields for backward compatibility when setting primary key
	if slot == session.KS_PRIMARY {
		d.state.cipherKeyLocal = km.GetCipherKeyLocal()
		d.state.hmacKeyLocal = km.GetHmacKeyLocal()
		d.state.cipherKeyRemote = km.GetCipherKeyRemote()
		d.state.hmacKeyRemote = km.GetHmacKeyRemote()
		d.state.hmacLocal = km.HmacLocal()
		d.state.hmacRemote = km.HmacRemote()
	}

	d.log.Infof("Key material derived for slot %d, key_id %d", slot, keyID)
	return nil
}

// ExpireLameDuck clears the lame duck key slot.
func (d *DataChannel) ExpireLameDuck() {
	d.state.ClearSlot(session.KS_LAME_DUCK)
	d.log.Debug("Lame duck key expired and cleared")
}

//
// write + encrypt
//

// createDataPacket creates a data packet from an already-encrypted payload.
// This is used by fragmentation to wrap fragment data in proper packet headers.
func (d *DataChannel) createDataPacket(encryptedPayload []byte) *model.Packet {
	opcode := dataOpcode(d.sessionManager)
	packet := model.NewPacket(opcode, d.sessionManager.CurrentKeyID(), encryptedPayload)
	if opcode == model.P_DATA_V2 {
		peerid := &bytes.Buffer{}
		bytesx.WriteUint24(peerid, uint32(d.sessionManager.TunnelInfo().PeerID))
		packet.PeerID = model.PeerID(peerid.Bytes())
	}
	return packet
}

func (d *DataChannel) writePacket(payload []byte) (*model.Packet, error) {
	runtimex.Assert(d.state != nil, "data: nil state")
	runtimex.Assert(d.state.dataCipher != nil, "data.state: nil dataCipher")
	var err error

	switch d.state.dataCipher.isAEAD() {
	case false: // non-aead
		localPacketID, _ := d.sessionManager.LocalDataPacketID()
		payload = prependPacketID(localPacketID, payload)
	case true:
	}

	payload, err = doCompress(payload, d.options.Compress)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}
	// encryptAndEncodePayload adds padding, if needed, and it also includes the
	// opcode/keyid and peer-id headers and, if used, any authenticated
	// parts in the packet.
	encrypted, err := d.encryptAndEncodePayload(payload, d.state)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}

	// TODO(ainghazal): increment counter for used bytes
	// and trigger renegotiation if we're near the end of the key useful lifetime.

	opcode := dataOpcode(d.sessionManager)
	packet := model.NewPacket(opcode, d.sessionManager.CurrentKeyID(), encrypted)
	if opcode == model.P_DATA_V2 {
		peerid := &bytes.Buffer{}
		bytesx.WriteUint24(peerid, uint32(d.sessionManager.TunnelInfo().PeerID))
		packet.PeerID = model.PeerID(peerid.Bytes())
	}
	return packet, nil
}

// encrypt calls the corresponding function for AEAD or Non-AEAD decryption.
// Due to the particularities of the iv generation on each of the modes, encryption and encoding are
// done together in the same function.
func (d *DataChannel) encryptAndEncodePayload(plaintext []byte, dcs *dataChannelState) ([]byte, error) {
	runtimex.Assert(dcs != nil, "datachanelState is nil")
	runtimex.Assert(dcs.dataCipher != nil, "dcs.dataCipher is nil")

	if len(plaintext) == 0 {
		return []byte{}, fmt.Errorf("%w: nothing to encrypt", ErrCannotEncrypt)
	}

	padded, err := doPadding(plaintext, d.options.Compress, dcs.dataCipher.blockSize())
	if err != nil {
		return []byte{}, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}

	encrypted, err := d.encryptEncodeFn(d.log, padded, d.sessionManager, d.state)
	if err != nil {
		return []byte{}, fmt.Errorf("%w: %s", ErrCannotEncrypt, err)
	}
	return encrypted, nil

}

//
// read + decrypt
//

func (d *DataChannel) readPacket(p *model.Packet) ([]byte, error) {
	if len(p.Payload) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrCannotDecrypt, "empty payload")
	}
	runtimex.Assert(p.IsData(), "ReadPacket expects data packet")

	// Try multi-key decryption first: look up key material by packet's key_id
	km, slotIdx := d.state.GetKeyMaterialByID(p.KeyID)
	if km != nil {
		plaintext, err := d.decryptWithKeyMaterial(p.Payload, km)
		if err != nil {
			return nil, err
		}
		// Update counters on the correct key slot
		d.sessionManager.AddKeyBytes(slotIdx, int64(len(p.Payload)), 0)
		d.sessionManager.AddKeyPackets(slotIdx, 1, 0)
		return maybeDecompress(plaintext, d.state, d.options)
	}

	// Fallback to legacy single-key decryption (for backward compatibility)
	plaintext, err := d.decrypt(p.Payload)
	if err != nil {
		return nil, err
	}

	// get plaintext payload from the decrypted plaintext
	return maybeDecompress(plaintext, d.state, d.options)
}

// decryptWithKeyMaterial decrypts using a specific KeyMaterial.
func (d *DataChannel) decryptWithKeyMaterial(encrypted []byte, km *KeyMaterial) ([]byte, error) {
	if d.decryptFn == nil {
		return nil, ErrInitError
	}

	// Decode the encrypted payload
	encryptedData, err := d.decodeEncryptedPayloadWithKeyMaterial(encrypted, km)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCannotDecrypt, err)
	}
	if len(encryptedData.ciphertext) == 0 {
		return nil, fmt.Errorf("%w: nothing to decrypt", ErrCannotDecrypt)
	}

	// Get cipher key as a slice
	cipherKey := km.GetCipherKeyRemote()
	plainText, err := d.decryptFn(cipherKey[:], encryptedData)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCannotDecrypt, err)
	}

	// AEAD mode: check replay AFTER successful decryption/authentication
	// This follows OpenVPN official behavior (crypto.c:openvpn_decrypt_aead L465)
	// to prevent attackers from polluting the replay window with forged packets.
	//
	// IMPORTANT: Use per-key replay filter (km.CheckReplay) instead of shared filter.
	// Each key_state in OpenVPN has its own packet_id_rec for replay protection.
	// Using a shared filter would cause issues during key rotation when packet IDs
	// from different keys may overlap.
	if d.state.dataCipher.isAEAD() && encryptedData.packetID != 0 {
		if err := km.CheckReplay(encryptedData.packetID); err != nil {
			return nil, err
		}
	}

	return plainText, nil
}

// decodeEncryptedPayloadWithKeyMaterial decodes encrypted data using a specific KeyMaterial's HMAC.
func (d *DataChannel) decodeEncryptedPayloadWithKeyMaterial(b []byte, km *KeyMaterial) (*encryptedData, error) {
	// For now, delegate to the existing decoder which uses legacy state fields
	// TODO: Full multi-key support would require passing KeyMaterial to decode functions
	return d.decodeFn(d.log, b, d.sessionManager, d.state)
}

func (d *DataChannel) decrypt(encrypted []byte) ([]byte, error) {
	if d.decryptFn == nil {
		return []byte{}, ErrInitError
	}
	if len(d.state.hmacKeyRemote) == 0 {
		d.log.Warn("decrypt: not ready yet")
		return nil, ErrCannotDecrypt
	}
	encryptedData, err := d.decodeEncryptedPayload(encrypted, d.state)
	if err != nil {
		return []byte{}, fmt.Errorf("%w: %s", ErrCannotDecrypt, err)
	}
	if len(encryptedData.ciphertext) == 0 {
		return []byte{}, fmt.Errorf("%w: nothing to decrypt", ErrCannotDecrypt)
	}

	plainText, err := d.decryptFn(d.state.cipherKeyRemote[:], encryptedData)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCannotDecrypt, err)
	}

	// AEAD mode: check replay AFTER successful decryption/authentication
	// This follows OpenVPN official behavior (crypto.c:openvpn_decrypt_aead L465)
	// to prevent attackers from polluting the replay window with forged packets.
	//
	// NOTE: This legacy path uses the shared replay filter (d.state.CheckReplay)
	// because there is no per-key KeyMaterial available. This is acceptable for
	// backward compatibility with single-key mode, but the multi-key path
	// (decryptWithKeyMaterial) should be preferred as it uses per-key filters.
	if d.state.dataCipher.isAEAD() && encryptedData.packetID != 0 {
		if err := d.state.CheckReplay(encryptedData.packetID); err != nil {
			return nil, err
		}
	}

	return plainText, nil
}
