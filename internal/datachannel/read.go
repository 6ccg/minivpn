package datachannel

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

var (
	ErrTooShort      = errors.New("too short")
	ErrBadRemoteHMAC = errors.New("bad remote hmac")
)

func decodeEncryptedPayloadAEAD(log model.Logger, buf []byte, session *session.Manager, state *dataChannelState) (*encryptedData, error) {
	//   P_DATA_V2 GCM data channel crypto format
	//   48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	//   [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	//   - means authenticated -    * means encrypted *
	//   [ - opcode/peer-id - ] [ - packet ID - ] [ TAG ] [ * packet payload * ]

	// preconditions
	runtimex.Assert(state != nil, "passed nil state")
	runtimex.Assert(state.dataCipher != nil, "data cipher not initialized")

	if len(buf) == 0 || len(buf) < 20 {
		return &encryptedData{}, fmt.Errorf("%w: %d bytes", ErrTooShort, len(buf))
	}
	if len(state.hmacKeyRemote) < 8 {
		return &encryptedData{}, ErrBadRemoteHMAC
	}

	// Extract packet_id for replay protection
	// Note: replay check is performed AFTER successful decryption, following
	// OpenVPN official behavior (crypto.c:openvpn_decrypt_aead L465).
	// This prevents attackers from polluting the replay window with forged packets.
	packet_id := buf[:4]
	packetID := model.PacketID(binary.BigEndian.Uint32(packet_id))

	remoteHMAC := state.hmacKeyRemote[:8]

	// Build headers directly into scratch buffer (no allocation)
	headerLen := 1 + 4 // opcode/key + packet_id
	if dataOpcode(session) == model.P_DATA_V2 {
		headerLen += 3 // peer_id
	}

	headers := state.scratchAEADRemote[:headerLen]
	offset := 0
	headers[offset] = opcodeAndKeyHeader(session)
	offset++
	if dataOpcode(session) == model.P_DATA_V2 {
		peerID := uint32(session.TunnelInfo().PeerID)
		headers[offset] = byte(peerID >> 16)
		headers[offset+1] = byte(peerID >> 8)
		headers[offset+2] = byte(peerID)
		offset += 3
	}
	copy(headers[offset:], packet_id)

	// Swap tag|payload -> payload|tag using pooled buffer
	// ciphertext starts at buf[20:], tag is at buf[4:20]
	ciphertextLen := len(buf) - 20
	payloadLen := ciphertextLen + 16 // ciphertext + tag

	// Use slice pool for payload buffer
	payload := defaultSlicePool.getSlice(payloadLen)
	copy(payload[:ciphertextLen], buf[20:])  // ciphertext
	copy(payload[ciphertextLen:], buf[4:20]) // tag

	// Build IV directly into scratch buffer (no allocation)
	// iv := packetID | remoteHMAC
	iv := state.scratchIVRemote[:]
	copy(iv[:4], packet_id)
	copy(iv[4:], remoteHMAC)

	// Note: caller must return payload to pool after decryption via defaultSlicePool.putSlice()
	encrypted := &encryptedData{
		iv:         iv,
		ciphertext: payload,
		aead:       headers,
		packetID:   packetID, // For replay check after successful decryption
	}
	return encrypted, nil
}

var ErrCannotDecode = errors.New("cannot decode")

func decodeEncryptedPayloadNonAEAD(log model.Logger, buf []byte, session *session.Manager, state *dataChannelState) (*encryptedData, error) {
	runtimex.Assert(state != nil, "passed nil state")
	runtimex.Assert(state.dataCipher != nil, "data cipher not initialized")

	hashSize := uint8(state.hmacRemote.Size())
	blockSize := state.dataCipher.blockSize()

	minLen := hashSize + blockSize

	if len(buf) < int(minLen) {
		return &encryptedData{}, fmt.Errorf("%w: too short (%d bytes)", ErrCannotDecode, len(buf))
	}

	receivedHMAC := buf[:hashSize]
	iv := buf[hashSize : hashSize+blockSize]
	cipherText := buf[hashSize+blockSize:]

	state.hmacRemote.Reset()
	state.hmacRemote.Write(iv)
	state.hmacRemote.Write(cipherText)
	computedHMAC := state.hmacRemote.Sum(nil)

	if !hmac.Equal(computedHMAC, receivedHMAC) {
		log.Warnf("expected: %x, got: %x", computedHMAC, receivedHMAC)
		return &encryptedData{}, fmt.Errorf("%w: %s", ErrCannotDecrypt, ErrBadHMAC)
	}

	encrypted := &encryptedData{
		iv:         iv,
		ciphertext: cipherText,
		aead:       []byte{}, // no AEAD data in this mode, leaving it empty to satisfy common interface
	}
	return encrypted, nil
}

// maybeDecompress de-serializes the data from the payload according to the framing
// given by different compression methods. only the different no-compression
// modes are supported at the moment, so no real decompression is done. It
// returns a byte array, and an error if the operation could not be completed
// successfully.
func maybeDecompress(b []byte, st *dataChannelState, opt *config.OpenVPNOptions) ([]byte, error) {
	if st == nil || st.dataCipher == nil {
		return []byte{}, fmt.Errorf("%w:%s", ErrBadInput, "bad state")
	}
	if opt == nil {
		return []byte{}, fmt.Errorf("%w:%s", ErrBadInput, "bad options")
	}

	var compr byte // compression type
	var payload []byte

	switch st.dataCipher.isAEAD() {
	case true:
		// AEAD mode: replay check was already done in decodeEncryptedPayloadAEAD
		// The decrypted payload does not contain packet_id
		switch opt.Compress {
		case config.CompressionStub, config.CompressionLZONo:
			// these are deprecated in openvpn 2.5.x
			compr = b[0]
			payload = b[1:]
		default:
			compr = 0x00
			payload = b[:]
		}
	default: // non-aead
		// Non-AEAD mode: decrypted payload contains packet_id at the beginning
		if len(b) < 4 {
			return []byte{}, fmt.Errorf("%w: payload too short for packet_id", ErrBadInput)
		}
		remotePacketID := model.PacketID(binary.BigEndian.Uint32(b[:4]))

		// Check for replay attack using sliding window
		if err := st.CheckReplay(remotePacketID); err != nil {
			return []byte{}, err
		}

		switch opt.Compress {
		case config.CompressionStub, config.CompressionLZONo:
			compr = b[4]
			payload = b[5:]
		default:
			compr = 0x00
			payload = b[4:]
		}
	}

	switch compr {
	case 0xfb:
		// compression stub swap:
		// we get the last byte and replace the compression byte
		// these are deprecated in openvpn 2.5.x
		end := payload[len(payload)-1]
		b := payload[:len(payload)-1]
		payload = append([]byte{end}, b...)
	case 0x00, 0xfa:
		// do nothing
		// 0x00 is compress-no,
		// 0xfa is the old no compression or comp-lzo no case.
		// http://build.openvpn.net/doxygen/comp_8h_source.html
		// see: https://community.openvpn.net/openvpn/ticket/952#comment:5
	default:
		return []byte{}, fmt.Errorf("%w: cannot handle compression %x", errBadCompression, compr)
	}
	return payload, nil
}
