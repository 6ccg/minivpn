package datachannel

//
// Functions for encoding & writing packets
//

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/6ccg/minivpn/internal/bytesx"
	"github.com/6ccg/minivpn/internal/model"
	"github.com/6ccg/minivpn/internal/session"
	"github.com/6ccg/minivpn/pkg/config"
)

func dataOpcode(session *session.Manager) model.Opcode {
	// We infer DATA_V1/DATA_V2 from the first data packet received from the server.
	// When not inferred yet, default to DATA_V2 (legacy minivpn behaviour).
	if session == nil {
		return model.P_DATA_V2
	}
	if op := session.DataOpcode(); op != 0 {
		return op
	}
	return model.P_DATA_V2
}

// encryptAndEncodePayloadAEAD peforms encryption and encoding of the payload in AEAD modes (i.e., AES-GCM).
// Optimized to minimize allocations using scratch buffers.
func encryptAndEncodePayloadAEAD(log model.Logger, padded []byte, session *session.Manager, state *dataChannelState) ([]byte, error) {
	nextPacketID, keyID, err := session.LocalDataPacketIDAndKeyID()
	if err != nil {
		return nil, fmt.Errorf("bad packet id")
	}

	cipherKeyLocal := state.cipherKeyLocal
	hmacKeyLocal := state.hmacKeyLocal
	if km, _ := state.GetKeyMaterialByID(keyID); km != nil {
		cipherKeyLocal = km.GetCipherKeyLocal()
		hmacKeyLocal = km.GetHmacKeyLocal()
	}

	// Build AEAD header directly into scratch buffer (no allocation)
	// in AEAD mode, we authenticate:
	// - 1 byte: opcode/key
	// - 3 bytes: peer-id (only for P_DATA_V2)
	// - 4 bytes: packet-id
	aeadLen := 1 + 4 // opcode/key + packet_id
	if dataOpcode(session) == model.P_DATA_V2 {
		aeadLen += 3 // peer_id
	}

	aead := state.scratchAEADLocal[:aeadLen]
	offset := 0
	aead[offset] = byte((byte(dataOpcode(session)) << 3) | (byte(keyID) & 0x07))
	offset++
	if dataOpcode(session) == model.P_DATA_V2 {
		peerID := uint32(session.TunnelInfo().PeerID)
		aead[offset] = byte(peerID >> 16)
		aead[offset+1] = byte(peerID >> 8)
		aead[offset+2] = byte(peerID)
		offset += 3
	}
	binary.BigEndian.PutUint32(aead[offset:], uint32(nextPacketID))

	// Build IV directly into scratch buffer (no allocation)
	// the iv is the packetID concatenated with 8 bytes of the hmac key
	iv := state.scratchIVLocal[:]
	binary.BigEndian.PutUint32(iv[:4], uint32(nextPacketID))
	copy(iv[4:], hmacKeyLocal[:8])

	data := &plaintextData{
		iv:        iv,
		plaintext: padded,
		aead:      aead,
	}

	encryptFn := state.dataCipher.encrypt
	encrypted, err := encryptFn(cipherKeyLocal[:], data)
	if err != nil {
		return nil, err
	}

	// some reordering, because openvpn uses tag | payload
	boundary := len(encrypted) - 16
	tag := encrypted[boundary:]
	ciphertext := encrypted[:boundary]

	// Calculate output size and build result directly (single allocation for result)
	outputSize := aeadLen + 16 + len(ciphertext)
	result := make([]byte, outputSize)
	n := copy(result, aead)
	n += copy(result[n:], tag)
	copy(result[n:], ciphertext)

	return result, nil
}

// assign the random function to allow using a deterministic one in tests.
var genRandomFn = bytesx.GenRandomBytes

// encryptAndEncodePayloadNonAEAD peforms encryption and encoding of the payload in Non-AEAD modes (i.e., AES-CBC).
// Optimized to minimize allocations using direct slice operations.
func encryptAndEncodePayloadNonAEAD(log model.Logger, padded []byte, session *session.Manager, state *dataChannelState) ([]byte, error) {
	// For iv generation, OpenVPN uses a nonce-based PRNG that is initially seeded with
	// OpenSSL RAND_bytes function. I am assuming this is good enough for our current purposes.
	blockSize := state.dataCipher.blockSize()

	iv, err := genRandomFn(int(blockSize))
	if err != nil {
		return nil, err
	}
	data := &plaintextData{
		iv:        iv,
		plaintext: padded,
		aead:      nil,
	}

	keyID := uint8(0)
	if session != nil {
		keyID = session.DataKeyID()
	}

	cipherKeyLocal := state.cipherKeyLocal
	hmacLocal := state.hmacLocal
	if km, _ := state.GetKeyMaterialByID(keyID); km != nil {
		cipherKeyLocal = km.GetCipherKeyLocal()
		if kmHMAC := km.HmacLocal(); kmHMAC != nil {
			hmacLocal = kmHMAC
		}
	}

	encryptFn := state.dataCipher.encrypt
	ciphertext, err := encryptFn(cipherKeyLocal[:], data)
	if err != nil {
		return nil, err
	}

	hmacLocal.Reset()
	hmacLocal.Write(iv)
	hmacLocal.Write(ciphertext)
	computedMAC := hmacLocal.Sum(nil)

	// Calculate header size
	headerSize := 1 // opcode/key
	if dataOpcode(session) == model.P_DATA_V2 {
		headerSize += 3 // peer_id
	}

	// Total output: header + MAC + IV + ciphertext (single allocation)
	outputSize := headerSize + len(computedMAC) + len(iv) + len(ciphertext)
	result := make([]byte, outputSize)

	// Write directly to result buffer
	offset := 0
	result[offset] = byte((byte(dataOpcode(session)) << 3) | (byte(keyID) & 0x07))
	offset++
	if dataOpcode(session) == model.P_DATA_V2 {
		peerID := uint32(session.TunnelInfo().PeerID)
		result[offset] = byte(peerID >> 16)
		result[offset+1] = byte(peerID >> 8)
		result[offset+2] = byte(peerID)
		offset += 3
	}
	offset += copy(result[offset:], computedMAC)
	offset += copy(result[offset:], iv)
	copy(result[offset:], ciphertext)

	return result, nil
}

// doCompress adds compression bytes if needed by the passed compression options.
// if the compression stub is on, it sends the first byte to the last position,
// and it adds the compression preamble, according to the spec. compression
// lzo-no also adds a preamble. It returns a byte array and an error if the
// operation could not be completed.
func doCompress(b []byte, compress config.Compression) ([]byte, error) {
	switch compress {
	case "stub":
		// compression stub: send first byte to last
		// and add 0xfb marker on the first byte.
		b = append(b, b[0])
		b[0] = 0xfb
	case "lzo-no":
		// old "comp-lzo no" option
		b = append([]byte{0xfa}, b...)
	}
	return b, nil
}

var errPadding = errors.New("padding error")

// doPadding does pkcs7 padding of the encryption payloads as
// needed. if we're using the compression stub the padding is applied without taking the
// trailing bit into account. it returns the resulting byte array, and an error
// if the operatio could not be completed.
func doPadding(b []byte, compress config.Compression, blockSize uint8) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: %s", errPadding, "nothing to pad")
	}
	if compress == "stub" {
		// if we're using the compression stub
		// we need to account for a trailing byte
		// that we have appended in the doCompress stage.
		endByte := b[len(b)-1]
		padded, err := bytesx.BytesPadPKCS7(b[:len(b)-1], int(blockSize))
		if err != nil {
			return nil, err
		}
		padded[len(padded)-1] = endByte
		return padded, nil
	}
	padded, err := bytesx.BytesPadPKCS7(b, int(blockSize))
	if err != nil {
		return nil, err
	}
	return padded, nil
}

// prependPacketID returns a new buffer with the passed packetID
// concatenated at the beginning.
// Optimized to use single allocation instead of bytes.Buffer + make.
func prependPacketID(p model.PacketID, buf []byte) []byte {
	result := make([]byte, 4+len(buf))
	binary.BigEndian.PutUint32(result[:4], uint32(p))
	copy(result[4:], buf)
	return result
}

// opcodeAndKeyHeader returns the header byte encoding the opcode and keyID (3 upper
// and 5 lower bits, respectively)
func opcodeAndKeyHeader(session *session.Manager) byte {
	var keyID uint8
	if session != nil {
		keyID = session.DataKeyID()
	}
	return byte((byte(dataOpcode(session)) << 3) | (byte(keyID) & 0x07))
}
