package wire

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"log"
	"math"

	"github.com/6ccg/minivpn/internal/bytesx"
	"github.com/6ccg/minivpn/internal/model"
)

// ErrEmptyPayload indicates tha the payload of an OpenVPN control packet is empty.
var ErrEmptyPayload = errors.New("openvpn: empty payload")

// ErrParsePacket is a generic packet parse error which may be further qualified.
var ErrParsePacket = errors.New("openvpn: packet parse error")

// ErrMarshalPacket is the error returned when we cannot marshal a packet.
var ErrMarshalPacket = errors.New("cannot marshal packet")

// ErrPacketTooShort indicates that a packet is too short.
var ErrPacketTooShort = errors.New("openvpn: packet too short")

func MarshalPacket(p *model.Packet, packetAuth *ControlChannelSecurity) ([]byte, error) {
	switch p.Opcode {
	case model.P_DATA_V1, model.P_DATA_V2:
		// Data packets already include the opcode/key header (and peer-id for v2)
		// inside the encrypted payload produced by the datachannel.
		// 直接返回 payload，零拷贝
		return p.Payload, nil
	default:
		// Chunks that of the packet which will be composed in different ways
		// based on the type of control channel security used
		header := headerBytes(p)
		replay := replayProtectionBytes(p)
		ctrl, err := controlMessageBytes(p)
		if err != nil {
			return nil, fmt.Errorf("%w: %s\n", ErrMarshalPacket, err)
		}

		// Debug: show packet structure being marshaled
		if debugEnabled("MINIVPN_DEBUG_PACKET") {
			log.Printf("[DEBUG-PACKET] MarshalPacket:")
			log.Printf("[DEBUG-PACKET]   Opcode: %s", p.Opcode)
			log.Printf("[DEBUG-PACKET]   KeyID: %d", p.KeyID)
			log.Printf("[DEBUG-PACKET]   LocalSessionID: %x", p.LocalSessionID)
			log.Printf("[DEBUG-PACKET]   ReplayPacketID: %d", p.ReplayPacketID)
			log.Printf("[DEBUG-PACKET]   Timestamp: %d", p.Timestamp)
			log.Printf("[DEBUG-PACKET]   ACKs: %v", p.ACKs)
			log.Printf("[DEBUG-PACKET]   RemoteSessionID: %x", p.RemoteSessionID)
			log.Printf("[DEBUG-PACKET]   ID: %d", p.ID)
			log.Printf("[DEBUG-PACKET]   Payload (%d bytes): %x", len(p.Payload), p.Payload)
			log.Printf("[DEBUG-PACKET]   header bytes: %x", header)
			log.Printf("[DEBUG-PACKET]   replay bytes: %x", replay)
			log.Printf("[DEBUG-PACKET]   ctrl bytes: %x", ctrl)
			log.Printf("[DEBUG-PACKET]   Security mode: %d", packetAuth.Mode)
		}

		// 预分配 buffer：根据安全模式估算大小
		// header(9) + replay(8) + digest(最大32) + ctrl + wrappedKey
		estimatedSize := len(header) + len(replay) + 32 + len(ctrl) + len(packetAuth.WrappedClientKey)
		buf := make([]byte, 0, estimatedSize)

		switch packetAuth.Mode {
		case ControlSecurityModeNone:
			buf = append(buf, header...)
			buf = append(buf, ctrl...)

		case ControlSecurityModeTLSAuth:
			digest := GenerateTLSAuthDigest(packetAuth.TLSAuthDigest, packetAuth.LocalDigestKey, header, replay, ctrl)

			// Debug: show tls-auth wire format
			if debugEnabled("MINIVPN_DEBUG_PACKET") {
				log.Printf("[DEBUG-PACKET] TLS-AUTH wire format: header || hmac || replay || ctrl")
				log.Printf("[DEBUG-PACKET]   HMAC digest: %x", digest)
			}

			buf = append(buf, header...)
			buf = append(buf, digest...)
			buf = append(buf, replay...)
			buf = append(buf, ctrl...)

		// Note HMAC header is in a different position than tls-auth
		case ControlSecurityModeTLSCrypt, ControlSecurityModeTLSCryptV2:
			digest := GenerateTLSCryptDigest(packetAuth.LocalDigestKey, header, replay, ctrl)

			// The packet digest (HMAC) is used as the IV for the AES-256-CTR encryption
			// of the control message
			enc, err := EncryptControlMessage(digest, *packetAuth.LocalCipherKey, ctrl)
			if err != nil {
				return nil, err
			}

			buf = append(buf, header...)
			buf = append(buf, replay...)
			buf = append(buf, digest[:]...)
			buf = append(buf, enc...)
		}

		// tls-cryptv2 requires an additional "wrapped client key" to be appended to reset packets
		// which includes the client key (Kc) encrypted with a server key (not exposed to client) so
		// that the server can statelessly validate the keys used by the client
		if packetAuth.Mode == ControlSecurityModeTLSCryptV2 && p.Opcode == model.P_CONTROL_HARD_RESET_CLIENT_V3 {
			buf = append(buf, packetAuth.WrappedClientKey...) // WKc
		}

		return buf, nil
	}
}

// UnmarshalPacket produces a packet after parsing the common header. We assume that
// the underlying connection has already stripped out the framing.
func UnmarshalPacket(buf []byte, packetAuth *ControlChannelSecurity) (*model.Packet, error) {
	// Minimum 1 byte needed to read opcode (matches OpenVPN's buf->len <= 0 check)
	if len(buf) < 1 {
		return nil, ErrPacketTooShort
	}
	// parsing opcode and keyID
	opcode := model.Opcode(buf[0] >> 3)
	keyID := buf[0] & 0x07

	// extract the packet payload and possibly the peerID
	var (
		payload []byte
		peerID  model.PeerID
	)
	switch opcode {
	case model.P_DATA_V2:
		if len(buf) < 4 {
			return nil, ErrPacketTooShort
		}
		copy(peerID[:], buf[1:4])
		payload = buf[4:]
	default:
		payload = buf[1:]
	}

	// ACKs and control packets require more complex parsing
	if opcode.IsControl() || opcode == model.P_ACK_V1 {
		return parseControlOrACKPacket(opcode, keyID, payload, packetAuth)
	}

	// otherwise just return the data packet.
	p := &model.Packet{
		Opcode:          opcode,
		KeyID:           keyID,
		PeerID:          peerID,
		LocalSessionID:  [8]byte{},
		ACKs:            []model.PacketID{},
		RemoteSessionID: [8]byte{},
		ID:              0,
		Payload:         payload,
	}
	return p, nil
}

// parseControlOrACKPacket parses the contents of a control or ACK packet.
func parseControlOrACKPacket(opcode model.Opcode, keyID byte, payload []byte, packetAuth *ControlChannelSecurity) (*model.Packet, error) {
	// make sure we have payload to parse and we're parsing control or ACK
	if len(payload) <= 0 {
		return nil, ErrEmptyPayload
	}
	if !opcode.IsControl() && opcode != model.P_ACK_V1 {
		return nil, fmt.Errorf("%w: %s", ErrParsePacket, "expected control/ack packet")
	}

	// create a buffer for parsing the packet
	buf := bytes.NewBuffer(payload)
	p := model.NewPacket(opcode, keyID, payload)

	// local session id
	if _, err := io.ReadFull(buf, p.LocalSessionID[:]); err != nil {
		return p, fmt.Errorf("%w: bad sessionID: %s", ErrParsePacket, err)
	}

	switch packetAuth.Mode {
	case ControlSecurityModeNone:
		if err := readControlMessage(p, buf); err != nil {
			return p, err
		}
	case ControlSecurityModeTLSAuth:
		digestSize := packetAuth.TLSAuthDigest.Size()
		if digestSize == 0 {
			digestSize = 20
		}
		digestGot := make([]byte, digestSize)
		if _, err := io.ReadFull(buf, digestGot); err != nil {
			return p, fmt.Errorf("%w: %s", ErrParsePacket, err)
		}

		if err := readReplayProtection(p, buf); err != nil {
			return p, err
		}
		if err := readControlMessage(p, buf); err != nil {
			return p, err
		}

		// Now calculate the hmac digest over the parsed packet, and confirm it
		// matches what we recieved from the server. Invalid digest could indicate
		// that the server is not in possession of pre-shared key OR packet contents
		// has been tampered with
		match, err := validateTLSAuthDigest(p, packetAuth.RemoteDigestKey, packetAuth.TLSAuthDigest, digestGot)
		if err != nil || !match {
			return p, fmt.Errorf("%w: packet digest (hmac) is not valid", ErrParsePacket)
		}

	case ControlSecurityModeTLSCrypt, ControlSecurityModeTLSCryptV2:
		if err := readReplayProtection(p, buf); err != nil {
			return p, err
		}

		// The HMAC digest that was included with the received packet
		var hmacGot SHA256HMACDigest
		if _, err := io.ReadFull(buf, hmacGot[:]); err != nil {
			return p, fmt.Errorf("%w: bad packet digest (tls-crypt): %s", ErrParsePacket, err)
		}

		ct, err := io.ReadAll(buf)
		if err != nil {
			return p, fmt.Errorf("%w: %s", ErrParsePacket, err)
		}

		body, err := DecryptControlMessage(hmacGot, *packetAuth.RemoteCipherKey, ct)
		if err != nil {
			return p, fmt.Errorf("%w: %s", ErrParsePacket, err)
		}

		buf := bytes.NewBuffer(body)
		if err := readControlMessage(p, buf); err != nil {
			return p, err
		}

		// Now calculate the hmac digest over the parsed packet, and confirm it
		// matches what we recieved from the server. Invalid digest could indicate
		// that the server is not in possession of pre-shared key OR packet contents
		// has been tampered with
		match, err := validateTLSCryptDigest(p, packetAuth.RemoteDigestKey, hmacGot)
		if err != nil || !match {
			return p, fmt.Errorf("%w: packet digest (hmac) is not valid", ErrParsePacket)
		}
	}

	return p, nil
}

func validateTLSAuthDigest(p *model.Packet, key *ControlChannelKey, digest crypto.Hash, got []byte) (bool, error) {
	if digest == 0 {
		digest = crypto.SHA1
	}
	keyLen := digest.Size()

	header := headerBytes(p)
	replay := replayProtectionBytes(p)
	ctrl, err := controlMessageBytes(p)
	if err != nil {
		return false, err
	}

	want := GenerateTLSAuthDigest(digest, key, header, replay, ctrl)
	match := hmac.Equal(got, want)

	// Debug: show HMAC validation details on mismatch
	if !match && debugEnabled("MINIVPN_DEBUG_HMAC") {
		log.Printf("[DEBUG-HMAC] validateTLSAuthDigest MISMATCH!")
		log.Printf("[DEBUG-HMAC]   Got:  %x", got)
		log.Printf("[DEBUG-HMAC]   Want: %x", want)
		log.Printf("[DEBUG-HMAC]   Digest: %s", digest.String())
		log.Printf("[DEBUG-HMAC]   Key used (first %d): %x", keyLen, key[:keyLen])
		log.Printf("[DEBUG-HMAC]   header: %x", header)
		log.Printf("[DEBUG-HMAC]   replay: %x", replay)
		log.Printf("[DEBUG-HMAC]   ctrl: %x", ctrl)
	}

	return match, nil

}

// Also performs validation of the digest
func validateTLSCryptDigest(p *model.Packet, key *ControlChannelKey, got SHA256HMACDigest) (bool, error) {
	header := headerBytes(p)
	replay := replayProtectionBytes(p)
	ctrl, err := controlMessageBytes(p)
	if err != nil {
		return false, err
	}

	want := GenerateTLSCryptDigest(key, header, replay, ctrl)
	return hmac.Equal(got[:], want[:]), nil

}

func headerBytes(p *model.Packet) []byte {
	// 固定9字节：1字节opcode/keyID + 8字节sessionID，零分配
	var buf [9]byte
	buf[0] = (byte(p.Opcode) << 3) | (p.KeyID & 0x07)
	copy(buf[1:], p.LocalSessionID[:])
	return buf[:]
}

// ReplayProtection refers to (ReplayPacketID, Timestamp)
// these fields are used by the server to reject packets that have
// already been processed.
func replayProtectionBytes(p *model.Packet) []byte {
	// 固定8字节：4字节packetID + 4字节timestamp，零分配
	var buf [8]byte
	bytesx.PutUint32(buf[0:4], uint32(p.ReplayPacketID))
	bytesx.PutUint32(buf[4:8], uint32(p.Timestamp))
	return buf[:]
}

func readReplayProtection(p *model.Packet, buf *bytes.Buffer) error {
	// replay packet id
	replayId, err := bytesx.ReadUint32(buf)
	if err != nil {
		return fmt.Errorf("%w: bad replay packet id (tls-auth): %s", ErrParsePacket, err)
	}
	p.ReplayPacketID = model.PacketID(replayId)

	// timestamp
	timestamp, err := bytesx.ReadUint32(buf)
	if err != nil {
		return fmt.Errorf("%w: bad packet timestamp (tls-auth): %s", ErrParsePacket, err)
	}
	p.Timestamp = model.PacketTimestamp(timestamp)

	return nil
}

// ControlMessage refers to (len(ACKs), ACKs[], RemoteSessionID, ID, Payload)
// it is also the segment of the packet that is encrypted when tls-crypt(-v2)
// operation modes are used
func controlMessageBytes(p *model.Packet) ([]byte, error) {
	nAcks := len(p.ACKs)
	if nAcks > math.MaxUint8 {
		return nil, fmt.Errorf("%w: too many ACKs", ErrMarshalPacket)
	}

	// 预估大小：1(nAcks) + 4*nAcks(ACKs) + 8(RemoteSessionID,仅当有ACK时) + 4(ID) + len(Payload)
	estimatedSize := 1 + 4*nAcks + 4 + len(p.Payload)
	if nAcks > 0 {
		estimatedSize += 8
	}
	buf := make([]byte, 0, estimatedSize)

	// ACK count
	buf = append(buf, byte(nAcks))

	// ACKs
	for i := 0; i < nAcks; i++ {
		var ackBuf [4]byte
		bytesx.PutUint32(ackBuf[:], uint32(p.ACKs[i]))
		buf = append(buf, ackBuf[:]...)
	}

	// remote session id (only if ACKs present)
	if nAcks > 0 {
		buf = append(buf, p.RemoteSessionID[:]...)
	}

	// packet ID and payload (not for P_ACK_V1)
	if p.Opcode != model.P_ACK_V1 {
		var idBuf [4]byte
		bytesx.PutUint32(idBuf[:], uint32(p.ID))
		buf = append(buf, idBuf[:]...)
		buf = append(buf, p.Payload...)
	}

	return buf, nil
}

func readControlMessage(p *model.Packet, buf *bytes.Buffer) error {
	// ack array length
	ackArrayLenByte, err := buf.ReadByte()
	if err != nil {
		return fmt.Errorf("%w: bad ack: %s", ErrParsePacket, err)
	}
	ackArrayLen := int(ackArrayLenByte)

	// ack array
	p.ACKs = make([]model.PacketID, ackArrayLen)
	for i := 0; i < ackArrayLen; i++ {
		val, err := bytesx.ReadUint32(buf)
		if err != nil {
			return fmt.Errorf("%w: cannot parse ack id: %s", ErrParsePacket, err)
		}
		p.ACKs[i] = model.PacketID(val)
	}

	// remote session id
	if ackArrayLen > 0 {
		if _, err = io.ReadFull(buf, p.RemoteSessionID[:]); err != nil {
			return fmt.Errorf("%w: bad remote sessionID: %s", ErrParsePacket, err)
		}
	}

	// packet id
	if p.Opcode != model.P_ACK_V1 {
		val, err := bytesx.ReadUint32(buf)
		if err != nil {
			return fmt.Errorf("%w: bad packetID: %s", ErrParsePacket, err)
		}
		p.ID = model.PacketID(val)
	}

	// payload
	p.Payload = buf.Bytes()
	return nil
}
