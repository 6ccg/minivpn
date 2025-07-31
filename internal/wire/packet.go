package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
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
	buf := &bytes.Buffer{}

	switch p.Opcode {
	case model.P_DATA_V2:
		// we assume this is an encrypted data packet,
		// so we serialize just the encrypted payload

	default:
		// Chunks that of the packet which will be composed in different ways
		// based on the type of control channel security used
		header := headerBytes(p)
		replay := replayProtectionBytes(p)
		ctrl, err := controlMessageBytes(p)
		if err != nil {
			return nil, fmt.Errorf("%w: %s\n", ErrMarshalPacket, err)
		}

		switch packetAuth.Mode {
		case ControlSecurityModeNone:
			buf.Write(header)
			buf.Write(ctrl)

		case ControlSecurityModeTLSAuth:
			digest := GenerateTLSAuthDigest(packetAuth.LocalDigestKey, header, replay, ctrl)

			buf.Write(header)
			buf.Write(digest[:])
			buf.Write(replay)
			buf.Write(ctrl)

		// Note HMAC header is in a different position than tls-auth
		case ControlSecurityModeTLSCrypt, ControlSecurityModeTLSCryptV2:
			digest := GenerateTLSCryptDigest(packetAuth.LocalDigestKey, header, replay, ctrl)

			// The packet digest (HMAC) is used as the IV for the AES-256-CTR encryption
			// of the control message
			enc, err := EncryptControlMessage(digest, *packetAuth.LocalCipherKey, ctrl)
			if err != nil {
				return nil, err
			}

			buf.Write(header)
			buf.Write(replay)
			buf.Write(digest[:])
			buf.Write(enc)

		}

		// tls-cryptv2 requires an additional "wrapped client key" to be appended to reset packets
		// which includes the client key (Kc) encrypted with a server key (not exposed to client) so
		// that the server can statelessly validate the keys used by the client
		if packetAuth.Mode == ControlSecurityModeTLSCryptV2 && p.Opcode == model.P_CONTROL_HARD_RESET_CLIENT_V3 {
			buf.Write(packetAuth.WrappedClientKey) // WKc
		}
	}

	return buf.Bytes(), nil
}

// UnmarshalPacket produces a packet after parsing the common header. We assume that
// the underlying connection has already stripped out the framing.
func UnmarshalPacket(buf []byte, packetAuth *ControlChannelSecurity) (*model.Packet, error) {
	// a valid packet is larger, but this allows us
	// to keep parsing a non-data packet.
	if len(buf) < 2 {
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
		var digestGot SHA1HMACDigest
		if _, err := io.ReadFull(buf, digestGot[:]); err != nil {
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
		match, err := validateTLSAuthDigest(p, packetAuth.RemoteDigestKey, &digestGot)
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

func validateTLSAuthDigest(p *model.Packet, key *ControlChannelKey, got *SHA1HMACDigest) (bool, error) {
	header := headerBytes(p)
	replay := replayProtectionBytes(p)
	ctrl, err := controlMessageBytes(p)
	if err != nil {
		return false, err
	}

	want := GenerateTLSAuthDigest(key, header, replay, ctrl)
	return *got == want, nil

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
	return got == want, nil

}

func headerBytes(p *model.Packet) []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte((byte(p.Opcode) << 3) | (p.KeyID & 0x07))
	buf.Write(p.LocalSessionID[:])
	return buf.Bytes()
}

// ReplayProtection refers to (ReplayPacketID, Timestamp)
// these fields are used by the server to reject packets that have
// already been processed.
func replayProtectionBytes(p *model.Packet) []byte {
	buf := &bytes.Buffer{}
	bytesx.WriteUint32(buf, uint32(p.ReplayPacketID))
	bytesx.WriteUint32(buf, uint32(p.Timestamp))
	return buf.Bytes()
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
	buf := &bytes.Buffer{}
	nAcks := len(p.ACKs)
	if nAcks > math.MaxUint8 {
		return buf.Bytes(), fmt.Errorf("%w: too many ACKs", ErrMarshalPacket)
	}
	buf.WriteByte(byte(nAcks))
	for i := 0; i < nAcks; i++ {
		bytesx.WriteUint32(buf, uint32(p.ACKs[i]))
	}
	// remote session id
	if len(p.ACKs) > 0 {
		buf.Write(p.RemoteSessionID[:])
	}
	if p.Opcode != model.P_ACK_V1 {
		// Message-level pet id
		bytesx.WriteUint32(buf, uint32(p.ID))
		buf.Write(p.Payload)
	}
	return buf.Bytes(), nil
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
