package datachannel

import "bytes"

// OpenVPN ping packet signature.
// This random string identifies an OpenVPN ping packet.
// It should be of sufficient length and randomness
// so as not to collide with other tunnel data.
//
// Reference: OpenVPN 2.5 src/openvpn/ping.c
var pingString = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// pingStringSize is the size of the ping signature.
const pingStringSize = 16

// IsPingPacket checks if the given payload is an OpenVPN ping packet.
// It verifies both length and content match the official ping signature.
//
// Reference: OpenVPN 2.5 src/openvpn/ping.h is_ping_msg()
func IsPingPacket(payload []byte) bool {
	if len(payload) != pingStringSize {
		return false
	}
	return bytes.Equal(payload, pingString)
}

// PingPayload returns a copy of the OpenVPN ping packet payload.
// This is used to create keepalive packets to send to the server.
func PingPayload() []byte {
	p := make([]byte, pingStringSize)
	copy(p, pingString)
	return p
}
