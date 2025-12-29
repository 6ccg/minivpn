package tlssession

import (
	"encoding/binary"
	"testing"

	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

func decodeOptionStringAndAdvance(b []byte, offset int) (string, int, error) {
	if len(b) < offset+2 {
		return "", 0, errBadControlMessage
	}
	l := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	if len(b) < offset+2+l {
		return "", 0, errBadControlMessage
	}
	if l == 0 || b[offset+2+l-1] != 0x00 {
		return "", 0, errBadControlMessage
	}
	return string(b[offset+2 : offset+2+l-1]), offset + 2 + l, nil
}

func TestEncodeClientControlMessageAsBytes_AuthNoCachePurgesCredentials(t *testing.T) {
	k := &session.KeySource{}
	o := &config.OpenVPNOptions{
		AuthUserPass: true,
		AuthNoCache:  true,
		Username:     "user",
		Password:     "pass",
	}

	msg, err := encodeClientControlMessageAsBytes(k, o)
	if err != nil {
		t.Fatalf("encodeClientControlMessageAsBytes: %v", err)
	}
	if len(msg) < 4+1+len(k.Bytes()) {
		t.Fatalf("control message too short: %d", len(msg))
	}
	if msg[4] != 0x02 {
		t.Fatalf("unexpected key method: %d", msg[4])
	}

	offset := 4 + 1 + len(k.Bytes())
	_, offset, err = decodeOptionStringAndAdvance(msg, offset) // opts
	if err != nil {
		t.Fatalf("decode options: %v", err)
	}
	user, offset, err := decodeOptionStringAndAdvance(msg, offset)
	if err != nil {
		t.Fatalf("decode username: %v", err)
	}
	pass, _, err := decodeOptionStringAndAdvance(msg, offset)
	if err != nil {
		t.Fatalf("decode password: %v", err)
	}
	if user != "user" || pass != "pass" {
		t.Fatalf("unexpected encoded credentials: user=%q pass=%q", user, pass)
	}

	if o.Username != "" || o.Password != "" {
		t.Fatalf("expected credentials to be purged when auth-nocache is set, got user=%q pass=%q", o.Username, o.Password)
	}
}
