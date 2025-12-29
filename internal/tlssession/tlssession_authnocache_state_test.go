package tlssession

import (
	"testing"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

func Test_workersState_sendAuthRequestMessage_AuthNoCacheEncodesCredentialsOnSubsequentSends(t *testing.T) {
	conn := newScriptedConn()
	t.Cleanup(func() { _ = conn.Close() })

	opts := &config.OpenVPNOptions{
		AuthUserPass: true,
		AuthNoCache:  true,
		Username:     "user",
		Password:     "pass",
		Cipher:       "AES-256-GCM",
		Auth:         "SHA256",
		Proto:        config.ProtoUDP,
	}

	activeKey := &session.DataChannelKey{}
	if err := activeKey.AddLocalKey(&session.KeySource{}); err != nil {
		t.Fatalf("AddLocalKey: %v", err)
	}

	ws := &workersState{
		logger:  model.NewTestLogger(),
		options: opts,
	}

	// Send twice to simulate a later reset/renegotiation reusing the same worker state.
	for i := 0; i < 2; i++ {
		opts.Username = "user"
		opts.Password = "pass"
		if err := ws.sendAuthRequestMessage(conn, activeKey); err != nil {
			t.Fatalf("sendAuthRequestMessage (attempt=%d): %v", i, err)
		}
	}

	for i := 0; i < 2; i++ {
		var msg []byte
		select {
		case msg = <-conn.writes:
		default:
			t.Fatalf("missing auth request write (idx=%d)", i)
		}

		offset := 4 + 1 + len(activeKey.Local().Bytes())
		_, offset, err := decodeOptionStringAndAdvance(msg, offset) // opts
		if err != nil {
			t.Fatalf("decode options (idx=%d): %v", i, err)
		}
		user, offset, err := decodeOptionStringAndAdvance(msg, offset)
		if err != nil {
			t.Fatalf("decode username (idx=%d): %v", i, err)
		}
		pass, _, err := decodeOptionStringAndAdvance(msg, offset)
		if err != nil {
			t.Fatalf("decode password (idx=%d): %v", i, err)
		}
		if user != "user" || pass != "pass" {
			t.Fatalf("unexpected encoded credentials (idx=%d): user=%q pass=%q", i, user, pass)
		}
	}

	if opts.Username != "" || opts.Password != "" {
		t.Fatalf("expected credentials to be purged when auth-nocache is set, got user=%q pass=%q", opts.Username, opts.Password)
	}
}
