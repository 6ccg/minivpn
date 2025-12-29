package tlssession

import (
	"runtime"
	"strings"
	"testing"

	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

func Test_encodeClientControlMessageAsBytes_AuthNoCacheRequiresReinjectionAcrossSends(t *testing.T) {
	k := &session.KeySource{}
	o := &config.OpenVPNOptions{
		AuthUserPass: true,
		AuthNoCache:  true,
		Username:     "user",
		Password:     "pass",
	}

	_, err := encodeClientControlMessageAsBytes(k, o)
	if err != nil {
		t.Fatalf("encodeClientControlMessageAsBytes(first): %v", err)
	}
	if o.Username != "" || o.Password != "" {
		t.Fatalf("expected credentials to be purged after first send, got user=%q pass=%q", o.Username, o.Password)
	}

	if _, err := encodeClientControlMessageAsBytes(k, o); err == nil {
		t.Fatalf("expected second send to fail without reinjection")
	}

	o.Username = "user"
	o.Password = "pass"

	msg, err := encodeClientControlMessageAsBytes(k, o)
	if err != nil {
		t.Fatalf("encodeClientControlMessageAsBytes(second): %v", err)
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
		t.Fatalf("expected credentials to still be encoded on subsequent sends, got user=%q pass=%q", user, pass)
	}
}

func Test_encodeClientControlMessageAsBytes_PeerInfoIVCiphers_matchesOpenVPN25Defaults(t *testing.T) {
	t.Run("default cipher does not advertise CBC", func(t *testing.T) {
		k := &session.KeySource{}
		o := &config.OpenVPNOptions{
			Cipher: "AES-256-GCM",
			Auth:   "SHA256",
			Proto:  config.ProtoUDP,
		}

		msg, err := encodeClientControlMessageAsBytes(k, o)
		if err != nil {
			t.Fatalf("encodeClientControlMessageAsBytes: %v", err)
		}

		offset := 4 + 1 + len(k.Bytes())
		_, offset, err = decodeOptionStringAndAdvance(msg, offset) // opts
		if err != nil {
			t.Fatalf("decode options: %v", err)
		}
		_, offset, err = decodeOptionStringAndAdvance(msg, offset) // username
		if err != nil {
			t.Fatalf("decode username: %v", err)
		}
		_, offset, err = decodeOptionStringAndAdvance(msg, offset) // password
		if err != nil {
			t.Fatalf("decode password: %v", err)
		}
		peerInfo, _, err := decodeOptionStringAndAdvance(msg, offset)
		if err != nil {
			t.Fatalf("decode peer info: %v", err)
		}

		if !strings.Contains(peerInfo, "IV_VER=2.5.11\n") {
			t.Fatalf("unexpected IV_VER in peer info: %q", peerInfo)
		}

		wantPlat := map[string]string{
			"windows": "win",
			"linux":   "linux",
			"darwin":  "mac",
			"freebsd": "freebsd",
			"netbsd":  "netbsd",
			"openbsd": "openbsd",
			"solaris": "solaris",
			"android": "android",
		}[runtime.GOOS]
		if wantPlat == "" {
			t.Skipf("unsupported GOOS for IV_PLAT expectation: %s", runtime.GOOS)
		}
		if !strings.Contains(peerInfo, "IV_PLAT="+wantPlat+"\n") {
			t.Fatalf("unexpected IV_PLAT in peer info (want %q): %q", wantPlat, peerInfo)
		}

		if !strings.Contains(peerInfo, "IV_CIPHERS=AES-256-GCM:AES-128-GCM\n") {
			t.Fatalf("unexpected IV_CIPHERS in peer info: %q", peerInfo)
		}
		if strings.Contains(peerInfo, "AES-256-CBC") {
			t.Fatalf("unexpected CBC advertised in peer info: %q", peerInfo)
		}
	})

	t.Run("CBC cipher appends itself for negotiation", func(t *testing.T) {
		k := &session.KeySource{}
		o := &config.OpenVPNOptions{
			Cipher: "AES-256-CBC",
			Auth:   "SHA256",
			Proto:  config.ProtoUDP,
		}

		msg, err := encodeClientControlMessageAsBytes(k, o)
		if err != nil {
			t.Fatalf("encodeClientControlMessageAsBytes: %v", err)
		}

		offset := 4 + 1 + len(k.Bytes())
		_, offset, err = decodeOptionStringAndAdvance(msg, offset) // opts
		if err != nil {
			t.Fatalf("decode options: %v", err)
		}
		_, offset, err = decodeOptionStringAndAdvance(msg, offset) // username
		if err != nil {
			t.Fatalf("decode username: %v", err)
		}
		_, offset, err = decodeOptionStringAndAdvance(msg, offset) // password
		if err != nil {
			t.Fatalf("decode password: %v", err)
		}
		peerInfo, _, err := decodeOptionStringAndAdvance(msg, offset)
		if err != nil {
			t.Fatalf("decode peer info: %v", err)
		}

		if !strings.Contains(peerInfo, "IV_CIPHERS=AES-256-GCM:AES-128-GCM:AES-256-CBC\n") {
			t.Fatalf("unexpected IV_CIPHERS in peer info: %q", peerInfo)
		}
	})
}
