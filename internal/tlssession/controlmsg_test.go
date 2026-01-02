package tlssession

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ooni/minivpn/internal/model"
)

func Test_NewTunnelInfoFromRemoteOptionsString(t *testing.T) {
	type args struct {
		remoteOpts remoteOptions
	}
	tests := []struct {
		name string
		args args
		want *model.TunnelInfo
	}{
		{
			name: "get route",
			args: args{
				remoteOptions{
					"route": []string{"1.1.1.1"},
				},
			},
			want: &model.TunnelInfo{
				GW: "1.1.1.1",
			},
		},
		{
			name: "get route from gw",
			args: args{
				remoteOptions{
					"route-gateway": []string{"1.1.2.2"},
				},
			},
			want: &model.TunnelInfo{
				GW: "1.1.2.2",
			},
		},
		{
			name: "get ip",
			args: args{
				remoteOptions{
					"ifconfig": []string{"1.1.3.3", "255.255.255.0"},
				},
			},
			want: &model.TunnelInfo{
				IP:      "1.1.3.3",
				NetMask: "255.255.255.0",
			},
		},
		{
			name: "get ip and route",
			args: args{
				remoteOptions{
					"ifconfig":      []string{"10.0.8.1", "255.255.255.0"},
					"route":         []string{"1.1.3.3"},
					"route-gateway": []string{"1.1.2.2"},
				},
			},
			want: &model.TunnelInfo{
				IP:      "10.0.8.1",
				NetMask: "255.255.255.0",
				GW:      "1.1.3.3",
			},
		},
		{
			name: "empty map",
			args: args{
				remoteOpts: remoteOptions{},
			},
			want: &model.TunnelInfo{},
		},
		{
			name: "entries with nil value field",
			args: args{
				remoteOpts: remoteOptions{"bad": nil},
			},
			want: &model.TunnelInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := cmp.Diff(newTunnelInfoFromPushedOptions(tt.args.remoteOpts), tt.want)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}

func Test_pushedOptionsAsMap(t *testing.T) {
	type args struct {
		pushedOptions []byte
	}
	tests := []struct {
		name string
		args args
		want remoteOptions
	}{
		{
			name: "do parse tunnel ip",
			args: args{[]byte("foo bar,ifconfig 10.0.0.3,")},
			want: remoteOptions{
				"foo":      []string{"bar"},
				"ifconfig": []string{"10.0.0.3"},
			},
		},
		{
			name: "empty string",
			args: args{[]byte{}},
			want: remoteOptions{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(pushedOptionsAsMap(tt.args.pushedOptions), tt.want); diff != "" {
				t.Error(cmp.Diff(pushedOptionsAsMap(tt.args.pushedOptions), tt.want))
			}
		})
	}
}

func Test_parseServerControlMessage(t *testing.T) {
	serverRespHex := "0000000002a490a20a83086e255b4d6c2a10ee9c488d683d1a1337bd4b32b24196a49c98632f00fddcab2c261cb6efae333eed9e1a7f83f3095a0da79b7a6f4709fe1ae040008856342c6465762d747970652074756e2c6c696e6b2d6d747520313535312c74756e2d6d747520313530302c70726f746f2054435076345f5345525645522c636970686572204145532d3235362d47434d2c61757468205b6e756c6c2d6469676573745d2c6b657973697a65203235362c6b65792d6d6574686f6420322c746c732d73657276657200"
	wantOptions := "V4,dev-type tun,link-mtu 1551,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
	wantRandom1, _ := hex.DecodeString("a490a20a83086e255b4d6c2a10ee9c488d683d1a1337bd4b32b24196a49c9863")
	wantRandom2, _ := hex.DecodeString("2f00fddcab2c261cb6efae333eed9e1a7f83f3095a0da79b7a6f4709fe1ae040")

	msg, _ := hex.DecodeString(serverRespHex)
	gotKeySource, gotOptions, err := parseServerControlMessage(msg)
	if err != nil {
		t.Errorf("expected null error, got %v", err)
	}
	if wantOptions != gotOptions {
		t.Errorf("parseServerControlMessage(). got options = %v, want options %v", gotOptions, wantOptions)
	}
	if !bytes.Equal(wantRandom1, gotKeySource.R1[:]) {
		t.Errorf("parseServerControlMessage(). got R1 = %v, want %v", gotKeySource.R1, wantRandom1)
	}
	if !bytes.Equal(wantRandom2, gotKeySource.R2[:]) {
		t.Errorf("parseServerControlMessage(). got R2 = %v, want %v", gotKeySource.R2, wantRandom2)
	}
}

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
