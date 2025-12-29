package config

import (
	"errors"
	"strings"
	"testing"
)

func TestOptions_String(t *testing.T) {
	type fields struct {
		Remote    string
		Port      string
		Proto     Proto
		Username  string
		Password  string
		Cipher    string
		Auth      string
		TLSMaxVer string

		Compress   Compression
		ProxyOBFS4 string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name:   "empty cipher and no compression",
			fields: fields{},
			want:   "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-client",
		},
		{
			name: "proto tcp",
			fields: fields{
				Cipher: "AES-128-GCM",
				Auth:   "sha512",
				Proto:  ProtoTCP,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto TCPv4_CLIENT,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client",
		},
		{
			// OpenVPN 2.5: all compression modes output ",comp-lzo" for backward compatibility
			name: "compress stub outputs comp-lzo",
			fields: fields{
				Cipher:   "AES-128-GCM",
				Auth:     "sha512",
				Proto:    ProtoUDP,
				Compress: CompressionStub,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client,comp-lzo",
		},
		{
			// OpenVPN 2.5: all compression modes output ",comp-lzo" for backward compatibility
			name: "compress lzo-no outputs comp-lzo",
			fields: fields{
				Cipher:   "AES-128-GCM",
				Auth:     "sha512",
				Proto:    ProtoUDP,
				Compress: CompressionLZONo,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client,comp-lzo",
		},
		{
			name: "proto udp6",
			fields: fields{
				Cipher: "AES-128-GCM",
				Auth:   "sha512",
				Proto:  ProtoUDP6,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client",
		},
		{
			// CompressionUndef (empty string) should NOT output any compression string
			name: "compression undef outputs nothing",
			fields: fields{
				Cipher:   "AES-128-GCM",
				Auth:     "sha512",
				Proto:    ProtoUDP,
				Compress: CompressionUndef,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OpenVPNOptions{
				Remote:     tt.fields.Remote,
				Port:       tt.fields.Port,
				Proto:      tt.fields.Proto,
				Username:   tt.fields.Username,
				Password:   tt.fields.Password,
				Compress:   tt.fields.Compress,
				Cipher:     tt.fields.Cipher,
				Auth:       tt.fields.Auth,
				TLSMaxVer:  tt.fields.TLSMaxVer,
				ProxyOBFS4: tt.fields.ProxyOBFS4,
			}
			if got := o.ServerOptionsString(); got != tt.want {
				t.Errorf("Options.string() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetOptionsFromLines(t *testing.T) {
	t.Run("valid options return a valid option object", func(t *testing.T) {
		d := t.TempDir()
		l := []string{
			"remote 0.0.0.0 1194",
			"proto udp4",
			"cipher AES-256-GCM",
			"auth SHA512",
			"<ca>",
			"ca_string",
			"</ca>",
			"<cert>",
			"cert_string",
			"</cert>",
			"<key>",
			"key_string",
			"</key>",
			"<tls-auth>",
			"ta_string",
			"</tls-auth>",
		}
		opt, err := getOptionsFromLines(l, d)
		if err != nil {
			t.Errorf("Good options should not fail: %s", err)
		}
		if opt.Cipher != "AES-256-GCM" {
			t.Errorf("Cipher not what expected")
		}
		if opt.Auth != "SHA512" {
			t.Errorf("Auth not what expected")
		}
		if opt.Compress != CompressionUndef {
			t.Errorf("Expected compression undef (no compression configured)")
		}
	})
}

func TestGetOptionsFromLinesKeyDirection(t *testing.T) {
	t.Run("key-direction is parsed", func(t *testing.T) {
		l := []string{
			"key-direction 1",
		}
		o, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("Good options should not fail: %s", err)
		}
		if o.KeyDirection == nil || *o.KeyDirection != 1 {
			t.Fatalf("Expected KeyDirection=1, got: %v", o.KeyDirection)
		}
	})

	t.Run("tls-auth inline direction sets key-direction", func(t *testing.T) {
		l := []string{
			"tls-auth inline 0",
			"<tls-auth>",
			"ta_string",
			"</tls-auth>",
		}
		o, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("Good options should not fail: %s", err)
		}
		if o.KeyDirection == nil || *o.KeyDirection != 0 {
			t.Fatalf("Expected KeyDirection=0, got: %v", o.KeyDirection)
		}
	})

	t.Run("conflicting key-direction values fail", func(t *testing.T) {
		l := []string{
			"key-direction 0",
			"tls-auth inline 1",
		}
		if _, err := getOptionsFromLines(l, t.TempDir()); err == nil {
			t.Fatalf("Expected conflicting key-direction to fail")
		}
	})
}

func TestGetOptionsFromLinesInlineCerts(t *testing.T) {
	t.Run("inline credentials are correctlyparsed", func(t *testing.T) {
		l := []string{
			"<ca>",
			"ca_string",
			"</ca>",
			"<cert>",
			"cert_string",
			"</cert>",
			"<key>",
			"key_string",
			"</key>",
			"<tls-auth>",
			"ta_string",
			"</tls-auth>",
		}
		o, err := getOptionsFromLines(l, "")
		if err != nil {
			t.Errorf("Good options should not fail: %s", err)
		}
		if string(o.CA) != "ca_string\n" {
			t.Errorf("Expected ca_string, got: %s.", string(o.CA))
		}
		if string(o.Cert) != "cert_string\n" {
			t.Errorf("Expected cert_string, got: %s.", string(o.Cert))
		}
		if string(o.Key) != "key_string\n" {
			t.Errorf("Expected key_string, got: %s.", string(o.Key))
		}
		if string(o.TLSAuth) != "ta_string\n" {
			t.Errorf("Expected ta_string, got: %s.", string(o.Key))
		}
	})
}

func TestGetOptionsFromLinesInlineAuthUserPass(t *testing.T) {
	t.Run("inline auth-user-pass block is parsed", func(t *testing.T) {
		l := []string{
			"<ca>",
			"ca_string",
			"</ca>",
			"<auth-user-pass>",
			"user",
			"pass",
			"</auth-user-pass>",
		}
		o, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("Good options should not fail: %s", err)
		}
		if o.Username != "user" || o.Password != "pass" {
			t.Fatalf("Expected inline username/password to be parsed, got user=%q pass=%q", o.Username, o.Password)
		}
		if !o.AuthUserPass {
			t.Fatalf("Expected AuthUserPass to be true")
		}
	})

	t.Run("auth-user-pass file paths are rejected", func(t *testing.T) {
		l := []string{
			"auth-user-pass auth.txt",
		}
		if _, err := getOptionsFromLines(l, t.TempDir()); err == nil {
			t.Fatalf("Expected auth-user-pass file paths to be rejected")
		}
	})
}

func TestGetOptionsFromLinesRejectsFilePathDirectives(t *testing.T) {
	basedir := t.TempDir()
	tests := []struct {
		name  string
		lines []string
	}{
		{
			name:  "ca file path",
			lines: []string{"ca ca.crt"},
		},
		{
			name:  "cert file path",
			lines: []string{"cert client.crt"},
		},
		{
			name:  "key file path",
			lines: []string{"key client.key"},
		},
		{
			name:  "tls-auth file path",
			lines: []string{"tls-auth ta.key"},
		},
		{
			name:  "tls-auth file path with direction",
			lines: []string{"tls-auth ta.key 1"},
		},
		{
			name:  "tls-crypt file path",
			lines: []string{"tls-crypt tc.key"},
		},
		{
			name:  "tls-crypt-v2 file path",
			lines: []string{"tls-crypt-v2 tc2.key"},
		},
		{
			name:  "auth-user-pass file path",
			lines: []string{"auth-user-pass auth.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := getOptionsFromLines(tt.lines, basedir); err == nil {
				t.Fatalf("Expected file path directive to be rejected: %q", tt.lines[0])
			}
		})
	}
}

func TestAuthUserPassCredentialsCanBeInjectedByCaller(t *testing.T) {
	l := []string{
		"<ca>",
		"ca_string",
		"</ca>",
		"auth-user-pass",
	}
	o, err := getOptionsFromLines(l, t.TempDir())
	if err != nil {
		t.Fatalf("Good options should not fail: %s", err)
	}
	if !o.AuthUserPass {
		t.Fatalf("Expected AuthUserPass to be true")
	}
	if o.Username != "" || o.Password != "" {
		t.Fatalf("Expected username/password to be empty before caller injection, got user=%q pass=%q", o.Username, o.Password)
	}

	o.Username = "user"
	o.Password = "pass"
	if !o.HasAuthInfo() {
		t.Fatalf("Expected HasAuthInfo() to be true after caller injection")
	}
}

func TestGetOptionsFromLinesNoFiles(t *testing.T) {
	t.Run("getting certificatee should fail if no file passed", func(t *testing.T) {
		l := []string{"ca ca.crt"}
		if _, err := getOptionsFromLines(l, t.TempDir()); err == nil {
			t.Errorf("Should fail if no files provided")
		}
	})
}

func TestGetOptionsNoCompression(t *testing.T) {
	t.Run("compress (no args) is parsed as stub per OpenVPN 2.5", func(t *testing.T) {
		// OpenVPN 2.5: "compress" with no argument = COMP_ALG_STUB + COMP_F_SWAP
		// See options.c:7916-7920
		l := []string{"compress"}
		o, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("Should not fail: compress")
		}
		if o.Compress != CompressionStub {
			t.Errorf("Expected compress==stub (OpenVPN 2.5 semantics), got %q", o.Compress)
		}
	})
}

func TestGetOptionsCompressionStub(t *testing.T) {
	t.Run("compress stub is parsed as stub", func(t *testing.T) {
		l := []string{"compress stub"}
		o, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("Should not fail: compress stub")
		}
		if o.Compress != "stub" {
			t.Errorf("expected compress==stub")
		}
	})
}

func TestGetOptionsCompressionBad(t *testing.T) {
	t.Run("an unknown compression options should fail", func(t *testing.T) {
		l := []string{"compress foo"}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Errorf("Unknown compress: should fail")
		}
	})
}

func TestGetOptionsCompressLZO(t *testing.T) {
	t.Run("comp-lzo no is parsed as lzo-no", func(t *testing.T) {
		l := []string{"comp-lzo no"}
		o, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("Should not fail: lzo-comp no")
		}
		if o.Compress != "lzo-no" {
			t.Errorf("expected compress=lzo-no")
		}
	})
}

func TestGetOptionsBadRemote(t *testing.T) {
	t.Run("empty remote should fail", func(t *testing.T) {
		l := []string{"remote"}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Errorf("Should fail: malformed remote")
		}
	})
}

func TestGetOptionsBadCipher(t *testing.T) {
	t.Run("empty cipher should fail", func(t *testing.T) {
		l := []string{"cipher"}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Errorf("Should fail: malformed cipher")
		}
	})

	t.Run("incorrect cipher should fail", func(t *testing.T) {
		l := []string{
			"cipher AES-111-CBC",
		}
		if _, err := getOptionsFromLines(l, t.TempDir()); err == nil {
			t.Errorf("Should fail: bad cipher")
		}
	})
}

func TestGetOptionsComment(t *testing.T) {
	t.Run("a commented line is correctly parsed", func(t *testing.T) {
		l := []string{
			"cipher AES-256-GCM",
			"#cipher AES-128-GCM",
		}
		o, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("Should not fail: commented line")
		}
		if o.Cipher != "AES-256-GCM" {
			t.Errorf("Expected cipher: AES-256-GCM")
		}
	})
}

var dummyConfigFile = []byte(`proto udp
cipher AES-128-GCM
auth SHA1`)

func Test_ReadConfigFromBytes(t *testing.T) {
	t.Run("a valid config should be correctly parsed", func(t *testing.T) {
		o, err := ReadConfigFromBytes(dummyConfigFile)
		if err != nil {
			t.Errorf("ReadConfigFromBytes(): expected err=%v, got=%v", nil, err)
		}
		wantProto := ProtoUDP
		if o.Proto != wantProto {
			t.Errorf("ReadConfigFromBytes(): expected Proto=%v, got=%v", wantProto, o.Proto)
		}
		wantCipher := "AES-128-GCM"
		if o.Cipher != wantCipher {
			t.Errorf("ReadConfigFromBytes(): expected=%v, got=%v", wantCipher, o.Cipher)
		}
	})

	t.Run("ReadConfigFile is disabled and should return ErrBadConfig", func(t *testing.T) {
		if _, err := ReadConfigFile("config.ovpn"); !errors.Is(err, ErrBadConfig) {
			t.Errorf("ReadConfigFile(): want ErrBadConfig, got=%v", err)
		}
	})
}

func Test_parseProto(t *testing.T) {
	t.Run("fail with empty array of strings", func(t *testing.T) {
		_, err := parseProto([]string{}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseProto(): wantErr: %v, got %v", wantErr, err)
		}
	})

	t.Run("two parts should fail", func(t *testing.T) {
		_, err := parseProto([]string{"foo", "bar"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseProto(): wantErr %v, got %v", wantErr, err)
		}
	})

	t.Run("proto udp is parsed as udp", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseProto([]string{"udp"}, opt)
		if !errors.Is(err, nil) {
			t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
		}
		if o.Proto != ProtoUDP {
			t.Errorf("parseProto(): wantErr %v, got %v", nil, err)
		}
	})

	t.Run("proto udp4 is parsed as udp4", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseProto([]string{"udp4"}, opt)
		if !errors.Is(err, nil) {
			t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
		}
		if o.Proto != ProtoUDP4 {
			t.Errorf("parseProto(): want %v, got %v", ProtoUDP4, o.Proto)
		}
	})

	t.Run("proto udp6 is parsed as udp6", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseProto([]string{"udp6"}, opt)
		if !errors.Is(err, nil) {
			t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
		}
		if o.Proto != ProtoUDP6 {
			t.Errorf("parseProto(): want %v, got %v", ProtoUDP6, o.Proto)
		}
	})

	t.Run("proto tcp is parsed as tcp", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseProto([]string{"tcp"}, opt)
		if !errors.Is(err, nil) {
			t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
		}
		if o.Proto != ProtoTCP {
			t.Errorf("parseProto(): wantErr %v, got %v", nil, err)
		}
	})

	t.Run("proto tcp-client is parsed as tcp", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseProto([]string{"tcp-client"}, opt)
		if !errors.Is(err, nil) {
			t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
		}
		if o.Proto != ProtoTCP {
			t.Errorf("parseProto(): want %v, got %v", ProtoTCP, o.Proto)
		}
	})

	t.Run("proto tcp4-client is parsed as tcp4", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseProto([]string{"tcp4-client"}, opt)
		if !errors.Is(err, nil) {
			t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
		}
		if o.Proto != ProtoTCP4 {
			t.Errorf("parseProto(): want %v, got %v", ProtoTCP4, o.Proto)
		}
	})

	t.Run("proto tcp6-client is parsed as tcp6", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseProto([]string{"tcp6-client"}, opt)
		if !errors.Is(err, nil) {
			t.Errorf("parseProto(): wantErr: %v, got %v", nil, err)
		}
		if o.Proto != ProtoTCP6 {
			t.Errorf("parseProto(): want %v, got %v", ProtoTCP6, o.Proto)
		}
	})

	t.Run("proto tcp-server should fail", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseProto([]string{"tcp-server"}, opt)
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseProto(): wantErr: %v, got %v", wantErr, err)
		}
	})

	t.Run("unknown proto fails", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseProto([]string{"kcp"}, opt)
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseProto(): wantErr: %v, got %v", ErrBadConfig, err)
		}
	})
}

func Test_parseProxyOBFS4(t *testing.T) {
	t.Run("with empty parts", func(t *testing.T) {
		_, err := parseProxyOBFS4([]string{}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseProxyOBFS4(): wantErr: %v, got %v", wantErr, err)
		}
	})

	t.Run("with an obfs4 string", func(t *testing.T) {
		// TODO(ainghazal): this test must change when the function starts validating the obfs4 url
		opt := &OpenVPNOptions{}
		obfs4Uri := "obfs4://foobar"
		o, err := parseProxyOBFS4([]string{obfs4Uri}, opt)
		var wantErr error
		if !errors.Is(err, wantErr) {
			t.Errorf("parseProxyOBFS4(): wantErr: %v, got %v", wantErr, err)
		}
		if o.ProxyOBFS4 != obfs4Uri {
			t.Errorf("parseProxyOBFS4(): want %v, got %v", obfs4Uri, opt.ProxyOBFS4)
		}
	})
}

func Test_parseCA(t *testing.T) {
	t.Run("more than one part should fail", func(t *testing.T) {
		_, err := parseCA([]string{"one", "two"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseCA(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("empty part should fail", func(t *testing.T) {
		_, err := parseCA([]string{}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseCA(): want %v, got %v", wantErr, err)
		}
	})
}

func Test_parseCert(t *testing.T) {
	t.Run("more than one part should fail", func(t *testing.T) {
		_, err := parseCert([]string{"one", "two"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseCert(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("empty parts should fail", func(t *testing.T) {
		_, err := parseCert([]string{}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseCert(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("non-existent cert should fail", func(t *testing.T) {
		_, err := parseCert([]string{"/tmp/nonexistent"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseCert(): want %v, got %v", wantErr, err)
		}
	})
}

func Test_parseKey(t *testing.T) {
	t.Run("more than one part should fail", func(t *testing.T) {
		_, err := parseKey([]string{"one", "two"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseKey(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("empty parts should fail", func(t *testing.T) {
		_, err := parseKey([]string{}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseKey(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("non-existent key file path should fail", func(t *testing.T) {
		_, err := parseKey([]string{"/tmp/nonexistent"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseKey(): want %v, got %v", wantErr, err)
		}
	})
}

func Test_parseTLSAuth(t *testing.T) {
	t.Run("empty args should fail", func(t *testing.T) {
		_, err := parseTLSAuth([]string{}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseTLSAuth(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("file paths should fail", func(t *testing.T) {
		_, err := parseTLSAuth([]string{"ta.key"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseTLSAuth(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("inline should succeed", func(t *testing.T) {
		_, err := parseTLSAuth([]string{"inline"}, &OpenVPNOptions{}, "")
		if err != nil {
			t.Errorf("parseTLSAuth(): want %v, got %v", nil, err)
		}
	})

	t.Run("inline with direction should set key-direction", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseTLSAuth([]string{"inline", "1"}, opt, "")
		if err != nil {
			t.Errorf("parseTLSAuth(): want %v, got %v", nil, err)
		}
		if opt.KeyDirection == nil || *opt.KeyDirection != 1 {
			t.Errorf("parseTLSAuth(): expected KeyDirection=1, got %v", opt.KeyDirection)
		}
	})

	t.Run("invalid direction should fail", func(t *testing.T) {
		_, err := parseTLSAuth([]string{"inline", "2"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseTLSAuth(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("more than two parts should fail", func(t *testing.T) {
		_, err := parseTLSAuth([]string{"inline", "0", "extra"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseTLSAuth(): want %v, got %v", wantErr, err)
		}
	})
}

func Test_parseCompress(t *testing.T) {
	t.Run("more than one part should fail", func(t *testing.T) {
		_, err := parseCompress([]string{"one", "two"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseCompress(): want %v, got %v", wantErr, err)
		}
	})
}

func Test_parseCompLZO(t *testing.T) {
	t.Run("any other string than 'no' should fail", func(t *testing.T) {
		_, err := parseCompLZO([]string{"yes"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseCompLZO(): want %v, got %v", wantErr, err)
		}
	})
}

func Test_parseOption(t *testing.T) {
	t.Run("unknown key is fatal by default", func(t *testing.T) {
		_, err := parseOption(&OpenVPNOptions{}, t.TempDir(), "unknownKey", []string{"a", "b"}, 0)
		if !errors.Is(err, ErrBadConfig) {
			t.Errorf("parseOption(): want %v, got %v", ErrBadConfig, err)
		}
	})
}

func Test_parseAuth(t *testing.T) {
	type args struct {
		p []string
		o *OpenVPNOptions
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name:    "should fail with empty array",
			args:    args{[]string{}, &OpenVPNOptions{}},
			wantErr: ErrBadConfig,
		},
		{
			name:    "should fail with 2-element array",
			args:    args{[]string{"foo", "bar"}, &OpenVPNOptions{}},
			wantErr: ErrBadConfig,
		},
		{
			name:    "should fail with lowercase option",
			args:    args{[]string{"sha1"}, &OpenVPNOptions{}},
			wantErr: ErrBadConfig,
		},
		{
			name:    "should fail with unknown option",
			args:    args{[]string{"SHA666"}, &OpenVPNOptions{}},
			wantErr: ErrBadConfig,
		},
		{
			name:    "should not fail with good option",
			args:    args{[]string{"SHA512"}, &OpenVPNOptions{}},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseAuth(tt.args.p, tt.args.o); !errors.Is(err, tt.wantErr) {
				t.Errorf("parseAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseAuthUser(t *testing.T) {
	t.Run("no args should succeed and mark AuthUserPass", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		if _, err := parseAuthUser([]string{}, opt, ""); err != nil {
			t.Fatalf("parseAuthUser(): want %v, got %v", nil, err)
		}
		if !opt.AuthUserPass {
			t.Fatalf("parseAuthUser(): expected AuthUserPass to be true")
		}
	})

	t.Run("file paths should be rejected", func(t *testing.T) {
		_, err := parseAuthUser([]string{"auth.txt"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Fatalf("parseAuthUser(): wantErr %v, got %v", wantErr, err)
		}
	})

	t.Run("multiple args should be rejected", func(t *testing.T) {
		_, err := parseAuthUser([]string{"a", "b"}, &OpenVPNOptions{}, "")
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Fatalf("parseAuthUser(): wantErr %v, got %v", wantErr, err)
		}
	})
}

func Test_parseTLSVerMax(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr error
		wantVer string
	}{
		{
			name:    "no args should fail",
			args:    []string{},
			wantErr: ErrBadConfig,
		},
		{
			name:    "1.2 sets TLSMaxVer",
			args:    []string{"1.2"},
			wantErr: nil,
			wantVer: "1.2",
		},
		{
			name:    "1.3 sets TLSMaxVer",
			args:    []string{"1.3"},
			wantErr: nil,
			wantVer: "1.3",
		},
		{
			name:    "too many args should fail",
			args:    []string{"1.2", "1.3"},
			wantErr: ErrBadConfig,
		},
		{
			name:    "unknown version should fail",
			args:    []string{"1.4"},
			wantErr: ErrBadConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := &OpenVPNOptions{}
			if _, err := parseTLSVerMax(tt.args, opt); !errors.Is(err, tt.wantErr) {
				t.Fatalf("parseTLSVerMax() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && opt.TLSMaxVer != tt.wantVer {
				t.Fatalf("TLSMaxVer = %q, want %q", opt.TLSMaxVer, tt.wantVer)
			}
		})
	}
}

func TestOpenVPNOptions_HasAuthInfo(t *testing.T) {
	t.Run("username and password without ca should return false", func(t *testing.T) {
		opt := OpenVPNOptions{Username: "user", Password: "password"}
		if opt.HasAuthInfo() {
			t.Error("expected false")
		}
	})
	t.Run("username and password with ca should return true", func(t *testing.T) {
		opt := OpenVPNOptions{CA: []byte("ca"), Username: "user", Password: "password"}
		if !opt.HasAuthInfo() {
			t.Error("expected true")
		}
	})
	t.Run("non-empty ca, cert and key should return true", func(t *testing.T) {
		opt := OpenVPNOptions{CA: []byte("ca"), Cert: []byte("cert"), Key: []byte("key")}
		if !opt.HasAuthInfo() {
			t.Error("expected true")
		}
	})
	t.Run("auth-user-pass requires username and password even with cert and key", func(t *testing.T) {
		opt := OpenVPNOptions{CA: []byte("ca"), Cert: []byte("cert"), Key: []byte("key"), AuthUserPass: true}
		if opt.HasAuthInfo() {
			t.Error("expected false")
		}
	})
	t.Run("auth-user-pass with username, password and ca should return true", func(t *testing.T) {
		opt := OpenVPNOptions{CA: []byte("ca"), Username: "user", Password: "password", AuthUserPass: true}
		if !opt.HasAuthInfo() {
			t.Error("expected true")
		}
	})
	t.Run("ca only should return false", func(t *testing.T) {
		opt := OpenVPNOptions{CA: []byte("ca")}
		if opt.HasAuthInfo() {
			t.Error("expected false")
		}
	})
	t.Run("empty values should return false", func(t *testing.T) {
		opt := OpenVPNOptions{}
		if opt.HasAuthInfo() {
			t.Error("expected false")
		}
	})
}

func Test_parseRenegSec(t *testing.T) {
	t.Run("empty args should fail", func(t *testing.T) {
		_, err := parseRenegSec([]string{}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseRenegSec(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("too many args should fail", func(t *testing.T) {
		_, err := parseRenegSec([]string{"3600", "2700", "extra"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseRenegSec(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("negative value should fail", func(t *testing.T) {
		_, err := parseRenegSec([]string{"-1"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseRenegSec(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("non-numeric value should fail", func(t *testing.T) {
		_, err := parseRenegSec([]string{"abc"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseRenegSec(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("valid value should succeed", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseRenegSec([]string{"3600"}, opt)
		if err != nil {
			t.Errorf("parseRenegSec(): want %v, got %v", nil, err)
		}
		if o.RenegotiateSeconds != 3600 {
			t.Errorf("parseRenegSec(): expected RenegotiateSeconds=3600, got %d", o.RenegotiateSeconds)
		}
	})

	t.Run("zero value should succeed (disables renegotiation)", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseRenegSec([]string{"0"}, opt)
		if err != nil {
			t.Errorf("parseRenegSec(): want %v, got %v", nil, err)
		}
		if o.RenegotiateSeconds != 0 {
			t.Errorf("parseRenegSec(): expected RenegotiateSeconds=0, got %d", o.RenegotiateSeconds)
		}
	})

	t.Run("two values should succeed (min is ignored)", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseRenegSec([]string{"3600", "2700"}, opt)
		if err != nil {
			t.Errorf("parseRenegSec(): want %v, got %v", nil, err)
		}
		if o.RenegotiateSeconds != 3600 {
			t.Errorf("parseRenegSec(): expected RenegotiateSeconds=3600, got %d", o.RenegotiateSeconds)
		}
	})
}

func Test_parseRenegBytes(t *testing.T) {
	t.Run("empty args should fail", func(t *testing.T) {
		_, err := parseRenegBytes([]string{}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseRenegBytes(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("too many args should fail", func(t *testing.T) {
		_, err := parseRenegBytes([]string{"1000000", "extra"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseRenegBytes(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("negative value should fail", func(t *testing.T) {
		_, err := parseRenegBytes([]string{"-100"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseRenegBytes(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("non-numeric value should fail", func(t *testing.T) {
		_, err := parseRenegBytes([]string{"abc"}, &OpenVPNOptions{})
		wantErr := ErrBadConfig
		if !errors.Is(err, wantErr) {
			t.Errorf("parseRenegBytes(): want %v, got %v", wantErr, err)
		}
	})

	t.Run("valid value should succeed", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseRenegBytes([]string{"67108864"}, opt)
		if err != nil {
			t.Errorf("parseRenegBytes(): want %v, got %v", nil, err)
		}
		if o.RenegotiateBytes != 67108864 {
			t.Errorf("parseRenegBytes(): expected RenegotiateBytes=67108864, got %d", o.RenegotiateBytes)
		}
	})

	t.Run("zero value should succeed (disables renegotiation)", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		o, err := parseRenegBytes([]string{"0"}, opt)
		if err != nil {
			t.Errorf("parseRenegBytes(): want %v, got %v", nil, err)
		}
		if o.RenegotiateBytes != 0 {
			t.Errorf("parseRenegBytes(): expected RenegotiateBytes=0, got %d", o.RenegotiateBytes)
		}
	})
}

func TestRenegotiationDefaults(t *testing.T) {
	t.Run("default renegotiation values are set correctly", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.RenegotiateSeconds != DefaultRenegotiateSeconds {
			t.Errorf("expected default RenegotiateSeconds=%d, got %d", DefaultRenegotiateSeconds, opt.RenegotiateSeconds)
		}
		if opt.RenegotiateBytes != DefaultRenegotiateBytes {
			t.Errorf("expected default RenegotiateBytes=%d, got %d", DefaultRenegotiateBytes, opt.RenegotiateBytes)
		}
	})

	t.Run("reneg-sec is parsed from config", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"reneg-sec 7200",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.RenegotiateSeconds != 7200 {
			t.Errorf("expected RenegotiateSeconds=7200, got %d", opt.RenegotiateSeconds)
		}
	})

	t.Run("reneg-bytes is parsed from config", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"reneg-bytes 67108864",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.RenegotiateBytes != 67108864 {
			t.Errorf("expected RenegotiateBytes=67108864, got %d", opt.RenegotiateBytes)
		}
	})

	t.Run("reneg-sec 0 disables time-based renegotiation", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"reneg-sec 0",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.RenegotiateSeconds != 0 {
			t.Errorf("expected RenegotiateSeconds=0, got %d", opt.RenegotiateSeconds)
		}
	})
}

func TestPingDefaults(t *testing.T) {
	t.Run("ping options default to 0 (disabled)", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.Ping != 0 {
			t.Errorf("expected Ping=0, got %d", opt.Ping)
		}
		if opt.PingRestart != 0 {
			t.Errorf("expected PingRestart=0, got %d", opt.PingRestart)
		}
		if opt.PingExit != 0 {
			t.Errorf("expected PingExit=0, got %d", opt.PingExit)
		}
	})

	t.Run("ping is parsed from config", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"ping 15",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.Ping != 15 {
			t.Errorf("expected Ping=15, got %d", opt.Ping)
		}
	})

	t.Run("ping-restart is parsed from config", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"ping-restart 60",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.PingRestart != 60 {
			t.Errorf("expected PingRestart=60, got %d", opt.PingRestart)
		}
	})

	t.Run("ping-exit is parsed from config", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"ping-exit 120",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.PingExit != 120 {
			t.Errorf("expected PingExit=120, got %d", opt.PingExit)
		}
	})

	t.Run("keepalive sets ping and ping-restart", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"keepalive 10 60",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("getOptionsFromLines: %v", err)
		}
		if opt.Ping != 10 {
			t.Errorf("expected Ping=10, got %d", opt.Ping)
		}
		if opt.PingRestart != 60 {
			t.Errorf("expected PingRestart=60, got %d", opt.PingRestart)
		}
	})

	t.Run("invalid ping value returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"ping abc",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for invalid ping value")
		}
	})

	t.Run("negative ping value returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"ping -1",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for negative ping value")
		}
	})

	t.Run("keepalive with wrong arg count returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"keepalive 10",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for keepalive with one arg")
		}
	})
}

func TestTransitionWindowDefaults(t *testing.T) {
	t.Run("transition-window defaults to 3600 seconds", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.TransitionWindow != DefaultTransitionWindow {
			t.Errorf("expected default TransitionWindow=%d, got %d", DefaultTransitionWindow, opt.TransitionWindow)
		}
	})

	t.Run("transition-window is parsed from config", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"transition-window 120",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.TransitionWindow != 120 {
			t.Errorf("expected TransitionWindow=120, got %d", opt.TransitionWindow)
		}
	})
}

func TestServerOptionsString_DefaultsWhenCipherNotSet(t *testing.T) {
	l := []string{
		"remote 0.0.0.0 1194",
		"<ca>",
		"ca_string",
		"</ca>",
	}
	opt, err := getOptionsFromLines(l, t.TempDir())
	if err != nil {
		t.Fatalf("getOptionsFromLines: %v", err)
	}
	if opt.Auth != "SHA1" {
		t.Fatalf("expected default Auth=SHA1, got %q", opt.Auth)
	}
	if opt.Cipher != "" {
		t.Fatalf("expected default Cipher to be empty (negotiated via PUSH_REPLY), got %q", opt.Cipher)
	}

	s := opt.ServerOptionsString()
	if s == "" {
		t.Fatalf("expected non-empty ServerOptionsString when cipher is unset")
	}
	if strings.Contains(s, ",cipher ") {
		t.Fatalf("expected ServerOptionsString to omit cipher when Cipher is unset: %q", s)
	}
	if !strings.Contains(s, ",auth SHA1,") {
		t.Fatalf("expected ServerOptionsString to include default auth SHA1: %q", s)
	}
	if !strings.Contains(s, ",keysize 128,") {
		t.Fatalf("expected ServerOptionsString to use legacy keysize 128 when cipher is unset: %q", s)
	}
}

func TestHandshakeWindowDefaults(t *testing.T) {
	t.Run("hand-window defaults to 60 seconds", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.HandshakeWindow != DefaultHandshakeWindow {
			t.Errorf("expected default HandshakeWindow=%d, got %d", DefaultHandshakeWindow, opt.HandshakeWindow)
		}
	})

	t.Run("hand-window is parsed from config", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"hand-window 120",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.HandshakeWindow != 120 {
			t.Errorf("expected HandshakeWindow=120, got %d", opt.HandshakeWindow)
		}
	})

	t.Run("hand-window 0 is valid", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"hand-window 0",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.HandshakeWindow != 0 {
			t.Errorf("expected HandshakeWindow=0, got %d", opt.HandshakeWindow)
		}
	})

	t.Run("invalid hand-window value returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"hand-window abc",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for invalid hand-window value")
		}
	})

	t.Run("negative hand-window value returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"hand-window -1",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for negative hand-window value")
		}
	})

	t.Run("hand-window missing arg returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"hand-window",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for hand-window with no arg")
		}
	})
}

func TestVerifyX509NameParsing(t *testing.T) {
	t.Run("verify-x509-name with name only (default type=subject)", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"verify-x509-name Server-1",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.VerifyX509Name != "Server-1" {
			t.Errorf("expected VerifyX509Name=Server-1, got %q", opt.VerifyX509Name)
		}
		if opt.VerifyX509Type != VerifyX509SubjectDN {
			t.Errorf("expected VerifyX509Type=VerifyX509SubjectDN, got %d", opt.VerifyX509Type)
		}
	})

	t.Run("verify-x509-name with subject type", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"verify-x509-name C=KG,ST=NA,CN=Server subject",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.VerifyX509Name != "C=KG,ST=NA,CN=Server" {
			t.Errorf("expected VerifyX509Name=C=KG,ST=NA,CN=Server, got %q", opt.VerifyX509Name)
		}
		if opt.VerifyX509Type != VerifyX509SubjectDN {
			t.Errorf("expected VerifyX509Type=VerifyX509SubjectDN, got %d", opt.VerifyX509Type)
		}
	})

	t.Run("verify-x509-name with name type (CN match)", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"verify-x509-name MyServer name",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.VerifyX509Name != "MyServer" {
			t.Errorf("expected VerifyX509Name=MyServer, got %q", opt.VerifyX509Name)
		}
		if opt.VerifyX509Type != VerifyX509SubjectRDN {
			t.Errorf("expected VerifyX509Type=VerifyX509SubjectRDN, got %d", opt.VerifyX509Type)
		}
	})

	t.Run("verify-x509-name with name-prefix type", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"verify-x509-name Server- name-prefix",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.VerifyX509Name != "Server-" {
			t.Errorf("expected VerifyX509Name=Server-, got %q", opt.VerifyX509Name)
		}
		if opt.VerifyX509Type != VerifyX509SubjectRDNPrefix {
			t.Errorf("expected VerifyX509Type=VerifyX509SubjectRDNPrefix, got %d", opt.VerifyX509Type)
		}
	})

	t.Run("verify-x509-name type is case-insensitive", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"verify-x509-name Server NAME",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.VerifyX509Type != VerifyX509SubjectRDN {
			t.Errorf("expected VerifyX509Type=VerifyX509SubjectRDN, got %d", opt.VerifyX509Type)
		}
	})

	t.Run("verify-x509-name with unknown type returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"verify-x509-name Server unknown-type",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for unknown verify-x509-name type")
		}
	})

	t.Run("verify-x509-name with empty name returns error", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseVerifyX509Name([]string{""}, opt)
		if err == nil {
			t.Error("expected error for empty name")
		}
	})

	t.Run("verify-x509-name with no args returns error", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseVerifyX509Name([]string{}, opt)
		if err == nil {
			t.Error("expected error for no args")
		}
	})

	t.Run("verify-x509-name with too many args returns error", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseVerifyX509Name([]string{"name", "type", "extra"}, opt)
		if err == nil {
			t.Error("expected error for too many args")
		}
	})

	t.Run("default verify-x509-name is empty (no verification)", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.VerifyX509Name != "" {
			t.Errorf("expected empty VerifyX509Name, got %q", opt.VerifyX509Name)
		}
		if opt.VerifyX509Type != VerifyX509None {
			t.Errorf("expected VerifyX509Type=VerifyX509None, got %d", opt.VerifyX509Type)
		}
	})
}

func TestRemoteCertKUParsing(t *testing.T) {
	t.Run("remote-cert-ku with single hex value", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-ku 80",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 1 {
			t.Fatalf("expected 1 RemoteCertKU, got %d", len(opt.RemoteCertKU))
		}
		// OpenVPN 0x80 (digitalSignature) is converted to Go format 0x01
		if opt.RemoteCertKU[0] != KeyUsageDigitalSignature {
			t.Errorf("expected RemoteCertKU[0]=0x%x (digitalSignature), got 0x%x", KeyUsageDigitalSignature, opt.RemoteCertKU[0])
		}
	})

	t.Run("remote-cert-ku with multiple hex values", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-ku 80 a0 88",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 3 {
			t.Fatalf("expected 3 RemoteCertKU values, got %d", len(opt.RemoteCertKU))
		}
		// OpenVPN format -> Go format:
		// 0x80 -> 0x01 (digitalSignature)
		// 0xa0 -> 0x05 (digitalSignature | keyEncipherment)
		// 0x88 -> 0x11 (digitalSignature | keyAgreement)
		expected := []KeyUsage{
			KeyUsageDigitalSignature,                           // 0x80 -> 0x01
			KeyUsageDigitalSignature | KeyUsageKeyEncipherment, // 0xa0 -> 0x05
			KeyUsageDigitalSignature | KeyUsageKeyAgreement,    // 0x88 -> 0x11
		}
		for i, exp := range expected {
			if opt.RemoteCertKU[i] != exp {
				t.Errorf("expected RemoteCertKU[%d]=0x%x, got 0x%x", i, exp, opt.RemoteCertKU[i])
			}
		}
	})

	t.Run("remote-cert-ku with uppercase hex", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-ku A0 FF",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 2 {
			t.Fatalf("expected 2 RemoteCertKU values, got %d", len(opt.RemoteCertKU))
		}
		// OpenVPN 0xA0 -> Go 0x05 (digitalSignature | keyEncipherment)
		expectedA0 := KeyUsageDigitalSignature | KeyUsageKeyEncipherment
		if opt.RemoteCertKU[0] != expectedA0 {
			t.Errorf("expected RemoteCertKU[0]=0x%x, got 0x%x", expectedA0, opt.RemoteCertKU[0])
		}
		// OpenVPN 0xFF -> Go 0xFF (all 8 bits, symmetric after conversion)
		if opt.RemoteCertKU[1] != KeyUsage(0xFF) {
			t.Errorf("expected RemoteCertKU[1]=0xFF, got 0x%x", opt.RemoteCertKU[1])
		}
	})

	t.Run("remote-cert-ku with invalid hex returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-ku xyz",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for invalid hex in remote-cert-ku")
		}
	})

	t.Run("remote-cert-ku with no args requires KU extension", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-ku",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 1 {
			t.Fatalf("expected 1 RemoteCertKU value, got %d", len(opt.RemoteCertKU))
		}
		if opt.RemoteCertKU[0] != KeyUsageRequired {
			t.Errorf("expected RemoteCertKU[0]=0x%x (KeyUsageRequired), got 0x%x", KeyUsageRequired, opt.RemoteCertKU[0])
		}
	})

	t.Run("default remote-cert-ku is empty", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 0 {
			t.Errorf("expected empty RemoteCertKU, got %v", opt.RemoteCertKU)
		}
	})
}

func TestRemoteCertEKUParsing(t *testing.T) {
	t.Run("remote-cert-eku with OID", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-eku 1.3.6.1.5.5.7.3.1",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.RemoteCertEKU != "1.3.6.1.5.5.7.3.1" {
			t.Errorf("expected RemoteCertEKU=1.3.6.1.5.5.7.3.1, got %q", opt.RemoteCertEKU)
		}
	})

	t.Run("remote-cert-eku with name", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-eku serverAuth",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.RemoteCertEKU != "serverAuth" {
			t.Errorf("expected RemoteCertEKU=serverAuth, got %q", opt.RemoteCertEKU)
		}
	})

	t.Run("remote-cert-eku with no args returns error", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseRemoteCertEKU([]string{}, opt)
		if err == nil {
			t.Error("expected error for remote-cert-eku with no args")
		}
	})

	t.Run("remote-cert-eku with too many args returns error", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseRemoteCertEKU([]string{"oid1", "oid2"}, opt)
		if err == nil {
			t.Error("expected error for remote-cert-eku with too many args")
		}
	})

	t.Run("default remote-cert-eku is empty", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.RemoteCertEKU != "" {
			t.Errorf("expected empty RemoteCertEKU, got %q", opt.RemoteCertEKU)
		}
	})
}

func TestRemoteCertTLSParsing(t *testing.T) {
	t.Run("remote-cert-tls server sets EKU and requires KU", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-tls server",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 1 || opt.RemoteCertKU[0] != KeyUsageRequired {
			t.Errorf("expected RemoteCertKU=[0x%x], got %v", KeyUsageRequired, opt.RemoteCertKU)
		}
		if opt.RemoteCertEKU != "TLS Web Server Authentication" {
			t.Errorf("expected RemoteCertEKU=%q, got %q", "TLS Web Server Authentication", opt.RemoteCertEKU)
		}
	})

	t.Run("remote-cert-tls server then remote-cert-ku overrides KU but keeps EKU", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-tls server",
			"remote-cert-ku 80",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 1 || opt.RemoteCertKU[0] != KeyUsageDigitalSignature {
			t.Errorf("expected RemoteCertKU=[0x%x], got %v", KeyUsageDigitalSignature, opt.RemoteCertKU)
		}
		if opt.RemoteCertEKU != "TLS Web Server Authentication" {
			t.Errorf("expected RemoteCertEKU=%q, got %q", "TLS Web Server Authentication", opt.RemoteCertEKU)
		}
	})

	t.Run("remote-cert-ku then remote-cert-tls overrides KU to required", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-ku 80",
			"remote-cert-tls server",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 1 || opt.RemoteCertKU[0] != KeyUsageRequired {
			t.Errorf("expected RemoteCertKU=[0x%x], got %v", KeyUsageRequired, opt.RemoteCertKU)
		}
		if opt.RemoteCertEKU != "TLS Web Server Authentication" {
			t.Errorf("expected RemoteCertEKU=%q, got %q", "TLS Web Server Authentication", opt.RemoteCertEKU)
		}
	})

	t.Run("remote-cert-tls client sets EKU and requires KU", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-tls client",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 1 || opt.RemoteCertKU[0] != KeyUsageRequired {
			t.Errorf("expected RemoteCertKU=[0x%x], got %v", KeyUsageRequired, opt.RemoteCertKU)
		}
		if opt.RemoteCertEKU != "TLS Web Client Authentication" {
			t.Errorf("expected RemoteCertEKU=%q, got %q", "TLS Web Client Authentication", opt.RemoteCertEKU)
		}
	})

	t.Run("remote-cert-tls is case-insensitive", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-tls SERVER",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if len(opt.RemoteCertKU) != 1 || opt.RemoteCertKU[0] != KeyUsageRequired {
			t.Errorf("expected RemoteCertKU=[0x%x], got %v", KeyUsageRequired, opt.RemoteCertKU)
		}
		if opt.RemoteCertEKU != "TLS Web Server Authentication" {
			t.Errorf("expected RemoteCertEKU=%q, got %q", "TLS Web Server Authentication", opt.RemoteCertEKU)
		}
	})

	t.Run("remote-cert-tls with invalid type returns error", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-tls invalid",
		}
		_, err := getOptionsFromLines(l, t.TempDir())
		if err == nil {
			t.Error("expected error for invalid remote-cert-tls type")
		}
	})

	t.Run("remote-cert-tls with no args returns error", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseRemoteCertTLS([]string{}, opt)
		if err == nil {
			t.Error("expected error for remote-cert-tls with no args")
		}
	})

	t.Run("remote-cert-tls with too many args returns error", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseRemoteCertTLS([]string{"server", "extra"}, opt)
		if err == nil {
			t.Error("expected error for remote-cert-tls with too many args")
		}
	})
}

func TestOpenVPNKeyUsageToGo(t *testing.T) {
	// Test conversion from OpenVPN "high-bit" format to Go "low-bit" format
	// OpenVPN format: digitalSignature=0x80, nonRepudiation=0x40, keyEncipherment=0x20, etc.
	// Go format: digitalSignature=0x01, nonRepudiation=0x02, keyEncipherment=0x04, etc.

	tests := []struct {
		name     string
		ovpnKU   uint16
		expected KeyUsage
	}{
		{
			name:     "digitalSignature (OpenVPN 0x80 -> Go 0x01)",
			ovpnKU:   0x80,
			expected: KeyUsageDigitalSignature, // 0x01
		},
		{
			name:     "nonRepudiation (OpenVPN 0x40 -> Go 0x02)",
			ovpnKU:   0x40,
			expected: KeyUsageNonRepudiation, // 0x02
		},
		{
			name:     "keyEncipherment (OpenVPN 0x20 -> Go 0x04)",
			ovpnKU:   0x20,
			expected: KeyUsageKeyEncipherment, // 0x04
		},
		{
			name:     "dataEncipherment (OpenVPN 0x10 -> Go 0x08)",
			ovpnKU:   0x10,
			expected: KeyUsageDataEncipherment, // 0x08
		},
		{
			name:     "keyAgreement (OpenVPN 0x08 -> Go 0x10)",
			ovpnKU:   0x08,
			expected: KeyUsageKeyAgreement, // 0x10
		},
		{
			name:     "keyCertSign (OpenVPN 0x04 -> Go 0x20)",
			ovpnKU:   0x04,
			expected: KeyUsageKeyCertSign, // 0x20
		},
		{
			name:     "cRLSign (OpenVPN 0x02 -> Go 0x40)",
			ovpnKU:   0x02,
			expected: KeyUsageCRLSign, // 0x40
		},
		{
			name:     "encipherOnly (OpenVPN 0x01 -> Go 0x80)",
			ovpnKU:   0x01,
			expected: KeyUsageEncipherOnly, // 0x80
		},
		{
			name:     "combined: digitalSignature + keyEncipherment (OpenVPN 0xa0 -> Go 0x05)",
			ovpnKU:   0xa0,                                               // 0x80 | 0x20
			expected: KeyUsageDigitalSignature | KeyUsageKeyEncipherment, // 0x01 | 0x04 = 0x05
		},
		{
			name:     "combined: digitalSignature + keyAgreement (OpenVPN 0x88 -> Go 0x11)",
			ovpnKU:   0x88,                                            // 0x80 | 0x08
			expected: KeyUsageDigitalSignature | KeyUsageKeyAgreement, // 0x01 | 0x10 = 0x11
		},
		{
			name:     "zero value",
			ovpnKU:   0x00,
			expected: 0,
		},
		{
			name:     "all first 8 bits set (OpenVPN 0xff -> Go 0xff)",
			ovpnKU:   0xff,
			expected: 0xff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OpenVPNKeyUsageToGo(tt.ovpnKU)
			if got != tt.expected {
				t.Errorf("OpenVPNKeyUsageToGo(0x%02x) = 0x%02x, want 0x%02x", tt.ovpnKU, got, tt.expected)
			}
		})
	}
}

func TestParseRemoteCertKU_Conversion(t *testing.T) {
	// Test that parseRemoteCertKU correctly converts OpenVPN format to Go format

	t.Run("digitalSignature 0x80 converts to Go format", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseRemoteCertKU([]string{"80"}, opt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(opt.RemoteCertKU) != 1 {
			t.Fatalf("expected 1 KU value, got %d", len(opt.RemoteCertKU))
		}
		// OpenVPN 0x80 (digitalSignature) should become Go 0x01
		if opt.RemoteCertKU[0] != KeyUsageDigitalSignature {
			t.Errorf("expected KeyUsageDigitalSignature (0x%02x), got 0x%02x",
				KeyUsageDigitalSignature, opt.RemoteCertKU[0])
		}
	})

	t.Run("combined 0xa0 converts correctly", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseRemoteCertKU([]string{"a0"}, opt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// OpenVPN 0xa0 = digitalSignature(0x80) | keyEncipherment(0x20)
		// Go format = 0x01 | 0x04 = 0x05
		expected := KeyUsageDigitalSignature | KeyUsageKeyEncipherment
		if opt.RemoteCertKU[0] != expected {
			t.Errorf("expected 0x%02x, got 0x%02x", expected, opt.RemoteCertKU[0])
		}
	})

	t.Run("multiple values all convert correctly", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseRemoteCertKU([]string{"80", "a0", "88"}, opt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(opt.RemoteCertKU) != 3 {
			t.Fatalf("expected 3 KU values, got %d", len(opt.RemoteCertKU))
		}
		// 0x80 -> digitalSignature (0x01)
		if opt.RemoteCertKU[0] != KeyUsageDigitalSignature {
			t.Errorf("KU[0]: expected 0x%02x, got 0x%02x", KeyUsageDigitalSignature, opt.RemoteCertKU[0])
		}
		// 0xa0 -> digitalSignature | keyEncipherment (0x05)
		expected1 := KeyUsageDigitalSignature | KeyUsageKeyEncipherment
		if opt.RemoteCertKU[1] != expected1 {
			t.Errorf("KU[1]: expected 0x%02x, got 0x%02x", expected1, opt.RemoteCertKU[1])
		}
		// 0x88 -> digitalSignature | keyAgreement (0x11)
		expected2 := KeyUsageDigitalSignature | KeyUsageKeyAgreement
		if opt.RemoteCertKU[2] != expected2 {
			t.Errorf("KU[2]: expected 0x%02x, got 0x%02x", expected2, opt.RemoteCertKU[2])
		}
	})
}

// TestCompressionOpenVPN25Compliance tests that compression handling matches OpenVPN 2.5 behavior.
// Reference: options.c:3838-3841, options.c:7916-7920, compstub.c
func TestCompressionOpenVPN25Compliance(t *testing.T) {
	t.Run("default compression is undefined (COMP_ALG_UNDEF)", func(t *testing.T) {
		// OpenVPN 2.5: default comp.alg = COMP_ALG_UNDEF (0)
		// options_string only outputs ",comp-lzo" when alg != UNDEF
		l := []string{
			"remote 0.0.0.0 1194",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.Compress != CompressionUndef {
			t.Errorf("expected Compress=CompressionUndef, got %q", opt.Compress)
		}

		// OCC string should NOT contain any compression marker
		s := opt.ServerOptionsString()
		if strings.Contains(s, "comp") {
			t.Errorf("OCC string should not contain compression when undefined: %q", s)
		}
	})

	t.Run("compress (no args) equals COMP_ALG_STUB + COMP_F_SWAP", func(t *testing.T) {
		// OpenVPN 2.5 options.c:7916-7920:
		// "compress" with no argument sets COMP_ALG_STUB + COMP_F_SWAP
		l := []string{
			"remote 0.0.0.0 1194",
			"compress",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.Compress != CompressionStub {
			t.Errorf("expected Compress=CompressionStub, got %q", opt.Compress)
		}

		// OCC string should contain ",comp-lzo" (OpenVPN compatibility)
		s := opt.ServerOptionsString()
		if !strings.Contains(s, ",comp-lzo") {
			t.Errorf("OCC string should contain ,comp-lzo: %q", s)
		}
	})

	t.Run("compress stub equals COMP_ALG_STUB + COMP_F_SWAP", func(t *testing.T) {
		// OpenVPN 2.5 options.c:7875-7878
		l := []string{
			"remote 0.0.0.0 1194",
			"compress stub",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.Compress != CompressionStub {
			t.Errorf("expected Compress=CompressionStub, got %q", opt.Compress)
		}

		// OCC string should contain ",comp-lzo"
		s := opt.ServerOptionsString()
		if !strings.Contains(s, ",comp-lzo") {
			t.Errorf("OCC string should contain ,comp-lzo: %q", s)
		}
	})

	t.Run("comp-lzo no sets CompressionLZONo", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"comp-lzo no",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.Compress != CompressionLZONo {
			t.Errorf("expected Compress=CompressionLZONo, got %q", opt.Compress)
		}

		// OCC string should contain ",comp-lzo"
		s := opt.ServerOptionsString()
		if !strings.Contains(s, ",comp-lzo") {
			t.Errorf("OCC string should contain ,comp-lzo: %q", s)
		}
	})

	t.Run("OCC string uses ,comp-lzo for all compression modes", func(t *testing.T) {
		// OpenVPN 2.5 options.c:3838-3841 comment:
		// "for compatibility, this simply indicates that compression context is active,
		// not necessarily LZO per-se"
		testCases := []struct {
			name     string
			compress Compression
		}{
			{"stub", CompressionStub},
			{"lzo-no", CompressionLZONo},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				opt := &OpenVPNOptions{
					Compress: tc.compress,
				}
				s := opt.ServerOptionsString()
				if !strings.HasSuffix(s, ",comp-lzo") {
					t.Errorf("OCC string should end with ,comp-lzo for %s: %q", tc.name, s)
				}
				// Should NOT contain the specific mode (e.g., "compress stub")
				if strings.Contains(s, ",compress ") {
					t.Errorf("OCC string should not contain specific compress mode: %q", s)
				}
			})
		}
	})

	t.Run("CompressionUndef produces no compression in OCC string", func(t *testing.T) {
		opt := &OpenVPNOptions{
			Compress: CompressionUndef,
		}
		s := opt.ServerOptionsString()
		if strings.Contains(s, "comp") {
			t.Errorf("OCC string should not contain any compression marker for UNDEF: %q", s)
		}
	})
}
