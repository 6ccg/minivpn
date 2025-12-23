package config

import (
	"errors"
	"os"
	"reflect"
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
			name:   "empty cipher",
			fields: fields{},
			want:   "",
		},
		{
			name: "proto tcp",
			fields: fields{
				Cipher: "AES-128-GCM",
				Auth:   "sha512",
				Proto:  ProtoTCP,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto TCPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client",
		},
		{
			name: "compress stub",
			fields: fields{
				Cipher:   "AES-128-GCM",
				Auth:     "sha512",
				Proto:    ProtoUDP,
				Compress: CompressionStub,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client,compress stub",
		},
		{
			name: "compress lzo-no",
			fields: fields{
				Cipher:   "AES-128-GCM",
				Auth:     "sha512",
				Proto:    ProtoUDP,
				Compress: CompressionLZONo,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto UDPv4,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client,lzo-comp no",
		},
		{
			name: "proto udp6",
			fields: fields{
				Cipher: "AES-128-GCM",
				Auth:   "sha512",
				Proto:  ProtoUDP6,
			},
			want: "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto UDPv6,cipher AES-128-GCM,auth sha512,keysize 128,key-method 2,tls-client",
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
		if opt.Compress != CompressionEmpty {
			t.Errorf("Expected compression empty")
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

func TestGetOptionsFromLinesNoFiles(t *testing.T) {
	t.Run("getting certificatee should fail if no file passed", func(t *testing.T) {
		l := []string{"ca ca.crt"}
		if _, err := getOptionsFromLines(l, t.TempDir()); err == nil {
			t.Errorf("Should fail if no files provided")
		}
	})
}

func TestGetOptionsNoCompression(t *testing.T) {
	t.Run("compress is parsed as literal empty", func(t *testing.T) {
		l := []string{"compress"}
		o, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Errorf("Should not fail: compress")
		}
		if o.Compress != "empty" {
			t.Errorf("Expected compress==empty")
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

func writeDummyConfigFile(dir string) (string, error) {
	f, err := os.CreateTemp(dir, "tmpfile-")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(dummyConfigFile); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func Test_ParseConfigFile(t *testing.T) {
	t.Run("a valid configfile should be correctly parsed", func(t *testing.T) {
		f, err := writeDummyConfigFile(t.TempDir())
		if err != nil {
			t.Fatal("ParseConfigFile(): cannot write cert needed for the test")
		}
		o, err := ReadConfigFile(f)
		if err != nil {
			t.Errorf("ParseConfigFile(): expected err=%v, got=%v", nil, err)
		}
		wantProto := ProtoUDP
		if o.Proto != wantProto {
			t.Errorf("ParseConfigFile(): expected Proto=%v, got=%v", wantProto, o.Proto)
		}
		wantCipher := "AES-128-GCM"
		if o.Cipher != wantCipher {
			t.Errorf("ParseConfigFile(): expected=%v, got=%v", wantCipher, o.Cipher)
		}
	})

	t.Run("an empty file path should error", func(t *testing.T) {
		if _, err := ReadConfigFile(""); err == nil {
			t.Errorf("expected error with empty file")
		}
	})

	t.Run("an http uri should fail", func(t *testing.T) {
		if _, err := ReadConfigFile("http://example.com"); err == nil {
			t.Errorf("expected error with http uri")
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
	t.Run("an unknown key should not return an error but fail gracefully", func(t *testing.T) {
		_, err := parseOption(&OpenVPNOptions{}, t.TempDir(), "unknownKey", []string{"a", "b"}, 0)
		if err != nil {
			t.Errorf("parseOption(): want %v, got %v", nil, err)
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

// TODO(ainghazal): either check returned value or check mutation of the options argument.
func Test_parseTLSVerMax(t *testing.T) {
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
			name:    "default",
			args:    args{o: &OpenVPNOptions{}},
			wantErr: nil,
		},
		{
			name:    "default with good tls opt",
			args:    args{p: []string{"1.2"}, o: &OpenVPNOptions{}},
			wantErr: nil,
		},
		{
			// TODO(ainghazal): this case should fail
			name:    "default with too many parts",
			args:    args{p: []string{"1.2", "1.3"}, o: &OpenVPNOptions{}},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseTLSVerMax(tt.args.p, tt.args.o); !errors.Is(err, tt.wantErr) {
				t.Errorf("parseTLSVerMax() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getCredentialsFromFile(t *testing.T) {
	makeCreds := func(credStr string) string {
		f, err := os.CreateTemp(t.TempDir(), "tmpfile-")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(credStr)); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return f.Name()
	}

	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		{
			name:    "should fail with non-existing file",
			args:    args{"/tmp/nonexistent"},
			want:    nil,
			wantErr: ErrBadConfig,
		},
		{
			name:    "should fail with empty file",
			args:    args{makeCreds("")},
			want:    nil,
			wantErr: ErrBadConfig,
		},
		{
			name:    "should fail with empty user",
			args:    args{makeCreds("\n\n")},
			want:    nil,
			wantErr: ErrBadConfig,
		},
		{
			name:    "should fail with empty pass",
			args:    args{makeCreds("user\n\n")},
			want:    nil,
			wantErr: ErrBadConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCredentialsFromFile(tt.args.path)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("getCredentialsFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCredentialsFromFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isSubdir(t *testing.T) {
	type args struct {
		parent string
		sub    string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "sunny path",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo/bar/baz",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "same dir",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo/bar",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "same dir w/ slash",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo/bar/",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "not subdir",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "path traversal",
			args: args{
				parent: "/foo/bar",
				sub:    "/foo/bar/./../",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "path traversal with .",
			args: args{
				parent: ".",
				sub:    "/etc/",
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isSubdir(tt.args.parent, tt.args.sub)
			if (err != nil) != tt.wantErr {
				t.Errorf("isSubdir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isSubdir() = %v, want %v", got, tt.want)
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
		if opt.RemoteCertKU[0] != KeyUsage(0x80) {
			t.Errorf("expected RemoteCertKU[0]=0x80, got 0x%x", opt.RemoteCertKU[0])
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
		expected := []KeyUsage{0x80, 0xa0, 0x88}
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
		if opt.RemoteCertKU[0] != KeyUsage(0xA0) {
			t.Errorf("expected RemoteCertKU[0]=0xA0, got 0x%x", opt.RemoteCertKU[0])
		}
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

	t.Run("remote-cert-ku with no args returns error", func(t *testing.T) {
		opt := &OpenVPNOptions{}
		_, err := parseRemoteCertKU([]string{}, opt)
		if err == nil {
			t.Error("expected error for remote-cert-ku with no args")
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
	t.Run("remote-cert-tls server sets EKU to serverAuth", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-tls server",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.RemoteCertEKU != "serverAuth" {
			t.Errorf("expected RemoteCertEKU=serverAuth, got %q", opt.RemoteCertEKU)
		}
	})

	t.Run("remote-cert-tls client sets EKU to clientAuth", func(t *testing.T) {
		l := []string{
			"remote 0.0.0.0 1194",
			"remote-cert-tls client",
		}
		opt, err := getOptionsFromLines(l, t.TempDir())
		if err != nil {
			t.Fatalf("getOptionsFromLines: %v", err)
		}
		if opt.RemoteCertEKU != "clientAuth" {
			t.Errorf("expected RemoteCertEKU=clientAuth, got %q", opt.RemoteCertEKU)
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
		if opt.RemoteCertEKU != "serverAuth" {
			t.Errorf("expected RemoteCertEKU=serverAuth, got %q", opt.RemoteCertEKU)
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
