package config

import (
	"errors"
	"strings"
	"testing"
)

func TestReadConfigFromBytes_AllowsInlineBlocks(t *testing.T) {
	config := strings.Join([]string{
		"remote 198.51.100.1 1194",
		"proto udp4",
		"<ca>",
		"ca_string",
		"</ca>",
		"<cert>",
		"cert_string",
		"</cert>",
		"<key>",
		"key_string",
		"</key>",
		"",
	}, "\n")

	opts, err := ReadConfigFromBytes([]byte(config))
	if err != nil {
		t.Fatalf("ReadConfigFromBytes() failed: %v", err)
	}
	if len(opts.CA) == 0 || !strings.Contains(string(opts.CA), "ca_string") {
		t.Fatalf("expected inline <ca> to be parsed")
	}
	if len(opts.Cert) == 0 || !strings.Contains(string(opts.Cert), "cert_string") {
		t.Fatalf("expected inline <cert> to be parsed")
	}
	if len(opts.Key) == 0 || !strings.Contains(string(opts.Key), "key_string") {
		t.Fatalf("expected inline <key> to be parsed")
	}
}

func TestReadConfigFromBytes_RejectsFilePathArguments(t *testing.T) {
	testcases := []struct {
		name   string
		config string
	}{
		{
			name: "ca file path",
			config: strings.Join([]string{
				"ca ca.crt",
				"<ca>",
				"ca_string",
				"</ca>",
				"",
			}, "\n"),
		},
		{
			name: "cert file path",
			config: strings.Join([]string{
				"cert client.crt",
				"<cert>",
				"cert_string",
				"</cert>",
				"",
			}, "\n"),
		},
		{
			name: "key file path",
			config: strings.Join([]string{
				"key client.key",
				"<key>",
				"key_string",
				"</key>",
				"",
			}, "\n"),
		},
		{
			name: "tls-auth file path",
			config: strings.Join([]string{
				"tls-auth ta.key 1",
				"<tls-auth>",
				"ta_string",
				"</tls-auth>",
				"",
			}, "\n"),
		},
		{
			name: "tls-crypt file path",
			config: strings.Join([]string{
				"tls-crypt tc.key",
				"<tls-crypt>",
				"tc_string",
				"</tls-crypt>",
				"",
			}, "\n"),
		},
		{
			name: "tls-crypt-v2 file path",
			config: strings.Join([]string{
				"tls-crypt-v2 tc-v2.key",
				"<tls-crypt-v2>",
				"tc_v2_string",
				"</tls-crypt-v2>",
				"",
			}, "\n"),
		},
		{
			name: "auth-user-pass file path",
			config: strings.Join([]string{
				"auth-user-pass auth.txt",
				"",
			}, "\n"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadConfigFromBytes([]byte(tt.config))
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, ErrBadConfig) {
				t.Fatalf("expected ErrBadConfig, got %v", err)
			}
		})
	}
}

func TestReadConfigFromBytes_AuthUserPassInjected(t *testing.T) {
	config := strings.Join([]string{
		"remote 198.51.100.1 1194",
		"proto udp4",
		"auth-user-pass",
		"<ca>",
		"ca_string",
		"</ca>",
		"",
	}, "\n")

	opts, err := ReadConfigFromBytes([]byte(config))
	if err != nil {
		t.Fatalf("ReadConfigFromBytes() failed: %v", err)
	}
	if !opts.AuthUserPass {
		t.Fatalf("expected AuthUserPass=true")
	}
	if opts.Username != "" || opts.Password != "" {
		t.Fatalf("expected empty injected credentials before override")
	}

	opts.Username = "user"
	opts.Password = "pass"

	if !opts.HasAuthInfo() {
		t.Fatalf("expected HasAuthInfo() after injecting username/password")
	}

	u, p, err := opts.AuthUserPassSetup()
	if err != nil {
		t.Fatalf("AuthUserPassSetup() failed: %v", err)
	}
	if u != "user" || p != "pass" {
		t.Fatalf("unexpected credentials: got %q/%q", u, p)
	}
}
