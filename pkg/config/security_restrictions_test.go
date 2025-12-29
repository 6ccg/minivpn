package config

import "testing"

func TestReadConfigFromString_AllowsInlineCA(t *testing.T) {
	cfg := `
proto udp
remote 1.2.3.4 1194
<ca>
dummy-ca
</ca>
`
	o, err := ReadConfigFromString(cfg)
	if err != nil {
		t.Fatalf("ReadConfigFromString: %v", err)
	}
	if len(o.CA) == 0 {
		t.Fatalf("expected CA bytes from inline <ca> block")
	}
}

func TestReadConfigFromString_RejectsFilePathParameters(t *testing.T) {
	testcases := []struct {
		name string
		cfg  string
	}{
		{"ca", "ca ca.pem\n"},
		{"cert", "cert client.crt\n"},
		{"key", "key client.key\n"},
		{"tls-auth", "tls-auth ta.key\n"},
		{"tls-crypt", "tls-crypt tc.key\n"},
		{"tls-crypt-v2", "tls-crypt-v2 tc2.key\n"},
		{"auth-user-pass", "auth-user-pass creds.txt\n"},
		// OpenVPN 2.5.x directives that reference external files must be rejected
		// (we only support inline crypto/credentials blocks).
		{"pkcs12", "pkcs12 client.p12\n"},
		{"crl-verify", "crl-verify crl.pem\n"},
		{"dh", "dh dh.pem\n"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadConfigFromString(tc.cfg)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestHasAuthInfo_AllowsUpperLayerCredentialInjection(t *testing.T) {
	cfg := `
proto udp
remote 1.2.3.4 1194
auth-user-pass
<ca>
dummy-ca
</ca>
`
	o, err := ReadConfigFromString(cfg)
	if err != nil {
		t.Fatalf("ReadConfigFromString: %v", err)
	}
	if o.HasAuthInfo() {
		t.Fatalf("expected HasAuthInfo() to be false before injecting credentials")
	}
	o.Username = "user"
	o.Password = "pass"
	if !o.HasAuthInfo() {
		t.Fatalf("expected HasAuthInfo() to be true after injecting credentials")
	}
}
