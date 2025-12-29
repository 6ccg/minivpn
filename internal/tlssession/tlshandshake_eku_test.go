package tlssession

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

func Test_verifyExtKeyUsage_CustomOIDMatchesUnknownExtKeyUsage(t *testing.T) {
	cert := &x509.Certificate{
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			{1, 2, 3, 4, 5},
		},
	}

	if oid, ok := parseOID("1.2.3.4.5"); !ok {
		t.Fatalf("parseOID: expected ok=true")
	} else if oid.String() != "1.2.3.4.5" {
		t.Fatalf("parseOID: expected oid=1.2.3.4.5, got %q", oid.String())
	}

	if err := verifyExtKeyUsage(cert, "1.2.3.4.5"); err != nil {
		t.Fatalf("verifyExtKeyUsage: %v", err)
	}
}
