package tlssession

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/ooni/minivpn/pkg/config"
)

func TestVerifyKeyUsage_KeyUsageRequiredSentinel(t *testing.T) {
	t.Run("missing key usage extension fails", func(t *testing.T) {
		cert := &x509.Certificate{}
		err := verifyKeyUsage(cert, []config.KeyUsage{config.KeyUsageRequired})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("present key usage extension passes", func(t *testing.T) {
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 15}},
			},
		}
		err := verifyKeyUsage(cert, []config.KeyUsage{config.KeyUsageRequired})
		if err != nil {
			t.Fatalf("verifyKeyUsage: %v", err)
		}
	})
}
