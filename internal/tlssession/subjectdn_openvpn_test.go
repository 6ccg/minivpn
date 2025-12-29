package tlssession

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestFormatSubjectDN_IncludesExtraNames(t *testing.T) {
	rdns := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "test-server"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "extra"},
		},
	}
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("asn1.Marshal(RDNSequence) failed: %v", err)
	}
	got, err := formatSubjectDN(&x509.Certificate{RawSubject: raw})
	if err != nil {
		t.Fatalf("formatSubjectDN() failed: %v", err)
	}
	if !strings.Contains(got, "1.2.3.4=extra") {
		t.Fatalf("expected DN to include ExtraNames, got %q", got)
	}
}
