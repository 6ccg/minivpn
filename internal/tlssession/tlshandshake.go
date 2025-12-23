package tlssession

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/pkg/config"

	tls "github.com/refraction-networking/utls"
)

var (
	// ErrBadTLSInit is returned when TLS configuration cannot be initialized
	ErrBadTLSInit = errors.New("TLS init error")

	// ErrBadTLSHandshake is returned when the OpenVPN handshake failed.
	ErrBadTLSHandshake = errors.New("handshake failure")

	// ErrBadCA is returned when the CA file cannot be found or is not valid.
	ErrBadCA = errors.New("bad ca conf")

	// ErrBadKeypair is returned when the key or cert file cannot be found or is not valid.
	ErrBadKeypair = errors.New("bad keypair conf")

	// ErrBadParrot is returned for errors during TLS parroting
	ErrBadParrot = errors.New("cannot parrot")

	// ErrCannotVerifyCertChain is returned for certificate chain validation errors.
	ErrCannotVerifyCertChain = errors.New("cannot verify chain")

	// ErrX509NameMismatch is returned when the server certificate's X.509 name
	// does not match the expected value from --verify-x509-name.
	ErrX509NameMismatch = errors.New("X.509 name mismatch")

	// ErrKeyUsageMismatch is returned when the server certificate's Key Usage
	// does not match the expected value from --remote-cert-ku.
	ErrKeyUsageMismatch = errors.New("Key Usage mismatch")

	// ErrExtKeyUsageMismatch is returned when the server certificate's Extended Key Usage
	// does not match the expected value from --remote-cert-eku.
	ErrExtKeyUsageMismatch = errors.New("Extended Key Usage mismatch")
)

// certVerifyOptionsNoCommonNameCheck returns a x509.VerifyOptions initialized with
// an empty string for the DNSName. This allows to skip CN verification.
func certVerifyOptionsNoCommonNameCheck() x509.VerifyOptions {
	return x509.VerifyOptions{DNSName: ""}
}

// certVerifyOptions is the options factory that the customVerify function will
// use; by default it configures VerifyOptions to skip the DNSName check.
var certVerifyOptions = certVerifyOptionsNoCommonNameCheck

// certBytes holds the byte arrays for the cert, key, and ca used for OpenVPN
// certificate authentication.
type certBytes struct {
	cert []byte
	key  []byte
	ca   []byte
}

// loadCertAndCAFromBytes parses the PEM certificates from the byte arrays in the
// the passed certBytes, and return a certConfig with the client and CA certificates.
func loadCertAndCAFromBytes(crt certBytes) (*certConfig, error) {
	ca := x509.NewCertPool()
	ok := ca.AppendCertsFromPEM(crt.ca)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBadCA, "cannot parse ca cert")
	}
	cfg := &certConfig{ca: ca}
	if len(crt.cert) != 0 && len(crt.key) != 0 {
		cert, err := tls.X509KeyPair(crt.cert, crt.key)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBadKeypair, err)
		}
		cfg.cert = cert
	}
	return cfg, nil
}

// authorityPinner is any object from which we can obtain a certpool containing
// a pinned Certificate Authority for verification.
type authorityPinner interface {
	authority() *x509.CertPool
}

// certConfig holds the parsed certificate and CA used for OpenVPN mutual
// certificate authentication.
type certConfig struct {
	cert           tls.Certificate
	ca             *x509.CertPool
	verifyX509Name string
	verifyX509Type config.VerifyX509Type
	remoteCertKU   []config.KeyUsage
	remoteCertEKU  string
}

// newCertConfigFromOptions is a constructor that returns a certConfig object initialized
// from the paths specified in the passed Options object, and an error if it
// could not be properly built.
func newCertConfigFromOptions(o *config.OpenVPNOptions) (*certConfig, error) {
	cfg, err := loadCertAndCAFromBytes(certBytes{
		cert: o.Cert,
		key:  o.Key,
		ca:   o.CA,
	})
	if err != nil {
		return nil, err
	}
	cfg.verifyX509Name = o.VerifyX509Name
	cfg.verifyX509Type = o.VerifyX509Type
	cfg.remoteCertKU = o.RemoteCertKU
	cfg.remoteCertEKU = o.RemoteCertEKU
	return cfg, nil
}

// authority implements authorityPinner interface.
func (c *certConfig) authority() *x509.CertPool {
	return c.ca
}

// ensure certConfig implements authorityPinner.
var _ authorityPinner = &certConfig{}

// verifyFun is the type expected by the VerifyPeerCertificate callback in tls.Config.
type verifyFun func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// customVerifyFactory returns a verifyFun callback that will verify any received certificates
// against the ca provided by the certConfig, and optionally verify the X.509 name.
func customVerifyFactory(cfg *certConfig) verifyFun {
	// customVerify is a version of the verification routines that does not try to verify
	// the Common Name by default, since we don't know it a priori for a VPN gateway.
	// If verify-x509-name is configured, it will verify against the specified name.
	// Returns an error if the verification fails.
	// From tls/common documentation: If normal verification is disabled by
	// setting InsecureSkipVerify, [...] then this callback will be considered but
	// the verifiedChains argument will always be nil.
	customVerify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// we assume (from docs) that we're always given the
		// leaf certificate as the first cert in the array.
		leaf, _ := x509.ParseCertificate(rawCerts[0])
		if leaf == nil {
			return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, "nothing to verify")
		}
		// By default has DNSName verification disabled.
		opts := certVerifyOptions()
		// Set the configured CA(s) as the certificate pool to verify against.
		opts.Roots = cfg.authority()
		if len(rawCerts) > 1 {
			opts.Intermediates = x509.NewCertPool()
			for _, certDER := range rawCerts[1:] {
				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, err)
				}
				opts.Intermediates.AddCert(cert)
			}
		}

		if _, err := leaf.Verify(opts); err != nil {
			return fmt.Errorf("%w: %s", ErrCannotVerifyCertChain, err)
		}

		// Verify X.509 name if configured (--verify-x509-name)
		if cfg.verifyX509Type != config.VerifyX509None && cfg.verifyX509Name != "" {
			if err := verifyX509Name(leaf, cfg.verifyX509Name, cfg.verifyX509Type); err != nil {
				return err
			}
		}

		// Verify Key Usage if configured (--remote-cert-ku)
		if len(cfg.remoteCertKU) > 0 {
			if err := verifyKeyUsage(leaf, cfg.remoteCertKU); err != nil {
				return err
			}
		}

		// Verify Extended Key Usage if configured (--remote-cert-eku)
		if cfg.remoteCertEKU != "" {
			if err := verifyExtKeyUsage(leaf, cfg.remoteCertEKU); err != nil {
				return err
			}
		}

		return nil
	}
	return customVerify
}

// verifyX509Name verifies the certificate's X.509 name against the expected value.
// This implements OpenVPN's --verify-x509-name functionality.
func verifyX509Name(cert *x509.Certificate, expectedName string, verifyType config.VerifyX509Type) error {
	switch verifyType {
	case config.VerifyX509SubjectDN:
		// Match the complete Subject Distinguished Name
		// OpenVPN format: "C=XX, ST=State, L=City, CN=Name"
		subjectDN := formatSubjectDN(cert.Subject)
		if subjectDN != expectedName {
			return fmt.Errorf("%w: subject DN %q does not match expected %q",
				ErrX509NameMismatch, subjectDN, expectedName)
		}

	case config.VerifyX509SubjectRDN:
		// Match the Common Name (CN) exactly
		cn := cert.Subject.CommonName
		if cn != expectedName {
			return fmt.Errorf("%w: CN %q does not match expected %q",
				ErrX509NameMismatch, cn, expectedName)
		}

	case config.VerifyX509SubjectRDNPrefix:
		// Match the Common Name (CN) prefix
		cn := cert.Subject.CommonName
		if !strings.HasPrefix(cn, expectedName) {
			return fmt.Errorf("%w: CN %q does not have expected prefix %q",
				ErrX509NameMismatch, cn, expectedName)
		}
	}

	return nil
}

// formatSubjectDN formats the certificate subject in OpenVPN-compatible format.
// Example output: "C=KG, ST=NA, L=Bishkek, CN=Server-1"
func formatSubjectDN(subject pkix.Name) string {
	var parts []string

	for _, c := range subject.Country {
		parts = append(parts, "C="+c)
	}
	for _, st := range subject.Province {
		parts = append(parts, "ST="+st)
	}
	for _, l := range subject.Locality {
		parts = append(parts, "L="+l)
	}
	for _, o := range subject.Organization {
		parts = append(parts, "O="+o)
	}
	for _, ou := range subject.OrganizationalUnit {
		parts = append(parts, "OU="+ou)
	}
	if subject.CommonName != "" {
		parts = append(parts, "CN="+subject.CommonName)
	}

	return strings.Join(parts, ", ")
}

// verifyKeyUsage verifies the certificate's Key Usage against the expected values.
// This implements OpenVPN's --remote-cert-ku functionality.
// The certificate must match at least one of the expected Key Usage values.
func verifyKeyUsage(cert *x509.Certificate, expectedKUs []config.KeyUsage) error {
	if len(expectedKUs) == 0 {
		return nil
	}

	// Convert Go's x509.KeyUsage to our format
	// Go's x509.KeyUsage is a bitmask where bit 0 = KeyUsageDigitalSignature, etc.
	certKU := config.KeyUsage(cert.KeyUsage)

	for _, expected := range expectedKUs {
		// Check if all bits in expected are set in certKU
		if certKU&expected == expected {
			return nil
		}
	}

	return fmt.Errorf("%w: certificate key usage %04x does not match any of expected values",
		ErrKeyUsageMismatch, certKU)
}

// verifyExtKeyUsage verifies the certificate's Extended Key Usage against the expected value.
// This implements OpenVPN's --remote-cert-eku functionality.
// The expected EKU can be a name (e.g., "serverAuth") or an OID (e.g., "1.3.6.1.5.5.7.3.1").
func verifyExtKeyUsage(cert *x509.Certificate, expectedEKU string) error {
	if expectedEKU == "" {
		return nil
	}

	// Map of common EKU names to x509.ExtKeyUsage values
	ekuNameMap := map[string]x509.ExtKeyUsage{
		"serverAuth":                    x509.ExtKeyUsageServerAuth,
		"clientAuth":                    x509.ExtKeyUsageClientAuth,
		"codeSigning":                   x509.ExtKeyUsageCodeSigning,
		"emailProtection":               x509.ExtKeyUsageEmailProtection,
		"timeStamping":                  x509.ExtKeyUsageTimeStamping,
		"OCSPSigning":                   x509.ExtKeyUsageOCSPSigning,
		"TLS Web Server Authentication": x509.ExtKeyUsageServerAuth,
		"TLS Web Client Authentication": x509.ExtKeyUsageClientAuth,
	}

	// Map of OIDs to x509.ExtKeyUsage values
	ekuOIDMap := map[string]x509.ExtKeyUsage{
		"1.3.6.1.5.5.7.3.1": x509.ExtKeyUsageServerAuth,      // TLS Web Server Authentication
		"1.3.6.1.5.5.7.3.2": x509.ExtKeyUsageClientAuth,      // TLS Web Client Authentication
		"1.3.6.1.5.5.7.3.3": x509.ExtKeyUsageCodeSigning,     // Code Signing
		"1.3.6.1.5.5.7.3.4": x509.ExtKeyUsageEmailProtection, // Email Protection
		"1.3.6.1.5.5.7.3.8": x509.ExtKeyUsageTimeStamping,    // Time Stamping
		"1.3.6.1.5.5.7.3.9": x509.ExtKeyUsageOCSPSigning,     // OCSP Signing
	}

	// Try to find the expected EKU
	var targetEKU x509.ExtKeyUsage
	var found bool

	// Check by name first
	if eku, ok := ekuNameMap[expectedEKU]; ok {
		targetEKU = eku
		found = true
	}

	// Check by OID
	if !found {
		if eku, ok := ekuOIDMap[expectedEKU]; ok {
			targetEKU = eku
			found = true
		}
	}

	if !found {
		// Unknown EKU name/OID - we can't verify it
		return fmt.Errorf("%w: unknown Extended Key Usage: %s", ErrExtKeyUsageMismatch, expectedEKU)
	}

	// Check if the certificate has the required EKU
	for _, eku := range cert.ExtKeyUsage {
		if eku == targetEKU {
			return nil
		}
		// x509.ExtKeyUsageAny matches all EKUs
		if eku == x509.ExtKeyUsageAny {
			return nil
		}
	}

	return fmt.Errorf("%w: certificate does not have required Extended Key Usage: %s",
		ErrExtKeyUsageMismatch, expectedEKU)
}

// initTLS returns a tls.Config matching the VPN options. Internally, it uses
// the verify function returned by the global customVerifyFactory,
// verification function since verifying the ServerName does not make sense in
// the context of establishing a VPN session: we perform mutual TLS
// Authentication with the custom CA.
func initTLS(cfg *certConfig) (*tls.Config, error) {
	runtimex.Assert(cfg != nil, "passed nil configuration")

	customVerify := customVerifyFactory(cfg)

	tlsConf := &tls.Config{
		// the certificate we've loaded from the config file
		Certificates: []tls.Certificate{cfg.cert},
		// crypto/tls wants either ServerName or InsecureSkipVerify set ...
		InsecureSkipVerify: true,
		// ...but we pass our own verification function that verifies against the CA and ignores the ServerName
		VerifyPeerCertificate: customVerify,
		// disable DynamicRecordSizing to lower distinguishability.
		DynamicRecordSizingDisabled: true,
		// uTLS does not pick min/max version from the passed spec
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	} //#nosec G402

	return tlsConf, nil
}

// tlsHandshake performs the TLS handshake over the control channel, and return
// the TLS Client as a net.Conn; returns also any error during the handshake.
func tlsHandshake(tlsConn net.Conn, tlsConf *tls.Config) (net.Conn, error) {
	tlsClient, err := tlsFactoryFn(tlsConn, tlsConf)
	if err != nil {
		return nil, err
	}
	if err := tlsClient.Handshake(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadTLSHandshake, err)
	}
	return tlsClient, nil
}

// handshaker is a custom interface that we define here to be able to mock
// the tls.Conn implementation.
type handshaker interface {
	net.Conn
	Handshake() error
}

// defaultTLSFactory returns an implementer of the handshaker interface; that
// is, the default tls.Client factory; and an error.
// we're not using the default factory right now, but it comes handy to be able
// to compare the fingerprints with a golang TLS handshake.
// TODO(ainghazal): implement some sort of test that extracts/compares the TLS client hello.
func defaultTLSFactory(conn net.Conn, config *tls.Config) (handshaker, error) {
	c := tls.Client(conn, config)
	return c, nil
}

// vpnClientHelloHex is the hexadecimal representation of a capture from the reference openvpn implementation.
// openvpn=2.5.5,openssl=3.0.2
// You can use https://github.com/ainghazal/sniff/tree/main/clienthello to
// analyze a ClientHello from the wire or pcap.
var vpnClientHelloHex = `1603010114010001100303534e0a0f2687b240f7c7dfbb51c4aac33639f28173aa5d7bcebb159695ab0855208b835bf240a83df66885d6747b5bbf1b631e8c34ae469c629d7eb76e247128eb0032130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c013003300ff01000095000b000403000102000a00160014001d0017001e00190018010001010102010301040016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d0020a10bc24becb583293c317220e6725205d3a177a4a974090f6ffcf13a43da7035`

// parrotTLSFactory returns an implementer of the handshaker interface; in this
// case, a parroting implementation; and an error.
func parrotTLSFactory(conn net.Conn, config *tls.Config) (handshaker, error) {
	fingerprinter := &tls.Fingerprinter{AllowBluntMimicry: true}
	rawOpenVPNClientHelloBytes, err := hex.DecodeString(vpnClientHelloHex)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot decode raw fingerprint: %s", ErrBadParrot, err)
	}
	generatedSpec, err := fingerprinter.FingerprintClientHello(rawOpenVPNClientHelloBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: fingerprinting failed: %s", ErrBadParrot, err)
	}
	client := tls.UClient(conn, config, tls.HelloCustom)
	if err := client.ApplyPreset(generatedSpec); err != nil {
		return nil, fmt.Errorf("%w: cannot apply spec: %s", ErrBadParrot, err)
	}
	return client, nil
}

// global variables to allow monkeypatching in tests.
var (
	initTLSFn      = initTLS
	tlsFactoryFn   = parrotTLSFactory
	tlsHandshakeFn = tlsHandshake
)
