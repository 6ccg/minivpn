package tlssession

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
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
		// OpenVPN format uses OpenSSL's X509_NAME_print_ex output (see .openvpn-ref).
		subjectDN, err := formatSubjectDN(cert)
		if err != nil {
			return fmt.Errorf("%w: cannot format subject DN: %s", ErrX509NameMismatch, err)
		}
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

// formatSubjectDN formats the certificate subject in an OpenVPN/OpenSSL-compatible format.
//
// It mimics OpenSSL's X509_NAME_print_ex with:
// XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN | ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_CTRL.
func formatSubjectDN(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("nil cert")
	}
	raw := cert.RawSubject
	if len(raw) == 0 {
		seq := cert.Subject.ToRDNSequence()
		encoded, err := asn1.Marshal(seq)
		if err != nil {
			return "", err
		}
		raw = encoded
	}
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdns); err != nil {
		return "", err
	}
	if len(rdns) == 0 {
		return "", nil
	}

	rdnParts := make([]string, 0, len(rdns))
	for _, rdn := range rdns {
		if len(rdn) == 0 {
			continue
		}
		avParts := make([]string, 0, len(rdn))
		for _, atv := range rdn {
			avParts = append(avParts, oidShortName(atv.Type)+"="+escapeDNValue(formatATVValue(atv.Value)))
		}
		rdnParts = append(rdnParts, strings.Join(avParts, " + "))
	}
	return strings.Join(rdnParts, ", "), nil
}

var oidShortNames = map[string]string{
	"2.5.4.6":                    "C",            // countryName
	"2.5.4.8":                    "ST",           // stateOrProvinceName
	"2.5.4.7":                    "L",            // localityName
	"2.5.4.10":                   "O",            // organizationName
	"2.5.4.11":                   "OU",           // organizationalUnitName
	"2.5.4.3":                    "CN",           // commonName
	"2.5.4.5":                    "serialNumber", // serialNumber
	"2.5.4.9":                    "street",       // streetAddress
	"2.5.4.17":                   "postalCode",   // postalCode
	"1.2.840.113549.1.9.1":       "emailAddress", // pkcs9 emailAddress
	"0.9.2342.19200300.100.1.25": "DC",           // domainComponent
}

func oidShortName(oid asn1.ObjectIdentifier) string {
	if name, ok := oidShortNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

func formatATVValue(v any) string {
	switch vv := v.(type) {
	case string:
		return vv
	case []byte:
		return string(vv)
	default:
		return fmt.Sprint(v)
	}
}

func escapeDNValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString("\\\\")
		case r <= 0x1f || r == 0x7f:
			b.WriteString(fmt.Sprintf("\\x%02X", r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// verifyKeyUsage verifies the certificate's Key Usage against the expected values.
// This implements OpenVPN's --remote-cert-ku functionality.
// The certificate must match at least one of the expected Key Usage values.
func verifyKeyUsage(cert *x509.Certificate, expectedKUs []config.KeyUsage) error {
	if len(expectedKUs) == 0 {
		return nil
	}

	// OpenVPN 2.5 semantics: when --remote-cert-ku is specified with no args, or
	// when --remote-cert-tls is used, the first KU is the OPENVPN_KU_REQUIRED
	// sentinel (0xFFFF). In that case we only require the Key Usage extension to
	// be present, but we don't check specific bits.
	if expectedKUs[0] == config.KeyUsageRequired {
		if !hasKeyUsageExtension(cert) {
			return fmt.Errorf("%w: certificate does not have key usage extension",
				ErrKeyUsageMismatch)
		}
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

var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

func hasKeyUsageExtension(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidKeyUsage) {
			return true
		}
	}
	for _, ext := range cert.ExtraExtensions {
		if ext.Id.Equal(oidKeyUsage) {
			return true
		}
	}
	return false
}

// verifyExtKeyUsage verifies the certificate's Extended Key Usage against the expected value.
// This implements OpenVPN's --remote-cert-eku functionality.
// The expected EKU can be a name (e.g., "serverAuth") or an OID (e.g., "1.3.6.1.5.5.7.3.1").
func verifyExtKeyUsage(cert *x509.Certificate, expectedEKU string) error {
	if expectedEKU == "" {
		return nil
	}

	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny {
			return nil
		}
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

	// If expectedEKU looks like an OID, also check UnknownExtKeyUsage.
	if !found {
		oid, ok := parseOID(expectedEKU)
		if !ok {
			return fmt.Errorf("%w: unknown Extended Key Usage: %s", ErrExtKeyUsageMismatch, expectedEKU)
		}
		for _, u := range cert.UnknownExtKeyUsage {
			if u.Equal(oid) {
				return nil
			}
		}
		return fmt.Errorf("%w: certificate does not have required Extended Key Usage: %s",
			ErrExtKeyUsageMismatch, expectedEKU)
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

func parseOID(s string) (asn1.ObjectIdentifier, bool) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, false
	}
	out := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, false
		}
		out = append(out, value)
	}
	return out, true
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
	if err := applyTLSVersionMaxToClientHelloSpec(generatedSpec, config.MaxVersion); err != nil {
		return nil, fmt.Errorf("%w: cannot apply tls-version-max: %s", ErrBadParrot, err)
	}
	client := tls.UClient(conn, config, tls.HelloCustom)
	if err := client.ApplyPreset(generatedSpec); err != nil {
		return nil, fmt.Errorf("%w: cannot apply spec: %s", ErrBadParrot, err)
	}
	return client, nil
}

func applyTLSVersionMaxToClientHelloSpec(spec *tls.ClientHelloSpec, maxVersion uint16) error {
	if spec == nil || maxVersion == 0 || maxVersion >= tls.VersionTLS13 {
		return nil
	}

	supportedVersionsFound := false
	for _, ext := range spec.Extensions {
		sve, ok := ext.(*tls.SupportedVersionsExtension)
		if !ok {
			continue
		}
		supportedVersionsFound = true

		filtered := make([]uint16, 0, len(sve.Versions))
		for _, v := range sve.Versions {
			if isGreaseUint16(v) || v <= maxVersion {
				filtered = append(filtered, v)
			}
		}
		if !hasNonGreaseUint16(filtered) {
			return fmt.Errorf("%w: no supported TLS versions after applying tls-version-max", ErrBadTLSInit)
		}
		sve.Versions = filtered
	}

	if supportedVersionsFound {
		return nil
	}

	// If the spec has no SupportedVersionsExtension (e.g., a TLS 1.2 ClientHello),
	// fall back to clamping TLSVersMax directly.
	if spec.TLSVersMax == 0 || spec.TLSVersMax > maxVersion {
		spec.TLSVersMax = maxVersion
	}
	if spec.TLSVersMin == 0 || spec.TLSVersMin > maxVersion {
		spec.TLSVersMin = maxVersion
	}
	return nil
}

func isGreaseUint16(v uint16) bool {
	// See RFC 8701 (GREASE) for the 0x?a?a pattern.
	return (v&0x0f0f) == 0x0a0a && byte(v>>8) == byte(v)
}

func hasNonGreaseUint16(values []uint16) bool {
	for _, v := range values {
		if !isGreaseUint16(v) {
			return true
		}
	}
	return false
}

// global variables to allow monkeypatching in tests.
var (
	initTLSFn      = initTLS
	tlsFactoryFn   = parrotTLSFactory
	tlsHandshakeFn = tlsHandshake
)
