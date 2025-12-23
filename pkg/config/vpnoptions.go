package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ooni/minivpn/internal/runtimex"
)

type (
	// Compression describes a Compression type (e.g., stub).
	Compression string
)

const (
	// CompressionStub adds the (empty) compression stub to the packets.
	CompressionStub = Compression("stub")

	// CompressionEmpty is the empty compression.
	CompressionEmpty = Compression("empty")

	// CompressionLZONo is lzo-no (another type of no-compression, older).
	CompressionLZONo = Compression("lzo-no")
)

// Proto is the main vpn mode (e.g., TCP or UDP).
type Proto string

var _ fmt.Stringer = Proto("")

// String implements fmt.Stringer
func (p Proto) String() string {
	return string(p)
}

// IsTCP returns true if the protocol is TCP-based (tcp, tcp4, tcp6).
func (p Proto) IsTCP() bool {
	return p == ProtoTCP || p == ProtoTCP4 || p == ProtoTCP6
}

const (
	// ProtoTCP is used for vpn in TCP mode (dual-stack).
	ProtoTCP = Proto("tcp")

	// ProtoTCP4 is used for vpn in TCP mode, forcing IPv4.
	ProtoTCP4 = Proto("tcp4")

	// ProtoTCP6 is used for vpn in TCP mode, forcing IPv6.
	ProtoTCP6 = Proto("tcp6")

	// ProtoUDP is used for vpn in UDP mode (dual-stack).
	ProtoUDP = Proto("udp")

	// ProtoUDP4 is used for vpn in UDP mode, forcing IPv4.
	ProtoUDP4 = Proto("udp4")

	// ProtoUDP6 is used for vpn in UDP mode, forcing IPv6.
	ProtoUDP6 = Proto("udp6")
)

// ErrBadConfig is the generic error returned for invalid config files
var ErrBadConfig = errors.New("openvpn: bad config")

// SupportedCiphers defines the supported ciphers.
var SupportedCiphers = []string{
	"AES-128-CBC",
	"AES-192-CBC",
	"AES-256-CBC",
	"AES-128-GCM",
	"AES-256-GCM",
}

// SupportedAuth defines the supported authentication methods.
var SupportedAuth = []string{
	"SHA1",
	"SHA256",
	"SHA512",
}

// Default values for renegotiation options (matching OpenVPN 2.5 defaults)
const (
	// DefaultRenegotiateSeconds is the default time after which to renegotiate keys (1 hour).
	DefaultRenegotiateSeconds = 3600

	// DefaultRenegotiateBytes is -1 meaning disabled by default.
	// Exception: for ciphers with block sizes < 128 bits, OpenVPN sets this to 64MB.
	DefaultRenegotiateBytes = -1

	// DefaultTransitionWindow is how long (seconds) a lame duck key stays alive
	// after a soft reset. This corresponds to OpenVPN's --transition-window option.
	DefaultTransitionWindow = 60

	// DefaultHandshakeWindow is the default time in seconds within which the TLS handshake
	// must complete (including PUSH_REPLY). Corresponds to OpenVPN's --hand-window option.
	DefaultHandshakeWindow = 60

	// PushRequestInterval is the interval in seconds between PUSH_REQUEST retries.
	// This matches OpenVPN's PUSH_REQUEST_INTERVAL constant in common.h.
	PushRequestInterval = 5
)

// VerifyX509Type specifies how to verify the server certificate's X.509 name.
// Corresponds to OpenVPN's --verify-x509-name option.
type VerifyX509Type int

const (
	// VerifyX509None means no X.509 name verification (default).
	VerifyX509None VerifyX509Type = iota

	// VerifyX509SubjectDN matches the complete Subject Distinguished Name.
	VerifyX509SubjectDN

	// VerifyX509SubjectRDN matches a Subject Relative Distinguished Name (typically CN).
	VerifyX509SubjectRDN

	// VerifyX509SubjectRDNPrefix matches a prefix of the Subject RDN.
	VerifyX509SubjectRDNPrefix
)

// KeyUsage represents X.509 Key Usage flags.
// These correspond to the bits in the Key Usage extension (RFC 5280).
type KeyUsage uint16

const (
	// Key Usage bit flags (matching OpenVPN's definitions from ssl_verify.h)
	KeyUsageDigitalSignature KeyUsage = 1 << 0 // 0x0001
	KeyUsageNonRepudiation   KeyUsage = 1 << 1 // 0x0002
	KeyUsageKeyEncipherment  KeyUsage = 1 << 2 // 0x0004
	KeyUsageDataEncipherment KeyUsage = 1 << 3 // 0x0008
	KeyUsageKeyAgreement     KeyUsage = 1 << 4 // 0x0010
	KeyUsageKeyCertSign      KeyUsage = 1 << 5 // 0x0020
	KeyUsageCRLSign          KeyUsage = 1 << 6 // 0x0040
	KeyUsageEncipherOnly     KeyUsage = 1 << 7 // 0x0080
	KeyUsageDecipherOnly     KeyUsage = 1 << 8 // 0x0100
)

// OpenVPNOptions make all the relevant openvpn configuration options accessible to the
// different modules that need it.
type OpenVPNOptions struct {
	// These options have the same name of OpenVPN options referenced in the official documentation:
	Remote     string
	Port       string
	Proto      Proto
	Username   string
	Password   string
	CA         []byte
	Cert       []byte
	Key        []byte
	TLSAuth    []byte
	TLSCrypt   []byte
	TLSCryptV2 []byte
	Cipher     string
	Auth       string
	TLSMaxVer  string

	// Below are options that do not conform strictly to the OpenVPN configuration format, but still can
	// be understood by us in a configuration file:

	Compress   Compression
	ProxyOBFS4 string

	// KeyDirection is the tls-auth key-direction. When unset, OpenVPN operates
	// in bidirectional mode.
	KeyDirection *int

	// AuthUserPass indicates that auth-user-pass was present in the config.
	AuthUserPass bool

	// AuthNoCache indicates that auth-nocache was present in the config.
	// When set, suggests that credentials should not be cached in memory.
	// Note: In Go, true secure memory zeroing is not guaranteed due to GC.
	AuthNoCache bool

	// Fragment is the --fragment option value (max UDP packet size).
	// Only supported for UDP. 0 means disabled.
	Fragment int

	// RenegotiateSeconds is the maximum time in seconds before renegotiating data channel keys.
	// Default is 3600 (1 hour). Set to 0 to disable time-based renegotiation.
	RenegotiateSeconds int

	// RenegotiateBytes is the number of bytes after which to renegotiate data channel keys.
	// Default is -1 (disabled). Set to 0 to explicitly disable.
	// For ciphers with block sizes < 128 bits, this defaults to 64MB if not set.
	RenegotiateBytes int64

	// RenegotiatePackets is the number of packets after which to renegotiate data channel keys.
	// Default is 0 (disabled). Corresponds to OpenVPN's --reneg-pkts option.
	RenegotiatePackets int64

	// TransitionWindow is how long in seconds a lame duck key stays alive after soft reset.
	// Default is 60 seconds. Corresponds to OpenVPN's --transition-window option.
	TransitionWindow int

	// Ping is the interval in seconds for sending keepalive ping packets.
	// Default is 0 (disabled, uses hardcoded 10s). When set, sends ping every N seconds.
	// Corresponds to OpenVPN's --ping option.
	Ping int

	// PingRestart is the timeout in seconds after which the tunnel is restarted
	// if no packets are received. Default is 0 (disabled).
	// When triggered, sends SOFT_RESET to renegotiate keys.
	// Corresponds to OpenVPN's --ping-restart option.
	PingRestart int

	// PingExit is the timeout in seconds after which the client exits
	// if no packets are received. Default is 0 (disabled).
	// PingExit takes precedence over PingRestart if both are set.
	// Corresponds to OpenVPN's --ping-exit option.
	PingExit int

	// HandshakeWindow is the time in seconds within which the TLS handshake
	// (including receiving PUSH_REPLY) must complete. Default is 60.
	// Also controls the maximum number of PUSH_REQUEST retries.
	// Corresponds to OpenVPN's --hand-window option.
	HandshakeWindow int

	// VerifyX509Name is the expected X.509 name to verify against the server certificate.
	// Used together with VerifyX509Type. Empty means no verification.
	// Corresponds to OpenVPN's --verify-x509-name option.
	VerifyX509Name string

	// VerifyX509Type specifies how to match the VerifyX509Name against the certificate.
	// Default is VerifyX509None (no verification).
	VerifyX509Type VerifyX509Type

	// RemoteCertKU specifies the required Key Usage bits for the server certificate.
	// Multiple values are allowed; the certificate must match at least one.
	// Corresponds to OpenVPN's --remote-cert-ku option.
	RemoteCertKU []KeyUsage

	// RemoteCertEKU specifies the required Extended Key Usage OID or name for the server certificate.
	// Example values: "serverAuth", "TLS Web Server Authentication", "1.3.6.1.5.5.7.3.1"
	// Corresponds to OpenVPN's --remote-cert-eku option.
	RemoteCertEKU string
}

// ReadConfigFile expects a string with a path to a valid config file,
// and returns a pointer to a Options struct after parsing the file, and an
// error if the operation could not be completed.
func ReadConfigFile(filePath string) (*OpenVPNOptions, error) {
	lines, err := getLinesFromFile(filePath)
	dir, _ := filepath.Split(filePath)
	if err != nil {
		return nil, err
	}
	return getOptionsFromLines(lines, dir)
}

// HasAuthInfo returns true if:
// - we have inline byte arrays for cert, key and ca; or
// - we have username + password + ca info.
// TODO(ainghazal): add sanity checks for valid/existing credentials.
func (o *OpenVPNOptions) HasAuthInfo() bool {
	if len(o.CA) == 0 {
		return false
	}
	if o.AuthUserPass {
		return o.Username != "" && o.Password != ""
	}
	if len(o.Cert) != 0 && len(o.Key) != 0 {
		return true
	}
	if o.Username != "" && o.Password != "" {
		return true
	}
	return false
}

// clientOptions is the options line we're passing to the OpenVPN server during the handshake.
const clientOptions = "V4,dev-type tun,link-mtu 1601,tun-mtu 1500,proto %s,cipher %s,auth %s,keysize %s,key-method 2,tls-client"

// ServerOptionsString produces a comma-separated representation of the options, in the same
// order and format that the OpenVPN server expects from us.
func (o *OpenVPNOptions) ServerOptionsString() string {
	if o.Cipher == "" {
		return ""
	}
	// TODO(ainghazal): this line of code crashes if the ciphers are not well formed
	keysize := strings.Split(o.Cipher, "-")[1]
	proto := "UDPv4"
	switch o.Proto {
	case ProtoTCP, ProtoTCP4:
		proto = "TCPv4"
	case ProtoTCP6:
		proto = "TCPv6"
	case ProtoUDP, ProtoUDP4:
		proto = "UDPv4"
	case ProtoUDP6:
		proto = "UDPv6"
	default:
		proto = strings.ToUpper(o.Proto.String())
	}
	s := fmt.Sprintf(clientOptions, proto, o.Cipher, o.Auth, keysize)
	if o.Compress == CompressionStub {
		s = s + ",compress stub"
	} else if o.Compress == "lzo-no" {
		s = s + ",lzo-comp no"
	} else if o.Compress == CompressionEmpty {
		s = s + ",compress"
	}
	return s
}

func parseProto(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "proto needs one arg")
	}
	m := strings.ToLower(p[0])
	switch m {
	case "udp":
		o.Proto = ProtoUDP
	case "udp4":
		o.Proto = ProtoUDP4
	case "udp6":
		o.Proto = ProtoUDP6
	case "tcp", "tcp-client":
		o.Proto = ProtoTCP
	case "tcp4", "tcp4-client":
		o.Proto = ProtoTCP4
	case "tcp6", "tcp6-client":
		o.Proto = ProtoTCP6
	case "tcp-server", "tcp4-server", "tcp6-server":
		return o, fmt.Errorf("%w: unsupported proto (server mode): %s", ErrBadConfig, m)
	default:
		return o, fmt.Errorf("%w: bad proto: %s", ErrBadConfig, m)

	}
	return o, nil
}

func parseRemote(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 2 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "remote needs two args")
	}
	o.Remote, o.Port = p[0], p[1]
	return o, nil
}

func parseCipher(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "cipher expects one arg")
	}
	cipher := p[0]
	if !hasElement(cipher, SupportedCiphers) {
		return o, fmt.Errorf("%w: unsupported cipher: %s", ErrBadConfig, cipher)
	}
	o.Cipher = cipher
	return o, nil
}

func parseAuth(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "invalid auth entry")
	}
	auth := p[0]
	if !hasElement(auth, SupportedAuth) {
		return o, fmt.Errorf("%w: unsupported auth: %s", ErrBadConfig, auth)
	}
	o.Auth = auth
	return o, nil
}

func setKeyDirection(o *OpenVPNOptions, dir int) error {
	if dir != 0 && dir != 1 {
		return fmt.Errorf("%w: key-direction must be 0 or 1", ErrBadConfig)
	}
	if o.KeyDirection != nil && *o.KeyDirection != dir {
		return fmt.Errorf("%w: conflicting key-direction values", ErrBadConfig)
	}
	if o.KeyDirection == nil {
		o.KeyDirection = new(int)
	}
	*o.KeyDirection = dir
	return nil
}

func parseKeyDirection(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "key-direction expects one arg")
	}
	dir, err := strconv.Atoi(p[0])
	if err != nil {
		return o, fmt.Errorf("%w: key-direction must be 0 or 1", ErrBadConfig)
	}
	if err := setKeyDirection(o, dir); err != nil {
		return o, err
	}
	return o, nil
}

func parseCA(p []string, o *OpenVPNOptions, basedir string) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "ca expects one arg")
	}
	return o, fmt.Errorf("%w: %s", ErrBadConfig, "ca file paths are not supported; embed <ca>...</ca> in the .ovpn file")
}

func parseCert(p []string, o *OpenVPNOptions, basedir string) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "cert expects one arg")
	}
	return o, fmt.Errorf("%w: %s", ErrBadConfig, "cert file paths are not supported; embed <cert>...</cert> in the .ovpn file")
}

func parseKey(p []string, o *OpenVPNOptions, basedir string) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "key expects one arg")
	}
	return o, fmt.Errorf("%w: %s", ErrBadConfig, "key file paths are not supported; embed <key>...</key> in the .ovpn file")
}

func parseTLSAuth(p []string, o *OpenVPNOptions, basedir string) (*OpenVPNOptions, error) {
	if len(p) == 0 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "tls-auth expects at least one arg")
	}
	if len(p) == 1 {
		if strings.EqualFold(p[0], "inline") {
			return o, nil
		}
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "tls-auth file paths are not supported; embed <tls-auth>...</tls-auth> in the .ovpn file")
	}
	if len(p) == 2 {
		if !strings.EqualFold(p[0], "inline") {
			return o, fmt.Errorf("%w: %s", ErrBadConfig, "tls-auth file paths are not supported; use tls-auth inline <direction>")
		}
		dir, err := strconv.Atoi(p[1])
		if err != nil {
			return o, fmt.Errorf("%w: tls-auth direction must be 0 or 1", ErrBadConfig)
		}
		if err := setKeyDirection(o, dir); err != nil {
			return o, err
		}
		return o, nil
	}
	return o, fmt.Errorf("%w: %s", ErrBadConfig, "tls-auth expects at most two args")
}

func parseTLSCrypt(p []string, o *OpenVPNOptions, basedir string) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "tls-crypt expects one arg")
	}
	return o, fmt.Errorf("%w: %s", ErrBadConfig, "tls-crypt file paths are not supported; embed <tls-crypt>...</tls-crypt> in the .ovpn file")
}

func parseTLSCryptV2(p []string, o *OpenVPNOptions, basedir string) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "tls-crypt-v2 expects one arg")
	}
	return o, fmt.Errorf("%w: %s", ErrBadConfig, "tls-crypt-v2 file paths are not supported; embed <tls-crypt-v2>...</tls-crypt-v2> in the .ovpn file")
}

// parseAuthUser parses the auth-user-pass directive.
//
// We explicitly reject external credential files: credentials must be provided
// via the <auth-user-pass>...</auth-user-pass> inline block or via the caller
// configuration (e.g., Clash username/password).
func parseAuthUser(p []string, o *OpenVPNOptions, basedir string) (*OpenVPNOptions, error) {
	o.AuthUserPass = true
	if len(p) == 0 {
		return o, nil
	}
	return o, fmt.Errorf("%w: %s", ErrBadConfig, "auth-user-pass file paths are not supported; embed <auth-user-pass>...</auth-user-pass> in the .ovpn file or configure username/password")
}

func parseCompress(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) > 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "compress: only empty/stub options supported")
	}
	if len(p) == 0 {
		o.Compress = CompressionEmpty
		return o, nil
	}
	if p[0] == "stub" {
		o.Compress = CompressionStub
		return o, nil
	}
	return o, fmt.Errorf("%w: %s", ErrBadConfig, "compress: only empty/stub options supported")
}

func parseCompLZO(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if p[0] != "no" {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "comp-lzo: compression not supported")
	}
	o.Compress = "lzo-no"
	return o, nil
}

// parseTLSVerMax sets the maximum TLS version. This is currently ignored
// because we're using uTLS to parrot the Client Hello.
func parseTLSVerMax(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) == 0 {
		o.TLSMaxVer = "1.3"
		return o, nil
	}
	log.Printf("warn: tls-version-max %s is ignored (uTLS manages TLS version)", p[0])
	if p[0] == "1.2" {
		o.TLSMaxVer = "1.2"
	}
	return o, nil
}

func parseProxyOBFS4(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "proto-obfs4: need a properly configured proxy")
	}
	// TODO(ainghazal): can validate the obfs4://... scheme here
	o.ProxyOBFS4 = p[0]
	return o, nil
}

func parseFragment(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "fragment expects one arg")
	}
	size, err := strconv.Atoi(p[0])
	if err != nil {
		return o, fmt.Errorf("%w: fragment: invalid size: %s", ErrBadConfig, p[0])
	}
	if size < 68 || size > 65535 {
		return o, fmt.Errorf("%w: fragment: size must be between 68 and 65535", ErrBadConfig)
	}
	o.Fragment = size
	return o, nil
}

// parseRenegSec parses the --reneg-sec option.
// Syntax: reneg-sec max [min]
// We only support the max value; min is ignored (used by servers for randomization).
func parseRenegSec(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) == 0 || len(p) > 2 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "reneg-sec expects one or two args")
	}
	seconds, err := strconv.Atoi(p[0])
	if err != nil || seconds < 0 {
		return o, fmt.Errorf("%w: reneg-sec: invalid value: %s", ErrBadConfig, p[0])
	}
	o.RenegotiateSeconds = seconds
	// Note: p[1] (min) is ignored for clients; servers use it for randomization
	return o, nil
}

// parseRenegBytes parses the --reneg-bytes option.
func parseRenegBytes(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "reneg-bytes expects one arg")
	}
	bytes, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil || bytes < 0 {
		return o, fmt.Errorf("%w: reneg-bytes: invalid value: %s", ErrBadConfig, p[0])
	}
	o.RenegotiateBytes = bytes
	return o, nil
}

// parseRenegPkts parses the --reneg-pkts option.
func parseRenegPkts(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "reneg-pkts expects one arg")
	}
	pkts, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil || pkts < 0 {
		return o, fmt.Errorf("%w: reneg-pkts: invalid value: %s", ErrBadConfig, p[0])
	}
	o.RenegotiatePackets = pkts
	return o, nil
}

// parseTransitionWindow parses the --transition-window option.
// This sets how long a lame duck key stays alive after soft reset.
func parseTransitionWindow(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "transition-window expects one arg")
	}
	seconds, err := strconv.Atoi(p[0])
	if err != nil || seconds < 0 {
		return o, fmt.Errorf("%w: transition-window: invalid value: %s", ErrBadConfig, p[0])
	}
	o.TransitionWindow = seconds
	return o, nil
}

// parsePing parses the --ping option.
func parsePing(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "ping expects one arg")
	}
	seconds, err := strconv.Atoi(p[0])
	if err != nil || seconds < 0 {
		return o, fmt.Errorf("%w: ping: invalid value: %s", ErrBadConfig, p[0])
	}
	o.Ping = seconds
	return o, nil
}

// parsePingRestart parses the --ping-restart option.
func parsePingRestart(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "ping-restart expects one arg")
	}
	seconds, err := strconv.Atoi(p[0])
	if err != nil || seconds < 0 {
		return o, fmt.Errorf("%w: ping-restart: invalid value: %s", ErrBadConfig, p[0])
	}
	o.PingRestart = seconds
	return o, nil
}

// parsePingExit parses the --ping-exit option.
func parsePingExit(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "ping-exit expects one arg")
	}
	seconds, err := strconv.Atoi(p[0])
	if err != nil || seconds < 0 {
		return o, fmt.Errorf("%w: ping-exit: invalid value: %s", ErrBadConfig, p[0])
	}
	o.PingExit = seconds
	return o, nil
}

// parseKeepalive parses the --keepalive option (macro for ping + ping-restart).
func parseKeepalive(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 2 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "keepalive expects two args (interval timeout)")
	}
	interval, err := strconv.Atoi(p[0])
	if err != nil || interval < 0 {
		return o, fmt.Errorf("%w: keepalive: invalid interval: %s", ErrBadConfig, p[0])
	}
	timeout, err := strconv.Atoi(p[1])
	if err != nil || timeout < 0 {
		return o, fmt.Errorf("%w: keepalive: invalid timeout: %s", ErrBadConfig, p[1])
	}
	o.Ping = interval
	o.PingRestart = timeout
	return o, nil
}

// parseHandWindow parses the --hand-window option.
func parseHandWindow(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "hand-window expects one arg")
	}
	seconds, err := strconv.Atoi(p[0])
	if err != nil || seconds < 0 {
		return o, fmt.Errorf("%w: hand-window: invalid value: %s", ErrBadConfig, p[0])
	}
	o.HandshakeWindow = seconds
	return o, nil
}

// parseVerifyX509Name parses the --verify-x509-name option.
// Syntax: verify-x509-name name [type]
// type can be: subject (default), name, name-prefix
func parseVerifyX509Name(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) == 0 || len(p) > 2 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "verify-x509-name expects 1 or 2 args")
	}
	if p[0] == "" {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "verify-x509-name: name cannot be empty")
	}

	o.VerifyX509Name = p[0]
	o.VerifyX509Type = VerifyX509SubjectDN // default

	if len(p) == 2 {
		switch strings.ToLower(p[1]) {
		case "subject":
			o.VerifyX509Type = VerifyX509SubjectDN
		case "name":
			o.VerifyX509Type = VerifyX509SubjectRDN
		case "name-prefix":
			o.VerifyX509Type = VerifyX509SubjectRDNPrefix
		default:
			return o, fmt.Errorf("%w: verify-x509-name: unknown type: %s", ErrBadConfig, p[1])
		}
	}
	return o, nil
}

// parseRemoteCertKU parses the --remote-cert-ku option.
// Syntax: remote-cert-ku ku1 [ku2 ...]
// Each ku is a hexadecimal Key Usage value (e.g., 80, a0, 88).
// The certificate must match at least one of the specified values.
func parseRemoteCertKU(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) == 0 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "remote-cert-ku expects at least one arg")
	}

	for _, kuStr := range p {
		// Parse hexadecimal value (OpenVPN uses hex format)
		kuVal, err := strconv.ParseUint(kuStr, 16, 16)
		if err != nil {
			return o, fmt.Errorf("%w: remote-cert-ku: invalid hex value: %s", ErrBadConfig, kuStr)
		}
		o.RemoteCertKU = append(o.RemoteCertKU, KeyUsage(kuVal))
	}
	return o, nil
}

// parseRemoteCertEKU parses the --remote-cert-eku option.
// Syntax: remote-cert-eku oid
// oid can be a dotted OID (e.g., 1.3.6.1.5.5.7.3.1) or a name (e.g., "serverAuth").
func parseRemoteCertEKU(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "remote-cert-eku expects one arg")
	}
	if p[0] == "" {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "remote-cert-eku: oid cannot be empty")
	}
	o.RemoteCertEKU = p[0]
	return o, nil
}

// parseRemoteCertTLS parses the --remote-cert-tls option.
// Syntax: remote-cert-tls server|client
// This is a convenience option that sets --remote-cert-eku to the appropriate TLS EKU.
func parseRemoteCertTLS(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	if len(p) != 1 {
		return o, fmt.Errorf("%w: %s", ErrBadConfig, "remote-cert-tls expects one arg (server or client)")
	}
	switch strings.ToLower(p[0]) {
	case "server":
		// TLS Web Server Authentication (OID 1.3.6.1.5.5.7.3.1)
		o.RemoteCertEKU = "serverAuth"
	case "client":
		// TLS Web Client Authentication (OID 1.3.6.1.5.5.7.3.2)
		o.RemoteCertEKU = "clientAuth"
	default:
		return o, fmt.Errorf("%w: remote-cert-tls: must be 'server' or 'client', got: %s", ErrBadConfig, p[0])
	}
	return o, nil
}

func parseAuthNoCache(p []string, o *OpenVPNOptions) (*OpenVPNOptions, error) {
	o.AuthNoCache = true
	return o, nil
}

var pMap = map[string]interface{}{
	"proto":             parseProto,
	"remote":            parseRemote,
	"cipher":            parseCipher,
	"auth":              parseAuth,
	"key-direction":     parseKeyDirection,
	"compress":          parseCompress,
	"comp-lzo":          parseCompLZO,
	"proxy-obfs4":       parseProxyOBFS4,
	"tls-version-max":   parseTLSVerMax, // this is currently ignored because of uTLS
	"fragment":          parseFragment,
	"reneg-sec":         parseRenegSec,
	"reneg-bytes":       parseRenegBytes,
	"reneg-pkts":        parseRenegPkts,
	"transition-window": parseTransitionWindow,
	"ping":              parsePing,
	"ping-restart":      parsePingRestart,
	"ping-exit":         parsePingExit,
	"keepalive":         parseKeepalive,
	"hand-window":       parseHandWindow,
	"verify-x509-name":  parseVerifyX509Name,
	"auth-nocache":      parseAuthNoCache,
	"remote-cert-ku":    parseRemoteCertKU,
	"remote-cert-eku":   parseRemoteCertEKU,
	"remote-cert-tls":   parseRemoteCertTLS,
}

var pMapDir = map[string]interface{}{
	"ca":             parseCA,
	"cert":           parseCert,
	"key":            parseKey,
	"tls-auth":       parseTLSAuth,
	"tls-crypt":      parseTLSCrypt,
	"tls-crypt-v2":   parseTLSCryptV2,
	"auth-user-pass": parseAuthUser,
}

func parseOption(opt *OpenVPNOptions, dir, key string, p []string, lineno int) (*OpenVPNOptions, error) {
	switch key {
	case "proto", "remote", "cipher", "auth", "key-direction", "compress", "comp-lzo", "tls-version-max", "proxy-obfs4", "fragment", "reneg-sec", "reneg-bytes", "reneg-pkts", "transition-window", "ping", "ping-restart", "ping-exit", "keepalive", "hand-window", "verify-x509-name", "auth-nocache", "remote-cert-ku", "remote-cert-eku", "remote-cert-tls":
		fn := pMap[key].(func([]string, *OpenVPNOptions) (*OpenVPNOptions, error))
		if updatedOpt, e := fn(p, opt); e != nil {
			return updatedOpt, e
		}
	case "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "auth-user-pass":
		fn := pMapDir[key].(func([]string, *OpenVPNOptions, string) (*OpenVPNOptions, error))
		if updatedOpt, e := fn(p, opt, dir); e != nil {
			return updatedOpt, e
		}
	default:
		log.Printf("warn: unsupported key in line %d\n", lineno)
	}
	return opt, nil
}

// getOptionsFromLines tries to parse all the lines coming from a config file
// and raises validation errors if the values do not conform to the expected
// format. The config file supports inline file inclusion for <ca>, <cert> and <key>.
func getOptionsFromLines(lines []string, dir string) (*OpenVPNOptions, error) {
	opt := &OpenVPNOptions{
		Remote:             "",
		Port:               "",
		Proto:              ProtoUDP,
		Username:           "",
		Password:           "",
		CA:                 []byte{},
		Cert:               []byte{},
		Key:                []byte{},
		TLSAuth:            []byte{},
		TLSCrypt:           []byte{},
		TLSCryptV2:         []byte{},
		Cipher:             "",
		Auth:               "",
		TLSMaxVer:          "",
		Compress:           CompressionEmpty,
		ProxyOBFS4:         "",
		RenegotiateSeconds: DefaultRenegotiateSeconds,
		RenegotiateBytes:   DefaultRenegotiateBytes,
		RenegotiatePackets: 0, // disabled by default
		TransitionWindow:   DefaultTransitionWindow,
		HandshakeWindow:    DefaultHandshakeWindow,
	}

	// tag and inlineBuf are used to parse inline files.
	// these follow the format used by the reference openvpn implementation.
	// each block (e.g., ca, key, cert, tls-auth, tls-crypt) is marked by a
	// <option> line and closed by a </option> line; lines in between are
	// expected to contain the crypto block.
	tag := ""
	inlineBuf := new(bytes.Buffer)

	for lineno, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}

		// inline certs
		if isClosingTag(l) {
			// we expect an already existing inlineBuf
			e := parseInlineTag(opt, tag, inlineBuf)
			if e != nil {
				return nil, e
			}
			tag = ""
			inlineBuf = new(bytes.Buffer)
			continue
		}
		if tag != "" {
			inlineBuf.Write([]byte(l))
			inlineBuf.Write([]byte("\n"))
			continue
		}
		if isOpeningTag(l) {
			if len(inlineBuf.Bytes()) != 0 {
				// something wrong: an opening tag should not be found
				// when we still have bytes in the inline buffer.
				return opt, fmt.Errorf("%w: %s", ErrBadConfig, "tag not closed")
			}
			tag = parseTag(l)
			continue
		}

		// comments
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}

		// parse parts in the same line
		p := strings.Fields(l)
		if len(p) == 0 {
			continue
		}
		var (
			key   string
			parts []string
		)
		if len(p) == 1 {
			key = p[0]
		} else {
			key, parts = p[0], p[1:]
		}
		var err error
		opt, err = parseOption(opt, dir, key, parts, lineno)
		if err != nil {
			return nil, err
		}
	}

	// Validate option combinations (matching OpenVPN behavior)
	// --fragment can only be used with --proto udp
	if opt.Proto.IsTCP() && opt.Fragment > 0 {
		return nil, fmt.Errorf("%w: --fragment can only be used with --proto udp", ErrBadConfig)
	}

	return opt, nil
}

func isOpeningTag(key string) bool {
	switch key {
	case "<ca>", "<cert>", "<key>", "<tls-auth>", "<tls-crypt>", "<tls-crypt-v2>", "<auth-user-pass>":
		return true
	default:
		return false
	}
}

func isClosingTag(key string) bool {
	switch key {
	case "</ca>", "</cert>", "</key>", "</tls-auth>", "</tls-crypt>", "</tls-crypt-v2>", "</auth-user-pass>":
		return true
	default:
		return false
	}
}

func parseTag(tag string) string {
	switch tag {
	case "<ca>", "</ca>":
		return "ca"
	case "<cert>", "</cert>":
		return "cert"
	case "<key>", "</key>":
		return "key"
	case "<tls-auth>", "</tls-auth>":
		return "tls-auth"
	case "<tls-crypt>", "</tls-crypt>":
		return "tls-crypt"
	case "<tls-crypt-v2>", "</tls-crypt-v2>":
		return "tls-crypt-v2"
	case "<auth-user-pass>", "</auth-user-pass>":
		return "auth-user-pass"
	default:
		return ""
	}
}

// parseInlineTag
func parseInlineTag(o *OpenVPNOptions, tag string, buf *bytes.Buffer) error {
	b := buf.Bytes()
	if len(b) == 0 {
		return fmt.Errorf("%w: empty inline tag: %d", ErrBadConfig, len(b))
	}
	switch tag {
	case "ca":
		o.CA = b
	case "cert":
		o.Cert = b
	case "key":
		o.Key = b
	case "tls-auth":
		o.TLSAuth = b
	case "tls-crypt":
		o.TLSCrypt = b
	case "tls-crypt-v2":
		o.TLSCryptV2 = b
	case "auth-user-pass":
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) < 2 {
			return fmt.Errorf("%w: auth-user-pass expects at least two lines", ErrBadConfig)
		}
		o.Username = strings.TrimSpace(lines[0])
		o.Password = strings.TrimSpace(lines[1])
		if o.Username == "" || o.Password == "" {
			return fmt.Errorf("%w: auth-user-pass expects non-empty username and password", ErrBadConfig)
		}
		o.AuthUserPass = true
	default:
		return fmt.Errorf("%w: unknown tag: %s", ErrBadConfig, tag)
	}
	return nil
}

// hasElement checks if a given string is present in a string array. returns
// true if that is the case, false otherwise.
func hasElement(el string, arr []string) bool {
	for _, v := range arr {
		if v == el {
			return true
		}
	}
	return false
}

// existsFile returns true if the file to which the path refers to exists and
// is a regular file.
func existsFile(path string) bool {
	statbuf, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist) && statbuf.Mode().IsRegular()
}

func mustClose(c io.Closer) {
	err := c.Close()
	runtimex.PanicOnError(err, "could not close")
}

// getLinesFromFile accepts a path parameter, and return a string array with
// its content and an error if the operation cannot be completed.
func getLinesFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer mustClose(f)

	lines := make([]string, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}
	return lines, nil
}

// getCredentialsFromFile accepts a path string parameter, and return a string
// array containing the credentials in that file, and an error if the operation
// could not be completed.
func getCredentialsFromFile(path string) ([]string, error) {
	lines, err := getLinesFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, err)
	}
	if len(lines) != 2 {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, "malformed credentials file")
	}
	if len(lines[0]) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, "empty username in creds file")
	}
	if len(lines[1]) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, "empty password in creds file")
	}
	return lines, nil
}

// toAbs return an absolute path if the given path is not already absolute; to
// do so, it will append the path to the given basedir.
func toAbs(path, basedir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(basedir, path)
}

// isSubdir checks if a given path is a subdirectory of another. It returns
// true if that's the case, and any error raise during the check.
func isSubdir(parent, sub string) (bool, error) {
	p, err := filepath.Abs(parent)
	if err != nil {
		return false, err
	}
	s, err := filepath.Abs(sub)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(s, p), nil
}
