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

var pMap = map[string]interface{}{
	"proto":           parseProto,
	"remote":          parseRemote,
	"cipher":          parseCipher,
	"auth":            parseAuth,
	"key-direction":   parseKeyDirection,
	"compress":        parseCompress,
	"comp-lzo":        parseCompLZO,
	"proxy-obfs4":     parseProxyOBFS4,
	"tls-version-max": parseTLSVerMax, // this is currently ignored because of uTLS
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
	case "proto", "remote", "cipher", "auth", "key-direction", "compress", "comp-lzo", "tls-version-max", "proxy-obfs4":
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
		Remote:     "",
		Port:       "",
		Proto:      ProtoTCP,
		Username:   "",
		Password:   "",
		CA:         []byte{},
		Cert:       []byte{},
		Key:        []byte{},
		TLSAuth:    []byte{},
		TLSCrypt:   []byte{},
		TLSCryptV2: []byte{},
		Cipher:     "",
		Auth:       "",
		TLSMaxVer:  "",
		Compress:   CompressionEmpty,
		ProxyOBFS4: "",
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
