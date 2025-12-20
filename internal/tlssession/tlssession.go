package tlssession

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"

	tls "github.com/refraction-networking/utls"
)

var (
	serviceName = "tlssession"

	// ErrNoPushReply is returned when the server does not send PUSH_REPLY within
	// the expected time window.
	ErrNoPushReply = errors.New("no reply from server to push requests")
)

// Service is the tlssession service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// NotifyTLS is a channel where we receive incoming notifications.
	NotifyTLS chan *model.Notification

	// KeyUP is used to send newly negotiated data channel keys ready to be
	// used.
	KeyUp *chan *session.DataChannelKey

	// TLSRecordUp is data coming up from the control channel layer to us.
	// TODO(ainghazal): considere renaming when we have merged the whole
	// set of components. This name might not give a good idea of what the bytes being
	// moved around are - this is a serialized control channel packet, which is
	// mainly used to do the initial handshake and then receive control
	// packets encrypted with this TLS session.
	TLSRecordUp chan []byte

	// TLSRecordDown is data being transferred down from us to the control
	// channel.
	TLSRecordDown *chan []byte
}

// StartWorkers starts the tlssession workers. See the [ARCHITECTURE]
// file for more information about the packet-muxer workers.
//
// [ARCHITECTURE]: https://github.com/ooni/minivpn/blob/main/ARCHITECTURE.md
func (svc *Service) StartWorkers(
	config *config.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		keyUp:          *svc.KeyUp,
		logger:         config.Logger(),
		notifyTLS:      svc.NotifyTLS,
		options:        config.OpenVPNOptions(),
		tlsRecordDown:  *svc.TLSRecordDown,
		tlsRecordUp:    svc.TLSRecordUp,
		sessionManager: sessionManager,
		workersManager: workersManager,
	}
	workersManager.StartWorker(ws.worker)
}

// workersState contains the control channel state.
type workersState struct {
	logger         model.Logger
	notifyTLS      <-chan *model.Notification
	options        *config.OpenVPNOptions
	tlsRecordDown  chan<- []byte
	tlsRecordUp    <-chan []byte
	keyUp          chan<- *session.DataChannelKey
	sessionManager *session.Manager
	workersManager *workers.Manager
}

// worker is the main loop of the tlssession
func (ws *workersState) worker() {
	workerName := fmt.Sprintf("%s: worker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)
	for {
		select {
		case notif := <-ws.notifyTLS:
			if (notif.Flags & model.NotificationReset) != 0 {
				if err := ws.tlsAuth(); err != nil {
					if errors.Is(err, workers.ErrShutdown) {
						return
					}

					// If we don't have a working data channel yet, a TLS session
					// failure is unrecoverable and we must fail fast, otherwise
					// StartTUN will just time out with a generic context error.
					if ws.sessionManager.NegotiationState() < model.S_GENERATED_KEYS {
						select {
						case ws.sessionManager.Failure <- err:
						default:
						}
						return
					}

					// If we already have keys (e.g., during soft reset / key
					// rotation), keep the existing session alive and just warn.
					ws.logger.Warnf("%s: %s", workerName, err.Error())
				}
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// tlsAuth runs the TLS auth algorithm
func (ws *workersState) tlsAuth() error {
	// create the BIO to use channels as a socket
	conn := newTLSBio(ws.logger, ws.tlsRecordUp, ws.tlsRecordDown)
	defer conn.Close()

	// we construct the certCfg from options, that has access to the certificate material
	certCfg, err := newCertConfigFromOptions(ws.options)
	if err != nil {
		return err
	}

	// tlsConf is a tls.Config obtained from our own initialization function
	tlsConf, err := initTLSFn(certCfg)
	if err != nil {
		return err
	}

	// run the real algorithm in a background goroutine
	errorch := make(chan error)
	go ws.doTLSAuth(conn, tlsConf, errorch)

	select {
	case err := <-errorch:
		return err

	case <-ws.workersManager.ShouldShutdown():
		return workers.ErrShutdown
	}
}

// doTLSAuth is the internal implementation of tlsAuth such that tlsAuth
// can interrupt this function early if needed.
func (ws *workersState) doTLSAuth(conn net.Conn, config *tls.Config, errorch chan<- error) {
	ws.logger.Debug("tlsession: doTLSAuth: started")
	defer ws.logger.Debug("tlssession: doTLSAuth: done")

	// do the TLS handshake
	tlsConn, err := tlsHandshakeFn(conn, config)
	if err != nil {
		errorch <- err
		return
	}
	ws.logger.Debug("tlssession: TLS handshake completed")
	// In case you're wondering why we don't need to close the conn:
	// we don't care since the underlying conn is a tlsBio
	// defer tlsConn.Close()

	// we need the active key to create the first control message
	activeKey, err := ws.sessionManager.ActiveKey()
	if err != nil {
		errorch <- err
		return
	}

	// send the first control message with random material
	if err := ws.sendAuthRequestMessage(tlsConn, activeKey); err != nil {
		errorch <- err
		return
	}
	ws.sessionManager.SetNegotiationState(model.S_SENT_KEY)

	// read the server's keySource and options
	remoteKey, serverOptions, err := ws.recvAuthReplyMessage(tlsConn)
	if err != nil {
		errorch <- err
		return
	}
	ws.logger.Debugf("Remote options: %s", serverOptions)

	// init the tunnel info
	if err := ws.sessionManager.InitTunnelInfo(serverOptions); err != nil {
		errorch <- err
		return
	}

	// add the remote key to the active key
	activeKey.AddRemoteKey(remoteKey)
	ws.sessionManager.SetNegotiationState(model.S_GOT_KEY)

	// Send PUSH_REQUEST and keep retrying until we receive PUSH_REPLY.
	// The reference OpenVPN client periodically resends PUSH_REQUEST, because
	// some servers defer the push-reply until the connection is fully ready.
	const (
		pushRequestInterval = 5 * time.Second
		pushReplyTimeout    = 55 * time.Second
	)

	if err := ws.sendPushRequestMessage(tlsConn); err != nil {
		errorch <- err
		return
	}

	stopPushRequests := make(chan struct{})
	pushTimeout := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(pushRequestInterval)
		defer ticker.Stop()

		deadline := time.NewTimer(pushReplyTimeout)
		defer deadline.Stop()

		attempt := 1
		for {
			select {
			case <-ticker.C:
				attempt++
				ws.logger.Debugf("tlssession: resend push request attempt=%d", attempt)
				if err := ws.sendPushRequestMessage(tlsConn); err != nil {
					ws.logger.Warnf("tlssession: resend push request: %v", err)
				}
			case <-deadline.C:
				pushTimeout <- fmt.Errorf("%w after %s (%d requests)", ErrNoPushReply, pushReplyTimeout, attempt)
				_ = tlsConn.Close()
				return
			case <-stopPushRequests:
				return
			}
		}
	}()

	tinfo, err := ws.recvPushResponseMessage(tlsConn)
	close(stopPushRequests)
	if err != nil {
		select {
		case perr := <-pushTimeout:
			err = perr
		default:
		}
		errorch <- err
		return
	}

	// update with extra information obtained from push response
	ws.sessionManager.UpdateTunnelInfo(tinfo)

	// progress to the ACTIVE state
	ws.sessionManager.SetNegotiationState(model.S_ACTIVE)

	// notify the datachannel that we've got a key pair ready to use
	ws.keyUp <- activeKey

	errorch <- nil
}

// sendAuthRequestMessage sends the auth request message
func (ws *workersState) sendAuthRequestMessage(tlsConn net.Conn, activeKey *session.DataChannelKey) error {
	// this message is sending our options and asking the server to get AUTH
	ctrlMsg, err := encodeClientControlMessageAsBytes(activeKey.Local(), ws.options)
	if err != nil {
		return err
	}
	ws.logger.Debugf(
		"tlssession: send auth request len=%d head=%s",
		len(ctrlMsg),
		bytesx.HexPrefix(ctrlMsg, 32),
	)

	// let's fire off the message
	_, err = tlsConn.Write(ctrlMsg)
	return err
}

// recvAuthReplyMessage reads and parses the first control response.
func (ws *workersState) recvAuthReplyMessage(conn net.Conn) (*session.KeySource, string, error) {
	// read raw bytes
	buffer := make([]byte, 1<<17)
	count, err := conn.Read(buffer)
	if err != nil {
		return nil, "", err
	}
	data := buffer[:count]
	ws.logger.Debugf(
		"tlssession: auth reply len=%d head=%s",
		len(data),
		bytesx.HexPrefix(data, 32),
	)

	// parse what we received
	return parseServerControlMessage(data)
}

// sendPushRequestMessage sends the push request message
func (ws *workersState) sendPushRequestMessage(conn net.Conn) error {
	data := append([]byte("PUSH_REQUEST"), 0x00)
	ws.logger.Debugf(
		"tlssession: send push request len=%d head=%s",
		len(data),
		bytesx.HexPrefix(data, 32),
	)
	_, err := conn.Write(data)
	return err
}

type controlMessageReader struct {
	pending []byte
}

func (r *controlMessageReader) readNext(conn net.Conn, scratch []byte) ([]byte, error) {
	for {
		if idx := bytes.IndexByte(r.pending, 0x00); idx >= 0 {
			msg := r.pending[:idx+1]
			r.pending = r.pending[idx+1:]
			return msg, nil
		}
		n, err := conn.Read(scratch)
		if err != nil {
			return nil, err
		}
		r.pending = append(r.pending, scratch[:n]...)
	}
}

// recvPushResponseMessage receives and parses the push response message.
func (ws *workersState) recvPushResponseMessage(conn net.Conn) (*model.TunnelInfo, error) {
	reader := &controlMessageReader{}
	scratch := make([]byte, 1<<12) // avoid large allocations while looping

	for {
		msg, err := reader.readNext(conn, scratch)
		if err != nil {
			return nil, err
		}
		if len(msg) == 0 {
			continue
		}

		ws.logger.Debugf(
			"tlssession: control msg len=%d head=%s",
			len(msg),
			bytesx.HexPrefix(msg, 32),
		)

		// We only need PUSH_REPLY; ignore other messages until we get it.
		switch {
		case bytes.HasPrefix(msg, serverBadAuth):
			return nil, errBadAuth
		case bytes.HasPrefix(msg, serverPushReply):
			optsMap := pushedOptionsAsMap(msg)
			ws.logger.Infof("Server pushed options: %v", optsMap)
			ws.applyPushedCipher(optsMap)
			return newTunnelInfoFromPushedOptions(optsMap), nil
		case bytes.HasPrefix(msg, []byte("AUTH_PENDING")):
			ws.logger.Debugf("tlssession: received AUTH_PENDING, waiting for PUSH_REPLY")
		case bytes.HasPrefix(msg, []byte("INFO_PRE")):
			ws.logger.Debugf("tlssession: received INFO_PRE, waiting for PUSH_REPLY")
		default:
			ws.logger.Debugf("tlssession: ignoring control msg, waiting for PUSH_REPLY")
		}
	}
}

func (ws *workersState) applyPushedCipher(opts remoteOptions) {
	cipher := ""
	if v, ok := opts["cipher"]; ok && len(v) >= 1 {
		cipher = strings.TrimSpace(v[0])
	}
	if cipher == "" || ws.options == nil {
		return
	}

	canonical, ok := canonicalSupportedCipher(cipher)
	if !ok {
		ws.logger.Warnf("Ignoring unsupported PUSH_REPLY cipher: %q", cipher)
		return
	}
	if ws.options.Cipher == canonical {
		return
	}
	ws.logger.Infof("Negotiated data cipher: %s (from PUSH_REPLY, was %s)", canonical, ws.options.Cipher)
	ws.options.Cipher = canonical
}

func canonicalSupportedCipher(cipher string) (string, bool) {
	for _, supported := range config.SupportedCiphers {
		if strings.EqualFold(supported, cipher) {
			return supported, true
		}
	}
	return "", false
}
