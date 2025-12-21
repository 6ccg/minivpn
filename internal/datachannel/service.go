package datachannel

//
// OpenVPN data channel
//

import (
	"fmt"
	"sync"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/internal/workers"
	"github.com/ooni/minivpn/pkg/config"
)

var (
	serviceName = "datachannel"
)

// Service is the datachannel service. Make sure you initialize
// the channels before invoking [Service.StartWorkers].
type Service struct {
	// MuxerToData moves packets up to us
	MuxerToData chan *model.Packet

	// DataOrControlToMuxer is a shared channel to write packets to the muxer layer below
	DataOrControlToMuxer *chan *model.Packet

	// TUNToData moves bytes down from the TUN layer above
	TUNToData chan []byte

	// DataToTUN moves bytes up from us to the TUN layer above us
	DataToTUN chan []byte

	// KeyReady is where the TLSState layer passes us any new keys
	KeyReady chan *session.DataChannelKey
}

// StartWorkers starts the data-channel workers.
//
// We start three workers:
//
// 1. moveUpWorker BLOCKS on dataPacketUp to read a packet coming from the muxer and
// eventually BLOCKS on tunUp to deliver it;
//
// 2. moveDownWorker BLOCKS on tunDown to read a packet and
// eventually BLOCKS on dataOrControlToMuxer to deliver it;
//
// 3. keyWorker BLOCKS on keyUp to read a dataChannelKey and
// initializes the internal state with the resulting key;
func (s *Service) StartWorkers(
	config *config.Config,
	workersManager *workers.Manager,
	sessionManager *session.Manager,
) {
	ws := &workersState{
		options:              config.OpenVPNOptions(),
		dataOrControlToMuxer: *s.DataOrControlToMuxer,
		dataToTUN:            s.DataToTUN,
		keyReady:             s.KeyReady,
		logger:               config.Logger(),
		muxerToData:          s.MuxerToData,
		sessionManager:       sessionManager,
		tunToData:            s.TUNToData,
		workersManager:       workersManager,
	}

	firstKeyReady := make(chan any)

	workersManager.StartWorker(func() { ws.moveUpWorker(firstKeyReady) })
	workersManager.StartWorker(func() { ws.moveDownWorker(firstKeyReady) })
	workersManager.StartWorker(func() { ws.keyWorker(firstKeyReady) })
}

// workersState contains the data channel state.
type workersState struct {
	dataChannel          *DataChannel
	options              *config.OpenVPNOptions
	dataOrControlToMuxer chan<- *model.Packet
	dataToTUN            chan<- []byte
	keyReady             <-chan *session.DataChannelKey
	logger               model.Logger
	muxerToData          <-chan *model.Packet
	sessionManager       *session.Manager
	tunToData            <-chan []byte
	workersManager       *workers.Manager
}

// moveDownWorker moves packets down the stack. It will BLOCK on PacketDown
func (ws *workersState) moveDownWorker(firstKeyReady <-chan any) {
	workerName := serviceName + ":moveDownWorker"
	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)

	select {
	// wait for the first key to be ready
	case <-firstKeyReady:
		for {
			select {
			case data := <-ws.tunToData:
				// TODO: writePacket should get the ACTIVE KEY (verify this)
				packet, err := ws.dataChannel.writePacket(data)
				if err != nil {
					ws.logger.Warnf("error encrypting: %v", err)
					continue
				}

				select {
				case ws.dataOrControlToMuxer <- packet:
				case <-ws.workersManager.ShouldShutdown():
					return
				}

			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}

// moveUpWorker moves packets up the stack
func (ws *workersState) moveUpWorker(firstKeyReady <-chan any) {
	workerName := fmt.Sprintf("%s: moveUpWorker", serviceName)

	defer func() {

		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("%s: started", workerName)

	select {
	// wait for the first key to be ready
	case <-firstKeyReady:
		for {
			select {
			// TODO: opportunistically try to kill lame duck

			case pkt := <-ws.muxerToData:
				// TODO(ainghazal): factor out as handler function
				decrypted, err := ws.dataChannel.readPacket(pkt)
				if err != nil {
					ws.logger.Warnf("error decrypting: %v", err)
					continue
				}

				if len(decrypted) == 16 {
					// Some OpenVPN servers send a 16-byte keepalive payload; it's not an IP packet.
					ws.logger.Debugf("datachannel: keepalive payload received (%x)", decrypted)
					continue
				}

				// POSSIBLY BLOCK writing up towards TUN
				ws.dataToTUN <- decrypted
			case <-ws.workersManager.ShouldShutdown():
				return
			}
		}
	case <-ws.workersManager.ShouldShutdown():
		return
	}
}

// keyWorker receives notifications from key ready
func (ws *workersState) keyWorker(firstKeyReady chan<- any) {
	workerName := fmt.Sprintf("%s: keyWorker", serviceName)

	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()

	ws.logger.Debugf("%s: started", workerName)
	once := &sync.Once{}

	for {
		select {
		case key := <-ws.keyReady:
			// TODO(ainghazal): thread safety here - need to lock.
			// When we actually get to key rotation, we need to add locks.
			// Use RW lock, reader locks.

			if ws.dataChannel == nil {
				dc, err := NewDataChannelFromOptions(ws.logger, ws.options, ws.sessionManager)
				if err != nil {
					ws.logger.Warnf("cannot initialize channel %v", err)
					select {
					case ws.sessionManager.Failure <- err:
					default:
					}
					return
				}
				ws.dataChannel = dc
			}

			err := ws.dataChannel.setupKeys(key)
			if err != nil {
				ws.logger.Warnf("error on key derivation: %v", err)

				// Distinguish between initial key derivation and key rotation.
				// Similar to OpenVPN's handling: fatal error on initial, recoverable on rotation.
				if ws.sessionManager.NegotiationState() < model.S_GENERATED_KEYS {
					// Initial key derivation failed - fatal error, notify upper layer
					ws.sessionManager.SetNegotiationState(model.S_ERROR)
					select {
					case ws.sessionManager.Failure <- fmt.Errorf("key derivation failed: %w", err):
					default:
					}
					return
				}
				// Key rotation failed - old key still usable, wait for next rotation attempt
				ws.logger.Warnf("key rotation failed, continuing with current key")
				continue
			}
			ws.sessionManager.SetNegotiationState(model.S_GENERATED_KEYS)
			once.Do(func() {
				close(firstKeyReady)
			})

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}
