package tlssession

import (
	"github.com/6ccg/minivpn/internal/model"
	"github.com/6ccg/minivpn/internal/runtimex"
	"github.com/6ccg/minivpn/internal/session"
	"github.com/6ccg/minivpn/pkg/config"
)

func makeTestingSession() *session.Manager {
	manager, err := session.NewManager(config.NewConfig())
	runtimex.PanicOnError(err, "could not get session manager")
	manager.SetRemoteSessionID(model.SessionID{0x01})
	return manager
}
