package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/6ccg/minivpn/internal/model"
)

func TestNewConfig(t *testing.T) {
	t.Run("default constructor does not fail", func(t *testing.T) {
		c := NewConfig()
		if c.logger == nil {
			t.Errorf("logger should not be nil")
		}
		if c.tracer == nil {
			t.Errorf("tracer should not be nil")
		}
	})
	t.Run("WithLogger sets the logger", func(t *testing.T) {
		testLogger := model.NewTestLogger()
		c := NewConfig(WithLogger(testLogger))
		if c.Logger() != testLogger {
			t.Errorf("expected logger to be set to the configured one")
		}
	})
	t.Run("WithTracer sets the tracer", func(t *testing.T) {
		testTracer := model.HandshakeTracer(model.DummyTracer{})
		c := NewConfig(WithHandshakeTracer(testTracer))
		if c.Tracer() != testTracer {
			t.Errorf("expected tracer to be set to the configured one")
		}
	})

	t.Run("WithConfigBytes sets OpenVPNOptions after parsing the configured bytes", func(t *testing.T) {
		c := NewConfig(WithConfigBytes([]byte(sampleConfigFile)))
		opts := c.OpenVPNOptions()
		if opts.Proto.String() != "udp" {
			t.Error("expected proto udp")
		}
		wantRemote := &Remote{
			IPAddr:   "2.3.4.5",
			Endpoint: "2.3.4.5:1194",
			Protocol: "udp",
		}
		if diff := cmp.Diff(c.Remote(), wantRemote); diff != "" {
			t.Error(diff)
		}
	})

}

var sampleConfigFile = `
remote 2.3.4.5 1194
proto udp
cipher AES-256-GCM
auth SHA512
<ca>
dummy
</ca>
<cert>
dummy
</cert>
<key>
dummy
</key>
`
