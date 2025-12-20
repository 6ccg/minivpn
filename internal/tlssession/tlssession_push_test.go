package tlssession

import (
	"errors"
	"net"
	"testing"

	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/pkg/config"
)

func Test_recvPushResponseMessage_readsNullTerminatedMessages(t *testing.T) {
	t.Run("handles split writes", func(t *testing.T) {
		c0, c1 := net.Pipe()
		defer c0.Close()
		defer c1.Close()

		go func() {
			_, _ = c1.Write([]byte("PUSH_REPLY,route-gateway 10.0.0.1,ifconfig "))
			_, _ = c1.Write([]byte("10.0.0.2 255.255.255.0\x00"))
			_ = c1.Close()
		}()

		ws := &workersState{logger: model.NewTestLogger()}
		ti, err := ws.recvPushResponseMessage(c0)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if ti.IP != "10.0.0.2" {
			t.Fatalf("unexpected IP: %q", ti.IP)
		}
		if ti.NetMask != "255.255.255.0" {
			t.Fatalf("unexpected NetMask: %q", ti.NetMask)
		}
		if ti.GW != "10.0.0.1" {
			t.Fatalf("unexpected GW: %q", ti.GW)
		}
	})

	t.Run("ignores non-push control strings before PUSH_REPLY", func(t *testing.T) {
		c0, c1 := net.Pipe()
		defer c0.Close()
		defer c1.Close()

		go func() {
			_, _ = c1.Write([]byte("AUTH_PENDING,timeout 10\x00PUSH_REPLY,route-gateway 10.0.0.1,ifconfig 10.0.0.2 255.255.255.0\x00"))
			_ = c1.Close()
		}()

		ws := &workersState{logger: model.NewTestLogger()}
		ti, err := ws.recvPushResponseMessage(c0)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if ti.IP != "10.0.0.2" {
			t.Fatalf("unexpected IP: %q", ti.IP)
		}
	})

	t.Run("fails on AUTH_FAILED", func(t *testing.T) {
		c0, c1 := net.Pipe()
		defer c0.Close()
		defer c1.Close()

		go func() {
			_, _ = c1.Write([]byte("AUTH_FAILED\x00"))
			_ = c1.Close()
		}()

		ws := &workersState{logger: model.NewTestLogger()}
		_, err := ws.recvPushResponseMessage(c0)
		if !errors.Is(err, errBadAuth) {
			t.Fatalf("expected errBadAuth, got %v", err)
		}
	})
}

func Test_recvPushResponseMessage_updatesCipherFromPushReply(t *testing.T) {
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()

	opts := &config.OpenVPNOptions{Cipher: "AES-256-CBC"}

	go func() {
		_, _ = c1.Write([]byte("PUSH_REPLY,cipher AES-256-GCM,route-gateway 10.0.0.1,ifconfig 10.0.0.2 255.255.255.0\x00"))
		_ = c1.Close()
	}()

	ws := &workersState{
		logger:  model.NewTestLogger(),
		options: opts,
	}
	_, err := ws.recvPushResponseMessage(c0)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if opts.Cipher != "AES-256-GCM" {
		t.Fatalf("unexpected cipher: %q", opts.Cipher)
	}
}
