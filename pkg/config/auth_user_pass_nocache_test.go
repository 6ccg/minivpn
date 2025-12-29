package config

import (
	"errors"
	"testing"
)

func TestAuthNoCache_PurgeClearsAllCachedCredentials(t *testing.T) {
	opts := &OpenVPNOptions{
		AuthUserPass: true,
		AuthNoCache:  true,
		Username:     "user",
		Password:     "pass",
	}

	u1, p1, err := opts.AuthUserPassSetup()
	if err != nil {
		t.Fatalf("AuthUserPassSetup() failed: %v", err)
	}
	if u1 != "user" || p1 != "pass" {
		t.Fatalf("unexpected credentials: got %q/%q", u1, p1)
	}

	opts.PurgeAuthUserPass()

	u2, p2, err := opts.AuthUserPassSetup()
	if err == nil {
		t.Fatalf("expected error after purge, got nil (creds=%q/%q)", u2, p2)
	}
	if !errors.Is(err, ErrBadConfig) {
		t.Fatalf("expected ErrBadConfig, got %v", err)
	}
}
