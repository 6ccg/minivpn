package config

import (
	"errors"
	"strings"
	"testing"
)

func TestReadConfigFromBytes_UnknownOptionIsFatal(t *testing.T) {
	_, err := ReadConfigFromBytes([]byte("this-option-does-not-exist foo\n"))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, ErrBadConfig) {
		t.Fatalf("expected ErrBadConfig, got %v", err)
	}
}

func TestReadConfigFromBytes_IgnoreUnknownOptionAllowsListed(t *testing.T) {
	config := strings.Join([]string{
		"ignore-unknown-option this-option-does-not-exist",
		"this-option-does-not-exist foo",
		"",
	}, "\n")
	if _, err := ReadConfigFromBytes([]byte(config)); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
