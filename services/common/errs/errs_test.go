package errs

import (
	"errors"
	"testing"
)

func TestUpstreamUnwrap(t *testing.T) {
	base := errors.New("boom")
	e := Upstream{Msg: "up", Err: base}
	if !errors.Is(e, base) {
		t.Fatal("errors.Is must reach the wrapped cause")
	}
	if got := e.Error(); got != "up: boom" {
		t.Fatalf("got %q", got)
	}
}

func TestRateLimitedDefaultMessage(t *testing.T) {
	if got := (RateLimited{}).Error(); got != "rate limit exceeded" {
		t.Fatalf("got %q", got)
	}
}

func TestInvalidAsValue(t *testing.T) {
	err := error(Invalid{Msg: "validation failed", Fields: map[string]string{"name": "required"}})
	var inv Invalid
	if !errors.As(err, &inv) {
		t.Fatal("expected errors.As to match Invalid")
	}
	if inv.Fields["name"] != "required" {
		t.Fatalf("got %v", inv.Fields)
	}
}