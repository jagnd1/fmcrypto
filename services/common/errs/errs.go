package errs

import "time"

type BadRequest struct{ Msg string } // 400
func (e BadRequest) Error() string   { return e.Msg }

type TooLarge struct{ Msg string } // 413
func (e TooLarge) Error() string   { return e.Msg }

type NotFound struct{ Msg string } // 404
func (e NotFound) Error() string   { return e.Msg }

// Invalid → 422; Fields carries per-field messages (nil for plain rule failures).
type Invalid struct {
	Msg    string
	Fields map[string]string
}
func (e Invalid) Error() string { return e.Msg }

type UnAuth struct{ Msg string } // 401
func (e UnAuth) Error() string   { return e.Msg }

type Forbidden struct{ Msg string } // 403
func (e Forbidden) Error() string   { return e.Msg }

type Conflict struct{ Msg string } // 409
func (e Conflict) Error() string   { return e.Msg }

// RateLimited → 429 (+ Retry-After header when RetryAfter > 0).
type RateLimited struct {
	Msg        string
	RetryAfter time.Duration
}
func (e RateLimited) Error() string {
	if e.Msg == "" {
		return "rate limit exceeded"
	}
	return e.Msg
}

type Timeout struct{ Msg string } // 504
func (e Timeout) Error() string   { return e.Msg }

// NotImplemented → 501; used while transport endpoints are scaffolded but the
// underlying capability is not yet implemented.
type NotImplemented struct{ Msg string }
func (e NotImplemented) Error() string { return e.Msg }

// Upstream → 502; wraps the cause with %w, never leaks detail to callers.
type Upstream struct {
	Msg string
	Err error
}
func (e Upstream) Error() string {
	if e.Err == nil {
		return e.Msg
	}
	return e.Msg + ": " + e.Err.Error()
}
func (e Upstream) Unwrap() error { return e.Err }