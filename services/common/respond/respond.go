package respond

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"common/errs"
	"common/reqctx"
)

func JSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	writeJSON(w, r, status, v)
}

func Internal(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusInternalServerError, errBody(r, "internal error", nil))
}

func Err(w http.ResponseWriter, r *http.Request, err error) {
	var (
		bad errs.BadRequest
		big errs.TooLarge
		inv errs.Invalid
		un  errs.UnAuth
		fb  errs.Forbidden
		nf  errs.NotFound
		cf  errs.Conflict
		rl  errs.RateLimited
		to  errs.Timeout
		up  errs.Upstream
		ni  errs.NotImplemented
	)
	switch {
	case errors.As(err, &bad):
		writeJSON(w, r, http.StatusBadRequest, errBody(r, bad.Msg, nil))
	case errors.As(err, &big):
		writeJSON(w, r, http.StatusRequestEntityTooLarge, errBody(r, big.Msg, nil))
	case errors.As(err, &inv):
		writeJSON(w, r, http.StatusUnprocessableEntity, errBody(r, inv.Msg, inv.Fields))
	case errors.As(err, &un):
		writeJSON(w, r, http.StatusUnauthorized, errBody(r, un.Msg, nil))
	case errors.As(err, &fb):
		writeJSON(w, r, http.StatusForbidden, errBody(r, fb.Msg, nil))
	case errors.As(err, &nf):
		writeJSON(w, r, http.StatusNotFound, errBody(r, nf.Msg, nil))
	case errors.As(err, &cf):
		writeJSON(w, r, http.StatusConflict, errBody(r, cf.Msg, nil))
	case errors.As(err, &rl):
		if rl.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(rl.RetryAfter.Seconds())))
		}
		writeJSON(w, r, http.StatusTooManyRequests, errBody(r, rl.Error(), nil))
	case errors.Is(err, context.Canceled):
		slog.DebugContext(r.Context(), "request canceled")
		return
	case errors.As(err, &to), errors.Is(err, context.DeadlineExceeded):
		writeJSON(w, r, http.StatusGatewayTimeout, errBody(r, "request timed out", nil))
	case errors.As(err, &up):
		slog.ErrorContext(r.Context(), "upstream failure", "err", err)
		writeJSON(w, r, http.StatusBadGateway, errBody(r, "upstream unavailable", nil))
	case errors.As(err, &ni):
		writeJSON(w, r, http.StatusNotImplemented, errBody(r, ni.Msg, nil))
	default:
		slog.ErrorContext(r.Context(), "unhandled error", "err", err)
		writeJSON(w, r, http.StatusInternalServerError, errBody(r, "internal error", nil))
	}
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.ErrorContext(r.Context(), "encode response", "err", err)
	}
}

func errBody(r *http.Request, msg string, fields map[string]string) map[string]any {
	b := map[string]any{"error": msg}
	if id, ok := reqctx.RequestIDFrom(r.Context()); ok {
		b["request_id"] = id
	}
	if len(fields) > 0 {
		b["fields"] = fields
	}
	return b
}