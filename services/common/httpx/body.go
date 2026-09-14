package httpx

import (
	"encoding/json"
	"errors"
	"net/http"

	"common/errs"
)

func DecodeJSON(r *http.Request, dst any) error {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errs.TooLarge{Msg: "request body too large"}
		}
		return errs.BadRequest{Msg: "invalid json"}
	}
	return nil
}
