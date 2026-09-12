package services

import "common/errs"

// errNotImplemented is returned by endpoints whose engine lands in Phase 4.
var errNotImplemented = errs.NotImplemented{Msg: "not implemented"}