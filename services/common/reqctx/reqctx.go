package reqctx

import "context"

type ctxKey int

const reqIDKey ctxKey = 0

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, reqIDKey, id)
}

func RequestIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(reqIDKey).(string)
	return id, ok
}

type AccessMeta struct{ Route string }

const accessMetaKey ctxKey = 1

func WithAccessMeta(ctx context.Context, meta *AccessMeta) context.Context {
	return context.WithValue(ctx, accessMetaKey, meta)
}

func AccessMetaFrom(ctx context.Context) (*AccessMeta, bool) {
	meta, ok := ctx.Value(accessMetaKey).(*AccessMeta)
	return meta, ok
}
