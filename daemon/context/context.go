package daemon

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
)

type pathLookupContextKey string

const pathLookupKey pathLookupContextKey = "path-lookup"

// PathLookupInfo contains the source and destination ISD-AS from the original
// path lookup request.
type PathLookupInfo struct {
	Src addr.IA
	Dst addr.IA
}

// WithPathLookup derives a new context from ctx that contains the path lookup
// source and destination ISD-AS.
func WithPathLookup(ctx context.Context, src, dst addr.IA) context.Context {
	return context.WithValue(ctx, pathLookupKey, PathLookupInfo{Src: src, Dst: dst})
}

// MustPathLookupFromCtx extracts the path lookup information from the context.
// Returns the path lookup info.
func MustPathLookupFromCtx(ctx context.Context) PathLookupInfo {
	v, ok := ctx.Value(pathLookupKey).(PathLookupInfo)
	if !ok {
		panic("path lookup info not found in context")
	}
	return v
}
