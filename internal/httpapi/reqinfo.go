package httpapi

import (
	"context"

	"pdn-shield/internal/engine"
	"pdn-shield/internal/pii"
)

// reqInfoKey is the private context key for the per-request log info.
type reqInfoKey struct{}

// reqInfo carries the fields that the request-log middleware writes after the
// handler runs. It never holds PII values or span text.
type reqInfo struct {
	payloadID string
	direction string
	textLen   int
	chunks    int
	found     map[pii.Category]int
	misses    int
	stages    engine.Stages
	// tokens is the estimated (or, when the upstream LLM reports it, exact)
	// token count processed by this request. It feeds the pdn_tokens_total
	// metric and the request log line for every route, not just chat.
	tokens int
}

// withReqInfo attaches a reqInfo to the request context.
func withReqInfo(ctx context.Context) (context.Context, *reqInfo) {
	info := &reqInfo{}
	return context.WithValue(ctx, reqInfoKey{}, info), info
}

// reqInfoFrom returns the reqInfo attached to the context, or nil.
func reqInfoFrom(ctx context.Context) *reqInfo {
	info, _ := ctx.Value(reqInfoKey{}).(*reqInfo)
	return info
}
