package go_translator

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

// IngressResult helps to return the correct request to the upstream of a translator.
type IngressResult struct {
	// If set, the result for envoy is a "noop" OK result.
	Skip bool

	// Defines a list of header values that should be added to the request for
	// the downstream.
	HeadersToAdd []*core.HeaderValue

	// Defines a list of headers that should be removed from the request.
	// In addition to these headers, the WirePact JWT header is always removed.
	HeadersToRemove []string
}

// IngressTranslation acts as the translator for incoming communication.
// The function receives the parsed JWT subject (if possible) and the full request.
// It shall return a list of headers to add for the downstream and a list of headers that shall be removed.
// By default, the WirePact JWT header is removed.
type IngressTranslation func(subject string, req *auth.CheckRequest) (IngressResult, error)

// EgressResult helps to return the correct request to the upstream of a translator.
type EgressResult struct {
	// If set, the result for envoy is a "noop" OK result.
	Skip bool

	// Defines the userID that should be encoded into the JWT.
	// If an empty string is used, the request assumes that no userID
	// could be found for the presented authorization and therefore, the
	// request will be denied.
	UserID string

	// Defines a list of headers that should be removed from the request
	// (typically the consumed authentication header).
	HeadersToRemove []string
}

// EgressTranslation is the function that translates the specific
// authentication into a JWT. The function receives the request (from envoy)
// and shall return the check response according to its authentication scheme.
// Helper functions can be found in the envoy module.
type EgressTranslation func(req *auth.CheckRequest) (EgressResult, error)
