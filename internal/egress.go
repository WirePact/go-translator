package internal

import (
	"context"

	"github.com/WirePact/go-translator/envoy"
	"github.com/WirePact/go-translator/translator"
	"github.com/WirePact/go-translator/wirepact"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type EgressServer struct {
	EgressTranslator translator.EgressTranslation
	JWTConfig        *wirepact.JWTConfig
}

func (server *EgressServer) Check(_ context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	// Basically, the check runs for every incoming request. If the request contains the
	// specific X-WirePact-Identity header, the header value is processed.
	// If not, then the request is just forwarded and therefore allowed to the target system.

	result, err := server.EgressTranslator(req)
	if err != nil {
		return nil, err
	}

	if result.Skip {
		return envoy.CreateNoopOKResponse(), nil
	}

	if result.UserID == "" {
		return envoy.CreateForbiddenResponse("No UserID given for outbound communication."), nil
	}

	return envoy.CreateEgressOKResponse(server.JWTConfig, result.UserID, result.HeadersToRemove)
}
