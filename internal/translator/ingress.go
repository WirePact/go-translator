package translator

import (
	"context"

	"github.com/WirePact/go-translator/envoy"
	gotranslator "github.com/WirePact/go-translator/translator"
	"github.com/WirePact/go-translator/wirepact"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type IngressServer struct {
	IngressTranslator gotranslator.IngressTranslation
}

func (server *IngressServer) Check(_ context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	// Basically, the check runs for every incoming request. If the request contains the
	// specific X-WirePact-Identity header, the header value is processed.
	// If not, then the request is just forwarded and therefore allowed to the target system.

	wirePactJWT, ok := req.Attributes.Request.Http.Headers[wirepact.IdentityHeader]
	if !ok {
		return envoy.CreateNoopOKResponse(), nil
	}

	subject, err := wirepact.GetJWTUserSubject(wirePactJWT)
	if err != nil {
		return nil, err
	}

	result, err := server.IngressTranslator(subject, req)
	if err != nil {
		return nil, err
	}

	if result.Skip {
		return envoy.CreateNoopOKResponse(), nil
	}

	return envoy.CreateIngressOKResponse(result.HeadersToAdd, result.HeadersToRemove), nil
}
