package envoy

import (
	"github.com/WirePact/go-translator/wirepact"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	types "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

const (
	grpcOk               = 0
	grpcPermissionDenied = 7
)

// CreateNoopOKResponse creates a NOOP response for envoy (meaning that no headers
// are modified or removed).
func CreateNoopOKResponse() *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: grpcOk,
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{},
		},
	}
}

// CreateEgressOKResponse creates an outbound OK response by encoding the given userID with
// the given jwtConfig and then returning an auth result that adds the WirePact JWT header.
func CreateEgressOKResponse(jwtConfig *wirepact.JWTConfig, userID string, headersToRemove []string) (*auth.CheckResponse, error) {
	jwt, err := wirepact.CreateSignedJWTForUser(jwtConfig, userID)
	if err != nil {
		return nil, err
	}

	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: grpcOk,
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   wirepact.IdentityHeader,
							Value: jwt,
						},
					},
				},
				HeadersToRemove: headersToRemove,
			},
		},
	}, nil
}

// CreateIngressOKResponse creates an outbound OK response by encoding the given userID with
// the given jwtConfig and then returning an auth result that adds the WirePact JWT header.
func CreateIngressOKResponse(headersToAdd []*core.HeaderValue, headersToRemove []string) *auth.CheckResponse {
	var headerValues []*core.HeaderValueOption

	for _, header := range headersToAdd {
		headerValues = append(headerValues, &core.HeaderValueOption{Header: header})
	}

	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: grpcOk,
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers:         headerValues,
				HeadersToRemove: headersToRemove,
			},
		},
	}
}

// CreateForbiddenResponse creates a forbidden response for the up/downstream with the given reason.
func CreateForbiddenResponse(reason string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: grpcPermissionDenied,
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Body:   reason,
				Status: &types.HttpStatus{Code: types.StatusCode_Forbidden},
			},
		},
	}
}
