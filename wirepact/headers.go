package wirepact

const (
	// IdentityHeader defines the header that is transmitted
	// as the WirePact identity. This is a RSA256 signed JSONWebToken (JWT).
	IdentityHeader = "x-wirepact-identity"

	// AuthorizationHeader is the default HTTP header for authorization.
	AuthorizationHeader = "authorization"
)
