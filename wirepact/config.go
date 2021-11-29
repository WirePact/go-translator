package wirepact

import "time"

// JWTConfig contains specialized configuration for
// the CreateSignedJWTForUser method.
type JWTConfig struct {
	// The issuer that is inserted into the JWT.
	Issuer string

	// The lifetime of the token in a go duration.
	// If omitted, 60 seconds are used.
	Lifetime time.Duration
}
