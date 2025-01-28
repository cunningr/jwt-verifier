# jwt-verifier
A small tool written in Go to validate a JWT token with and OIDC provider (JWKS)

1. In `main.go`, add you OIDC JWKS provider base URL.  This will be combined with `/openid/v1/jwks` to fetch the JWKS.
2. Copy a token that you want to validate into `main.go`
3. Run `go run .`.

Note the `main.go` is only provided as an example with the intention that the `/oidc` can be used as a go package for test tools.
