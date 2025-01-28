package main

import (
	"fmt"
	oidc "github.com/cunningr/jwt-verifier/oidc"
	"log"
)

func main() {
	token := "<INSERt JWT TOKEN HERE>" // Replace with your JWT token
	// Set the OIDC provider URL
	oidcURL := "https://auth.example.com" // Replace with your OIDC provider URL

	// Fetch the JWKS
	jwks, err := oidc.FetchJWKS(oidcURL)
	if err != nil {
		log.Fatalf("Failed to fetch JWKS: %v", err)
	}

	// Extract the 'kid' from the JWT
	kid, err := oidc.GetKidFromJWT(token)
	if err != nil {
		log.Fatalf("Failed to extract 'kid' from JWT: %v", err)
	}

	// Find the key that corresponds to the 'kid' in the JWKS
	key, err := oidc.FindKeyByKid(jwks, kid)
	if err != nil {
		log.Fatalf("Failed to find key by 'kid': %v", err)
	}

	// Build the RSA public key from the 'n' and 'e' fields in the JWKS
	publicKey, err := oidc.BuildRSAPublicKey(key["n"].(string), key["e"].(string))
	if err != nil {
		log.Fatalf("Failed to build RSA public key: %v", err)
	}

	// Verify the JWT token using the public key
	err = oidc.VerifyJWT(token, publicKey)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Println("*** Token is valid ***")
}
