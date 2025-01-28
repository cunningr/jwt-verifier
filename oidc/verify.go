package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

func base64URLDecode(input string) ([]byte, error) {
	// Replace URL-specific characters: '-' -> '+', '_' -> '/'
	decodedStr := strings.ReplaceAll(input, "-", "+")
	decodedStr = strings.ReplaceAll(decodedStr, "_", "/")

	// Add padding to make the length of the string a multiple of 4
	for len(decodedStr)%4 != 0 {
		decodedStr += "="
	}

	// Decode the base64 URL string
	return base64.StdEncoding.DecodeString(decodedStr)
}

func FindKeyByKid(jwks map[string]interface{}, kid string) (map[string]interface{}, error) {
	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("no keys found in JWKS")
	}

	// Range over the keys array and find the key that matches the 'kid'
	for _, key := range keys {
		keyMap, ok := key.(map[string]interface{})
		if !ok {
			continue
		}
		if keyMap["kid"] == kid {
			return keyMap, nil
		}
	}

	return nil, fmt.Errorf("no matching key found for kid: %s", kid)
}

func FetchJWKS(oidcURL string) (map[string]interface{}, error) {
	// Fetch the JWKS from the OIDC provider
	resp, err := http.Get(oidcURL + "/openid/v1/jwks")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse the JWKS response into a map
	var jwks map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return nil, err
	}

	return jwks, nil
}

func GetKidFromJWT(token string) (string, error) {
	// Split the JWT into header, payload, and signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode the JWT header
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return "", fmt.Errorf("error decoding header: %v", err)
	}

	// Parse the header to extract 'kid'
	var header map[string]interface{}
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return "", fmt.Errorf("error parsing header: %v", err)
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return "", fmt.Errorf("no 'kid' field in JWT header")
	}

	return kid, nil
}

func BuildRSAPublicKey(n string, e string) (*rsa.PublicKey, error) {
	// Decode 'n' and 'e' from Base64 URL
	modulusBytes, err := base64URLDecode(n)
	if err != nil {
		return nil, fmt.Errorf("error decoding modulus: %v", err)
	}
	exponentBytes, err := base64URLDecode(e)
	if err != nil {
		return nil, fmt.Errorf("error decoding exponent: %v", err)
	}

	// Create the big integers for modulus and exponent
	modulus := new(big.Int).SetBytes(modulusBytes)
	exponent := new(big.Int).SetBytes(exponentBytes)

	// Build the RSA public key
	publicKey := &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}

	return publicKey, nil
}

// Function to verify JWT using the public key
func VerifyJWT(token string, publicKey *rsa.PublicKey) error {
	// Parse the JWT and verify its signature
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token is signed with RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("error parsing JWT: %v", err)
	}

	if !parsedToken.Valid {
		return fmt.Errorf("invalid token")
	}

	// Accessing claims and printing out specific data
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("could not extract claims")
	}

	// Print some claims from the JWT
	fmt.Println("Claims:")
	for key, value := range claims {
		switch v := value.(type) {
		case string:
			fmt.Printf("%s: %s\n", key, v)
		case float64:
			fmt.Printf("%s: %f\n", key, v)
		default:
			fmt.Printf("%s: %v\n", key, v)
		}
	}

	// If you want to print specific claims:
	if validFrom, ok := claims["iat"].(float64); ok {
		// Convert Unix timestamp to human-readable format
		t := time.Unix(int64(validFrom), 0)
		fmt.Printf("Issued At: %s\n", t.Format(time.RubyDate)) // Human-readable format
	}

	if notBefore, ok := claims["nbf"].(float64); ok {
		// Convert Unix timestamp to human-readable format
		t := time.Unix(int64(notBefore), 0)
		fmt.Printf("Not Before: %s\n", t.Format(time.RubyDate)) // Human-readable format
	}

	if exp, ok := claims["exp"].(float64); ok {
		// Convert Unix timestamp to human-readable format
		t := time.Unix(int64(exp), 0)
		fmt.Printf("Expires At: %s\n", t.Format(time.RubyDate)) // Human-readable format
	}

	return nil
}
