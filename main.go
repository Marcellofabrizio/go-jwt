package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Claims struct {
	Iss         string                 `json:"iss"`
	Sub         string                 `json:"sub"`
	Aud         string                 `json:"aud"`
	Exp         string                 `json:"exp"`
	Nbf         string                 `json:"nbf"`
	ExtraFields map[string]interface{} `json:"-"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	X5c []string `json:"x5c"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	Kid string   `json:"kid"`
	X5t string   `json:"x5t"`
}

func readRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block or invalid type")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return privateKey, nil
}

func createJwt(header Header, claims Claims, secret string) string {

	headerDataJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	encodedHeader := base64.URLEncoding.EncodeToString(headerDataJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)

	secretByte := []byte(secret)

	var builder strings.Builder
	builder.Grow(len(encodedHeader) + len(encodedClaims))

	parts := []string{encodedHeader, ".", encodedClaims}

	for _, part := range parts {
		builder.WriteString(part)
	}

	hmac := hmac.New(sha256.New, secretByte)

	hmac.Write([]byte(builder.String()))
	dataHmac := hmac.Sum(nil)

	hmacHex := base64.RawURLEncoding.EncodeToString(dataHmac)
	secretHex := base64.RawURLEncoding.EncodeToString(secretByte)
	jwt := fmt.Sprintf("%s.%s.%s", encodedHeader, encodedClaims, hmacHex)

	fmt.Printf("HMAC_SHA256(key: %s, data: %s): %s \n", secretHex, builder.String(), hmacHex)
	fmt.Printf("JWT: %s \n", jwt)

	return jwt
}

func main() {
	headerData := Header{Alg: "HS256", Typ: "JWT"}
	payloadString := `{"sub":"1234567890","name":"John Doe","admin":true, "ipInfo": {"ip": "120.020.102.011", "country": "USA"}}`

	var payloadJSONUnmarshaled Claims

	err := json.Unmarshal([]byte(payloadString), &payloadJSONUnmarshaled)

	if err != nil {
		fmt.Println("error parsing payload:", err)
		return
	}

	fmt.Println("Payload: ", payloadJSONUnmarshaled)

	secret := make([]byte, 64)
	_, err = rand.Read(secret)
	if err != nil {
		fmt.Println("error generating a random secret:", err)
		return
	}

	createJwt(headerData, payloadJSONUnmarshaled, string(secret))

	//TODO: Create JWK file to read public key and validate signature
	key, err := readRSAPrivateKey("./rsa")
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	fmt.Printf("RSA Key: %+v\n", key)

	// n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	// bytes := make([]byte, 8)
	// binary.BigEndian.PutUint64(bytes, uint64(key.E))
	// e := base64.RawURLEncoding.EncodeToString(bytes)

	fmt.Printf("N: %+v\n", base64.StdEncoding.EncodeToString([]byte(key.N.String())))
	fmt.Printf("E: %+v\n", base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(key.E))))
}
