package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
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

func (c *Claims) UnmarshalJSON(data []byte) error {
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	if v, ok := rawMap["iss"].(string); ok {
		c.Iss = v
	}
	if v, ok := rawMap["sub"].(string); ok {
		c.Sub = v
	}
	if v, ok := rawMap["aud"].(string); ok {
		c.Aud = v
	}
	if v, ok := rawMap["exp"].(string); ok {
		c.Exp = v
	}
	if v, ok := rawMap["nbf"].(string); ok {
		c.Nbf = v
	}

	delete(rawMap, "iss")
	delete(rawMap, "sub")
	delete(rawMap, "aud")
	delete(rawMap, "exp")
	delete(rawMap, "nbf")

	c.ExtraFields = rawMap
	return nil
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

func ReadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
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
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return privateKey, nil
}

func ReadRSAPubKey(filename string) (*rsa.PublicKey, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block or invalid type")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return pubKey, nil
}

func CreateJWT(header Header, claims Claims, privateKey *rsa.PrivateKey) (string, error) {
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := fmt.Sprintf("%s.%s", encodedHeader, encodedClaims)

	hashed := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	jwt := fmt.Sprintf("%s.%s.%s", encodedHeader, encodedClaims, encodedSignature)

	return jwt, nil
}

func VerifyJWT(jwtToken string, key *rsa.PublicKey) (bool, error) {
	parts := strings.Split(jwtToken, ".")
	message := []byte(strings.Join(parts[0:2], "."))

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])

	if err != nil {
		return false, err
	}

	hasher := crypto.SHA256.New()
	hasher.Write(message)

	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hasher.Sum(nil), signature)

	if err != nil {
		return false, err
	}

	return true, nil
}

func main() {
	headerData := Header{Alg: "HS256", Typ: "JWT"}
	payloadString := `{"sub":"1234567890","name":"John Doe","admin":true, "ipInfo": {"ip": "120.020.102.011", "country": "USA"}}`

	payloadJSONUnmarshaled := Claims{}

	err := json.Unmarshal([]byte(payloadString), &payloadJSONUnmarshaled)

	if err != nil {
		fmt.Println("error parsing payload:", err)
		return
	}

	fmt.Printf("Payload: %+v", payloadJSONUnmarshaled)

	secret := make([]byte, 64)
	_, err = rand.Read(secret)
	if err != nil {
		fmt.Println("error generating a random secret:", err)
		return
	}

	//TODO: Create JWK file to read public key and validate signature
	key, err := ReadRSAPrivateKey("./rsa")
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	fmt.Printf("RSA Key: %+v\n", key)

	jwt, _ := CreateJWT(headerData, payloadJSONUnmarshaled, key)

	fmt.Printf("JWT: %+v\n", jwt)

	publicKey, readErr := ReadRSAPubKey("./rsa.pub")

	if readErr != nil {
		fmt.Println("error reading pub key:", readErr)
	}

	valid, validationErr := VerifyJWT(jwt, publicKey)

	fmt.Println("Is jwt valid?", valid)

	if validationErr != nil {
		fmt.Println("error verifying jwt:", validationErr)
	}
}
