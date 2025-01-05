package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func main() {
	headerData := header{Alg: "HS256", Typ: "JWT"}
	headerDataJSON, _ := json.Marshal(headerData)
	payloadString := `{"sub":"1234567890","name":"John Doe","admin":true, "ipInfo": {"ip": "120.020.102.011", "country": "USA"}}`

	var payloadJSONUnmarshaled map[string]interface{}

	err := json.Unmarshal([]byte(payloadString), &payloadJSONUnmarshaled)

	if err != nil {
		fmt.Println("error parsing payload:", err)
		return
	}

	fmt.Println("Payload: ", payloadJSONUnmarshaled)

	payloadJSONMarshaled, _ := json.Marshal(payloadJSONUnmarshaled)

	encodedHeader := base64.URLEncoding.EncodeToString(headerDataJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSONMarshaled)

	// secret := make([]byte, 64)
	// _, err = rand.Read(secret)
	// if err != nil {
	// 	fmt.Println("error generating a random secret:", err)
	// 	return
	// }

	secret := []byte("8Zz5tw0Ionm3XPZZfN0NOml3z9FMfmpgXwovR9fp6ryDIoGRM8EPHAB6iHsc0fb")

	fmt.Println("Header: ", string(headerDataJSON))
	fmt.Println("Encoded Header: ", encodedHeader)
	fmt.Println("Encoded Payload: ", encodedPayload)

	var builder strings.Builder
	builder.Grow(len(encodedHeader) + len(encodedPayload) + len(secret) + 2)

	parts := []string{encodedHeader, ".", encodedPayload}

	for _, part := range parts {
		builder.WriteString(part)
	}

	hmac := hmac.New(sha256.New, secret)

	hmac.Write([]byte(builder.String()))
	dataHmac := hmac.Sum(nil)

	hmacHex := base64.RawURLEncoding.EncodeToString(dataHmac)
	secretHex := base64.RawURLEncoding.EncodeToString(secret)

	fmt.Printf("HMAC_SHA256(key: %s, data: %s): %s \n", secretHex, builder.String(), hmacHex)
	fmt.Printf("JWT: %s.%s.%s \n", encodedHeader, encodedPayload, hmacHex)
}
