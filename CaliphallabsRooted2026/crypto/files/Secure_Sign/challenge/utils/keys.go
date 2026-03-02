package utils

import (
	"log"
	"os"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"encoding/pem"
)

var (
	ServerPrivateKey *ecdsa.PrivateKey
	ServerPublicKey  *ecdsa.PublicKey
)

const (
	PrivKeyFile = "server_private.pem"
	PubKeyFile  = "server_public.pem"
)

func LoadOrGenerateKeys() {
	if _, err := os.Stat(PrivKeyFile); os.IsNotExist(err) {
		generateKeys()
	} else {
		loadKeys()
	}
}

func generateKeys() {
	var err error

	if ServerPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		log.Fatal("Failed to generate private key:", err)
	}

	ServerPublicKey = &ServerPrivateKey.PublicKey
	x509Encoded, err := x509.MarshalECPrivateKey(ServerPrivateKey)

	if err != nil {
		log.Fatal("Failed to encode private key:", err)
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Encoded})

	if err = os.WriteFile(PrivKeyFile, pemEncoded, 0600); err != nil {
		log.Fatal("Failed to save private key:", err)
	}

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(ServerPublicKey)

	if err != nil {
		log.Fatal("Failed to encode public key:", err)
	}

	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	if err = os.WriteFile(PubKeyFile, pemEncodedPub, 0644); err != nil {
		log.Fatal("Failed to save public key:", err)
	}
}

func loadKeys() {
	pemEncoded, err := os.ReadFile(PrivKeyFile)

	if err != nil {
		log.Fatal("Failed to read private key:", err)
	}

	block, _ := pem.Decode(pemEncoded)

	if ServerPrivateKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		log.Fatal("Failed to parse private key:", err)
	}

	ServerPublicKey = &ServerPrivateKey.PublicKey
}

func GetPrivateKey() *ecdsa.PrivateKey {
	return ServerPrivateKey
}

func GetPublicKey() *ecdsa.PublicKey {
	return ServerPublicKey
}

func GetPublicKeyPEM() string {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(ServerPublicKey)

	if err != nil {
		log.Fatal("Failed to encode public key:", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub}))
}
