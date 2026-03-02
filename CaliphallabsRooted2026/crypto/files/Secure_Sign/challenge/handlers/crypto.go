package handlers

import (
	"secure-sign/utils"

	"bytes"
	"os"

	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"

	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"

	"math/big"

	"github.com/gofiber/fiber/v2"
)

type EcdsaSignature struct {
	R, S *big.Int
}

type SignResult struct {
	Filename  string `json:"filename"`
	Signature string `json:"signature"`
	Error     string `json:"error,omitempty"`
}

type VerifyResult struct {
	Filename string `json:"filename"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
}

type CustomReader struct {
	state  int16
	random []byte
}

var a, c int16 = 31337, 1337

func (r *CustomReader) Read(p []byte) (n int, err error) {
	var s []byte

	for i := range p {
		if i%2 == 0 {
			r.state = a*r.state + c
			s = big.NewInt(int64(r.state)).Bytes()
			p[i] = sha256.Sum256(append(s, r.random...))[i]
		} else {
			p[i] = sha256.Sum256(append(r.random, s...))[i]
		}
	}

	return len(p), nil
}

type FileRequest struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

type SignRequest struct {
	Files []FileRequest `json:"files"`
}

func SignDocument(c *fiber.Ctx) error {
	var req SignRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "failed to parse json"})
	}

	if len(req.Files) == 0 {
		return c.Status(400).JSON(fiber.Map{"message": "docs required"})
	}

	random := make([]byte, 32)
	rand.Read(random)

	var results []SignResult
	reader := &CustomReader{state: 12345, random: random}

	for _, file := range req.Files {
		fileBytes, err := base64.StdEncoding.DecodeString(file.Content)

		if err != nil {
			results = append(results, SignResult{Filename: file.Filename, Error: "failed to decode base64"})
			continue
		}

		hash := sha256.Sum256(fileBytes)
		priv := utils.GetPrivateKey()
		N := priv.Params().N

		buf := make([]byte, 32)
		reader.Read(buf)
		k := new(big.Int).SetBytes(buf)
		k.Mod(k, N)

		kGx, _ := priv.Curve.ScalarBaseMult(k.Bytes())
		r := new(big.Int).Mod(kGx, N)
		s := new(big.Int).Mul(new(big.Int).ModInverse(k, N), new(big.Int).Add(new(big.Int).SetBytes(hash[:]), new(big.Int).Mul(r, priv.D)))
		s.Mod(s, N)

		asn1Signature, err := asn1.Marshal(EcdsaSignature{R: r, S: s})

		if err != nil {
			results = append(results, SignResult{Filename: file.Filename, Error: "failed to encode signature"})
			continue
		}

		results = append(results, SignResult{
			Filename:  file.Filename,
			Signature: hex.EncodeToString(asn1Signature),
		})
	}

	pk, _ := utils.GetPublicKey().Bytes()
	return c.JSON(fiber.Map{"results": results, "public_key": hex.EncodeToString(pk)})
}

func VerifySignature(c *fiber.Ctx) error {
	docFile, err := c.FormFile("document")

	if err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "document file required"})
	}

	fDoc, err := docFile.Open()

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"message": "failed to open document"})
	}

	defer fDoc.Close()

	docBytes := make([]byte, docFile.Size)
	fDoc.Read(docBytes)

	var sigBytes []byte

	sigFile, err := c.FormFile("signature_file")

	if err == nil {
		fSig, err := sigFile.Open()

		if err != nil {
			return c.Status(500).JSON(fiber.Map{"message": "failed to open signature file"})
		}

		defer fSig.Close()

		sigContent := make([]byte, sigFile.Size)
		fSig.Read(sigContent)
		sigBytes, err = hex.DecodeString(string(sigContent))

		if err != nil {
			sigBytes = sigContent
		}
	} else {
		sigHex := c.FormValue("signature")

		if sigHex == "" {
			return c.Status(400).JSON(fiber.Map{"message": "signature required (file or text)"})
		}

		sigBytes, err = hex.DecodeString(sigHex)

		if err != nil {
			return c.Status(400).JSON(fiber.Map{"message": "invalid hex signature"})
		}
	}

	publicKey := utils.GetPublicKey()
	pk, _ := publicKey.Bytes()
	hash := sha256.Sum256(docBytes)

	var sig EcdsaSignature

	if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "failed to parse ASN.1 signature"})
	}

	valid := ecdsa.Verify(publicKey, hash[:], sig.R, sig.S)

	// Proof of Possession
	if valid && bytes.Equal(docBytes, pk) {
		return c.JSON(fiber.Map{
			"filename": docFile.Filename,
			"valid":    valid,
			"flag":     os.Getenv("FLAG"),
		})
	}

	return c.JSON(fiber.Map{
		"filename": docFile.Filename,
		"valid":    valid,
	})
}
