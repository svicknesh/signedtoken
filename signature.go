package signedtoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/jwk"
)

// ecdsasig - ecdsa encoding using ASN.1
type ecdsasig struct {
	R, S *big.Int
}

// Sign - signs the given input with the given JWK RSA or ECDSA private key
func Sign(j *JWK, hashed []byte) (sig []byte, err error) {

	// convert JWK to private key

	jwkBytes, err := json.Marshal(j)
	if nil != err {
		return nil, fmt.Errorf("sign: %w", err)
	}

	var rawkey interface{}

	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	if err = key.Raw(&rawkey); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	switch j.Kty {
	case "EC":
		ecPrivKey, ok := rawkey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("sign: invalid EC private key found")
		}

		// we found the ECDSA private key
		var encode ecdsasig
		encode.R, encode.S, err = ecdsa.Sign(rand.Reader, ecPrivKey, hashed)
		if nil != err {
			return nil, fmt.Errorf("sign: %w", err)
		}

		return asn1.Marshal(encode)

	case "RSA":
		rsaPrivKey, ok := rawkey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("sign: invalid RSA private key found")
		}

		// we found the RSA private key
		// RSA is always signed using SHA2-256
		return rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, crypto.SHA256, hashed)

	case "OKP":
		ed25519PrivKey, ok := rawkey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("sign: invalid ED25519 private key found")
		}

		return ed25519.Sign(ed25519PrivKey, hashed), nil

	}

	return nil, fmt.Errorf("sign: no valid private key found")
}

// Verify - verifies a given signature using the recipient's JWK RSA or ECDSA public key
func Verify(j *JWK, hashed, sig []byte) (err error) {

	// convert JWK to public key

	jwkBytes, err := json.Marshal(j)
	if nil != err {
		return fmt.Errorf("verify: %w", err)
	}

	var rawkey interface{}
	//var rsaPubKey *rsa.PublicKey
	//var ecPubKey *ecdsa.PublicKey
	//var ok bool

	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	if err = key.Raw(&rawkey); err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	switch j.Kty {
	case "EC":
		ecPubKey, ok := rawkey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("sign: invalid EC public key found")
		}

		// we found the ECDSA public key
		var decode ecdsasig

		_, err = asn1.Unmarshal(sig, &decode)
		if nil != err {
			return fmt.Errorf("verify: %w", err)
		}

		if !ecdsa.Verify(ecPubKey, hashed, decode.R, decode.S) {
			err = fmt.Errorf("verify: ECDSA signature verification failed")
		}

		return

	case "RSA":

		rsaPubKey, ok := rawkey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("sign: invalid RSA public key found")
		}

		// we found the RSA public key
		// RSA is always signed using SHA2-256
		return rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed, sig)

	case "OKP":

		ed25519PubKey, ok := rawkey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("sign: invalid ED25519 public key found")
		}

		if ok := ed25519.Verify(ed25519PubKey, hashed, sig); !ok {
			err = errors.New("verify: ED25519 signature verification failed")
		}

		return

	}

	return fmt.Errorf("sign: no valid public key found")

}
