package signedtoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"
	"time"
)

func TestSign(t *testing.T) {

	hashed1 := sha256.Sum256([]byte("hello world")) // RSA only accepts SHA2-256 but ECDSA can use anything, including SHA3

	// try EC key

	privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	privateECJWK, err := New(privateKey)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	sigECDSA, err := Sign(privateECJWK, hashed1[:]) // input must be a sha256 hashed message
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println(sigECDSA)

	publicECJWK, err := New(&privateKey.PublicKey)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	err = Verify(publicECJWK, hashed1[:], sigECDSA)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	} else {
		fmt.Println("ECDSA signature matches")
	}

	// try RSA key
	privateRSAkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	privateRSAJWK, err := New(privateRSAkey)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	sigRSA, err := Sign(privateRSAJWK, hashed1[:]) // input must be a sha256 hashed message
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println(sigRSA)

	publicRSAJWK, err := New(&privateRSAkey.PublicKey)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	err = Verify(publicRSAJWK, hashed1[:], sigRSA)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	} else {
		fmt.Println("RSA signature matches")
	}

}

func TestJWS(t *testing.T) {

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	privateECJWK, err := New(privateKey)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	privateECJWK.Kid = "abc"
	fmt.Println(privateECJWK.Kty)

	type input struct {
		Subject   string `json:"sub,omitempty"`
		Audience  string `json:"aud,omitempty"`
		IssuedAt  int64  `json:"iat,omitempty"`
		NotBefore int64  `json:"nbf,omitempty"`
		Expire    int64  `json:"exp,omitempty"`
	}

	i := new(input)

	i.IssuedAt = time.Now().UTC().Unix()
	i.NotBefore = i.IssuedAt
	i.Expire = time.Now().AddDate(1, 0, 0).UTC().Unix()
	i.Audience = "me"
	i.Subject = "supersubject"

	iBytes, _ := json.Marshal(i)

	//jwtBytes, err := GenerateJWS(privateECJWK, iBytes)
	jwtBytes, err := GenerateJWSWithAlg(privateECJWK, iBytes)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	//fmt.Println(string(jwtBytes))

	/*
		h, err := GetJWSHeader(jwtBytes)
		if nil != err {
			log.Println(err)
			os.Exit(1)
		}
	*/

	//payload, err := VerifyJWS(privateECJWK, jwtBytes, jwa.SignatureAlgorithm(h.Alg))
	payload, err := VerifyJWS(privateECJWK, jwtBytes)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(payload))

}
