package signedtoken

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

const (
	ES256       jwa.SignatureAlgorithm = jwa.ES256
	ES256K      jwa.SignatureAlgorithm = jwa.ES256K
	ES384       jwa.SignatureAlgorithm = jwa.ES384
	ES512       jwa.SignatureAlgorithm = jwa.ES512
	EdDSA       jwa.SignatureAlgorithm = jwa.EdDSA
	HS256       jwa.SignatureAlgorithm = jwa.HS256
	HS384       jwa.SignatureAlgorithm = jwa.HS384
	HS512       jwa.SignatureAlgorithm = jwa.HS512
	NoSignature jwa.SignatureAlgorithm = jwa.NoSignature
	PS256       jwa.SignatureAlgorithm = jwa.PS256
	PS384       jwa.SignatureAlgorithm = jwa.PS384
	PS512       jwa.SignatureAlgorithm = jwa.PS512
	RS256       jwa.SignatureAlgorithm = jwa.RS256
	RS384       jwa.SignatureAlgorithm = jwa.RS384
	RS512       jwa.SignatureAlgorithm = jwa.RS512
)

// Header - header for JWS
type Header struct {
	Alg   string `json:"alg,omitempty"`
	KeyID string `json:"kid,omitempty"`
}

// GenerateJWS - generates a new JWS from the given input
func GenerateJWS(j *JWK, payload []byte) (jwsBytes []byte, err error) {

	set, _ := jwk.Parse([]byte(j.String()))
	//privKey, _ := set.LookupKeyID(keyidAttr.KeyID)
	privKey, ok := set.Get(0) // we know there is only 1 key in the set
	if !ok {
		return nil, fmt.Errorf("generatejws: failed to decode private key")
	}

	var sigAlg jwa.SignatureAlgorithm
	if j.Kty == "EC" {
		switch j.Crv {
		case "P-256":
			sigAlg = jwa.ES256
		case "P-384":
			sigAlg = jwa.ES384
		case "P-521":
			sigAlg = jwa.ES512
		default:
			return nil, fmt.Errorf("generatejws: unsupported EC curve %s", j.Crv)
		}
	} else if j.Kty == "RSA" {
		sigAlg = jwa.RS256 // we always use SHA-256 for RSA keys
	} else {
		return nil, fmt.Errorf("generatejws: unsupported key type %s", j.Kty)
	}

	jwsBytes, err = jws.Sign(payload, sigAlg, privKey)

	return
}

// GenerateJWSWithAlg - generates a new JWS from the given input using the given algorithm
func GenerateJWSWithAlg(j *JWK, payload []byte) (jwsBytes []byte, err error) {

	set, _ := jwk.Parse([]byte(j.String()))
	//privKey, _ := set.LookupKeyID(keyidAttr.KeyID)
	privKey, ok := set.Get(0) // we know there is only 1 key in the set
	if !ok {
		return nil, fmt.Errorf("generatejws: failed to decode private key")
	}

	var sigAlg jwa.SignatureAlgorithm
	if j.Kty == "EC" {
		switch j.Crv {
		case "P-256":
			sigAlg = jwa.ES256
		case "P-384":
			sigAlg = jwa.ES384
		case "P-521":
			sigAlg = jwa.ES512
		default:
			return nil, fmt.Errorf("generatejws: unsupported EC curve %s", j.Crv)
		}
	} else if j.Kty == "RSA" {
		sigAlg = jwa.RS256 // we always use SHA-256 for RSA keys
	} else {
		return nil, fmt.Errorf("generatejws: unsupported key type %s", j.Kty)
	}

	jwsBytes, err = jws.Sign(payload, sigAlg, privKey)

	return
}

// VerifyJWS - verifies a given JWS input
func VerifyJWS(j *JWK, jwsBytes []byte) (payload []byte, err error) {

	jwkBytes, err := json.Marshal(j)
	if nil != err {
		return nil, fmt.Errorf("verifyjws: %w", err)
	}

	var rawkey interface{}

	var pubKey interface{}
	var ecPrivKey *ecdsa.PrivateKey
	var ok bool
	var sigAlg jwa.SignatureAlgorithm

	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("verifyjws: %w", err)
	}

	if err = key.Raw(&rawkey); err != nil {
		return nil, fmt.Errorf("verifyjws: %w", err)
	}

	if j.Kty == "EC" {
		ecPrivKey, ok = rawkey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("verifyjws: invalid EC key")
		}

		pubKey = ecPrivKey.PublicKey

		switch j.Crv {
		case "P-256":
			sigAlg = jwa.ES256
		case "P-384":
			sigAlg = jwa.ES384
		case "P-521":
			sigAlg = jwa.ES512
		default:
			return nil, fmt.Errorf("generatejws: unsupported EC curve %s", j.Crv)
		}

	} else if j.Kty == "RSA" {

		var rsaPrivKey *rsa.PrivateKey
		rsaPrivKey, ok = rawkey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("verifyjws: invalid RSA key")
		}

		pubKey = rsaPrivKey.PublicKey

		sigAlg = jwa.RS256 // we always use SHA-256 for RSA keys

	} else {
		return nil, fmt.Errorf("unsupported key type %s", j.Kty)
	}

	payload, err = jws.Verify(jwsBytes, jwa.SignatureAlgorithm(sigAlg), pubKey)

	return
}

// GetJWSHeader - gets the JWS header
func GetJWSHeader(jwsBytes []byte) (header *Header, err error) {

	// split the string by period (.)
	jwsComponents := strings.Split(string(jwsBytes), ".")
	//fmt.Println(jwsComponents)

	if len(jwsComponents) != 3 {
		return nil, fmt.Errorf("invalid JWS") // if this is not a valid JWS, return immediately
	}

	// transform the header into its json structure
	jwsHeader, err := b64Decode([]byte(jwsComponents[0]))
	if nil != err {
		return
	}

	header = new(Header)
	err = json.Unmarshal(jwsHeader, header)

	return
}

// b64Decode - extracted from `github.com/lestrrat-go/jwx/internal/base64` to decode the base64 header
func b64Decode(src []byte) ([]byte, error) {
	var enc *base64.Encoding

	var isRaw = !bytes.HasSuffix(src, []byte{'='})
	var isURL = !bytes.ContainsAny(src, "+/")
	switch {
	case isRaw && isURL:
		enc = base64.RawURLEncoding
	case isURL:
		enc = base64.URLEncoding
	case isRaw:
		enc = base64.RawStdEncoding
	default:
		enc = base64.StdEncoding
	}

	dst := make([]byte, enc.DecodedLen(len(src)))
	n, err := enc.Decode(dst, src)
	if err != nil {
		return nil, errors.Wrap(err, `failed to decode source`)
	}
	return dst[:n], nil
}
