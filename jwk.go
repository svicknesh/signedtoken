package signedtoken

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

// JWK - RSA & EC keys is in JWK format
type JWK struct {
	Kty string `yaml:"kty,omitempty" json:"kty,omitempty"`
	Crv string `yaml:"crv,omitempty" json:"crv,omitempty"`
	N   string `yaml:"n,omitempty" json:"n,omitempty"`
	E   string `yaml:"e,omitempty" json:"e,omitempty"`
	G   string `yaml:"g,omitempty" json:"g,omitempty"`
	P   string `yaml:"p,omitempty" json:"p,omitempty"`
	Q   string `yaml:"q,omitempty" json:"q,omitempty"`
	X   string `yaml:"x,omitempty" json:"x,omitempty"`
	Y   string `yaml:"y,omitempty" json:"y,omitempty"`
	D   string `yaml:"d,omitempty" json:"d,omitempty"`
	DP  string `yaml:"dp,omitempty" json:"dp,omitempty"`
	DQ  string `yaml:"dq,omitempty" json:"dq,omitempty"`
	QI  string `yaml:"qi,omitempty" json:"qi,omitempty"`
	Kid string `yaml:"kid,omitempty" json:"kid,omitempty"`
}

// New - creates a new instance of JWK from a given key
func New(key interface{}) (j *JWK, err error) {

	j = new(JWK)

	set, err := jwk.New(key)
	if nil != err {
		return nil, fmt.Errorf("newjwk init: %w", err)
	}

	err = jwk.AssignKeyID(set)
	if nil != err {
		return nil, fmt.Errorf("newjwk assignkeyid: %w", err)
	}

	jwkBytes, err := json.Marshal(set)
	if nil != err {
		return nil, fmt.Errorf("newjwk marshal: %w", err)
	}

	err = json.Unmarshal(jwkBytes, j)

	return
}

// ToJWK - creates a new `JWK` istance from a given JWK string bytes
func ToJWK(bytes []byte) (j *JWK, err error) {

	j = new(JWK)
	err = json.Unmarshal(bytes, j)

	return
}

// Bytes - returns a JSON bytes of this JWK instance
func (j *JWK) Bytes() (bytes []byte) {
	bytes, _ = json.Marshal(j)
	return bytes
}

// String - returns a JSON string of this JWK instance
func (j *JWK) String() (str string) {
	return string(j.Bytes())
}

func (j *JWK) ToKey() (key interface{}, err error) {

	jwkBytes, err := json.Marshal(j)
	if nil != err {
		return nil, fmt.Errorf("tokey: %w", err)
	}

	jkey, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("tokey: %w", err)
	}

	if err = jkey.Raw(&key); err != nil {
		return nil, fmt.Errorf("tokey: %w", err)
	}

	return
}
