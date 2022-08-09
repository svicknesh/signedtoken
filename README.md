# Signed Token

Golang library to created signed tokens for whatever use case you may think off. Some of the potential use cases are
- Authorization tokens using public/private key.
- File integrity checking for each individual.
- Creating revision information and signing them to prevent tampering.
- and so many other ideas ...


## Usage

### ECDSA signing and verification

```go

// generate public and private ECDSA key

// convert an ECDSA private key to this library's `JWK` format before using.
privateECJWK, err := signedtoken.New(privateKey)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// sign the input. input **MUST** be hashed message, ECDSA can accept any hashed input, SHA2 or SHA3 preferred
// for signing we use the ECDSA private key
sigECDSA, err := signedtoken.Sign(privateECJWK, hashed1[:])
if nil != err {
    log.Println(err)
    os.Exit(1)
}
fmt.Println(sigECDSA)


// convert an ECDSA public key to this library's `JWK` format before using.
publicECJWK, err := signedtoken.New(&privateKey.PublicKey)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// verify a signature given the recipient's public key and hashed input (as used for signing)
err = signedtoken.Verify(publicECJWK, hashed1[:], sigECDSA)
if nil != err {
    log.Println(err)
    os.Exit(1)
} else {
    fmt.Println("ECDSA signature matches")
}

```


### RSA signing and verification

```go

// generate public and private RSA key

// convert an RSA private key to this library's `JWK` format before using.
privateRSAJWK, err := New(privateKey)
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// sign the input. input **MUST** be hashed message, RSADSA can accept any hashed input, SHA2 or SHA3 preferred
// for signing we use the RSADSA private key
sigEC, err := Sign(privateRSAJWK, hashed1[:]) // result is in PKCS1 format in bytes
if nil != err {
    log.Println(err)
    os.Exit(1)
}
fmt.Println(sigEC)


// convert an RSADSA public key to this library's `JWK` format before using.
publicRSAJWK, err := New(&privateKey.PublicKey) // result is in ASN.1 encoding for the values of `R` and `S` in bytes
if nil != err {
    log.Println(err)
    os.Exit(1)
}

// verify a signature given the rRSAipient's public key and hashed input (as used for signing)
err = Verify(publicRSAJWK, hashed1[:], sigEC)
if nil != err {
    log.Println(err)
    os.Exit(1)
} else {
    fmt.Println("RSADSA signature matches")
}

```
