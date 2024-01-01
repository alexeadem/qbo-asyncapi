package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    //"crypto/x509"
    //"encoding/pem"
    "fmt"
    //"log"
    "math/big"
    //"os"

    b64 "encoding/base64"

    //"github.com/contiamo/jwt"

    // gojose "gopkg.in/square/go-jose.v2"
    gojose "github.com/go-jose/go-jose/v3"
    //jwtgo "github.com/dgrijalva/jwt-go"
)

func main() {

    testgojmx()
}

func testgojmx() {
    plaintext := []byte("66fac858-a271-49cf-bad0-fdd9ff0b4787")

    xEnc := "AMu-cWn4gmkQiCAJMeW4BfZUAhPwAA3rROnw6nGUk8hl3bvV7gKKng2Eov6oxTvg70kulH6Nbq2wvJbAzyAjnPlT"
    yEnc := "Ab7VgSfOzG-7IgRF6ffUn5E0J43eDL8_vFtFtP7RihVgNBMUeZzo0yaskfx59SdqnL8q24wEHSTp4dDUxNal3kQ1"
    dEnc := "AVuTcFe_AJetnzt2xYQu2M505A3YNoAiHgh7JlkbFJq7H3UNjmaEhawPiK0AU8IoimyfoN4cCSlF087u1_Cytqw7"
    
    x := new(big.Int)
    temp, _ := b64.URLEncoding.DecodeString(xEnc)
    x = x.SetBytes(temp)

    y := new(big.Int)
    temp, _ = b64.URLEncoding.DecodeString(yEnc)
    y = y.SetBytes(temp)

    d := new(big.Int)
    temp, _ = b64.URLEncoding.DecodeString(dEnc)
    d = d.SetBytes(temp)

    privkey := new(ecdsa.PrivateKey)

    privkey.PublicKey.Curve = elliptic.P521()
    privkey.D = d
    privkey.PublicKey.X = x
    privkey.PublicKey.Y = y

    //javaKey := `{"kty":"EC","d":"AGPoHUdXajyyRLV0bAokQTnDzlO7Kjs1zSucSu69CGfSwpg7oXSxlfptApD-5O47d1PX3y0ag5228XsPFXVzYnH0","crv":"P-521","x":"AVuFsno89wJ5xT2z63iznxVO8H5gsfcHmS1XJ_JbfEzIsudqjrvKGrzxJT96-dmP_NY7KeMvyJEUInmqcqCWbzcQ","y":"ANv5hayQ3_TwMcFqPrtw-a9wNkfQuynuWhhbWOXYvGArdvibDGYRIRx3O5gAjfyumpibZFQ0K0jrjb09YP3AVbtc"}`
    //jwkSet, err := jwk.ParseString(javaKey)

    //if err != nil {
    //  panic(err)
    //}

    //key, err := jwkSet.Keys[0].Materialize()

    //if err != nil {
    //  panic(err)
    //}

    //privkey := key.(*ecdsa.PrivateKey)

    fmt.Printf("X: %d\nY: %d\nD: %d\n", privkey.X, privkey.Y, privkey.D)

    //A256CBC-HS512
    //A256GCM
    encrypter, err := gojose.NewEncrypter(gojose.A256CBC_HS512, gojose.Recipient{Algorithm: gojose.ECDH_ES, Key: privkey.Public()}, nil)
    if err != nil {
        panic(err)
    }

    encrypted, err := encrypter.Encrypt(plaintext)
    if err != nil {
        panic(err)
    }

    fmt.Printf("encrypted = %v\n", encrypted.Header)

    compact, err := encrypted.CompactSerialize()
    if err != nil {
        panic(err)
    }

    //compact = "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBRUFNS2ZGQ3p5NlY2WmdPdEFjSEh1c0VEM0syUC1aZmdrd2xLWmxtRFJaeGVLcTh4dUx0cXJDTzFycWx5Wkh5MXpfOEVmWXFNM0F6YlI3UGNhQVdCTURkIiwieSI6IkFMUWpEQjNLWWpLQ2twUUsxd0VUVmtvbXZ1ZDRkT05LeXhMeFJVcGpsQ0ZNSnl1bXFlUjJvc0d4N0w3UC1aU19vemJDTnhLaWU1RVQtdlNXUXczRmNLMDAifSwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IkVDREgtRVMifQ..4pyFf4sd5muL9Ony.TOMCKHHWd20nPU8.NN6MFByRemeyNa50yJGVUQ"

    fmt.Printf("Compact Encrypted: %v\n", compact)

    msg, _ := gojose.ParseEncrypted(compact)
    fmt.Printf("Message from Encrypted: %v\n", msg.Header)

    decrypted, err := msg.Decrypt(privkey)

    fmt.Printf("Decrtyped: %s\n", decrypted)
}
