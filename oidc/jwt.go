package oidc

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"

	// "github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// implemented using https://github.com/lestrrat-go/jwx

// var key string = "pAHlvdVt5MpvZQPFe2x-legbvqd0StLQ-ewqevwJ4YEDzP_hBgkcrD_BJi0j5DgXAMR5HKjW-cEqXZ7wvmf_LGkAdTcj0X8BSJqKbyR5U_DHpt1Ux7sI7yhS91BVrNtFVDi-DKXngEt0rTsBx3JObwNZSFa-Q4UCcHAYcol_3m-Kp1Jtmy72OMnrDZ_zLjclYfhIJLkuBC_JjY-sI3XrELdxLBfw7FEc0bT-Ze7OXOuWjr5mWM4sX4nUXlEpl9KkFPB1-mrBi63Kab1tAPzHf4ANE9wc06huT3KTYCJ1mOYis3HhKAoeAXmYQe5A23_MCgpw6KBvah5MiY0DH5aL9w"

// ParseJWKs takes the jwks endpoint response as string & returns the array of *rsa.PublicKey, else error
func ParseJWKs(jwksJson string) ([]*rsa.PublicKey, error) {

	var keys []*rsa.PublicKey
	set, err := jwk.Parse([]byte(jwksJson))
	if err != nil {
		panic(err)
	}
	fmt.Println(set)
	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			log.Printf("failed to create public key: %s", err)
			return nil, err
		}

		// We know this is an RSA Key so...
		rsa, ok := rawkey.(*rsa.PublicKey)
		if !ok {
			panic(fmt.Sprintf("expected ras key, got %T", rawkey))
		}
		// As this is a demo just dump the key to the console
		// fmt.Println(rsa)
		keys = append(keys, rsa)
	}

	return keys, nil
}

func ValidateJwt(tokenString string) error {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return err
	}

	fmt.Println(token.Issuer())

	for k, v := range token.PrivateClaims() {
		fmt.Printf("%v= %v\n", k, v)
	}

	return nil
}

// func ValidateJwt(tokenStr string) error {

// 	token, err := jwt.Parse(tokenStr, fetchKey)

// 	if err != nil {
// 		// TODO: @esiddiqui use errors.Is() to return more details.
// 		return err
// 	}
// 	if !token.Valid {
// 		return fmt.Errorf("token is not valid")
// 	}
// 	return nil
// }

// func fetchKey(*jwt.Token) (interface{}, error) {
// 	kk := rsa.PublicKey
// 	return []byte(key), nil
// 	// return jwt.ParseRSAPublicKeyFromPEM([]byte(key))
// 	// return []byte(key), nil
// }

// func verifyToken(t string) (*verifier.Jwt, error) {
// 	tv := map[string]string{}
// 	tv["nonce"] = nonce
// 	tv["aud"] = os.Getenv("CLIENT_ID")
// 	jv := verifier.JwtVerifier{
// 		Issuer:           os.Getenv("ISSUER"),
// 		ClaimsToValidate: tv,
// 	}

// 	result, err := jv.New().VerifyIdToken(t)
// 	if err != nil {
// 		return nil, fmt.Errorf("%s", err)
// 	}

// 	if result != nil {
// 		return result, nil
// 	}

// 	return nil, fmt.Errorf("token could not be verified: %s", "")
// }
