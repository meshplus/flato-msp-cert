package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseAndMarshalPKCS1PrivateKey(t *testing.T) {
	PemBlocks, _ := pem.Decode([]byte(RSAPrivateKey))
	_, err := ParsePKCS1PrivateKey(PemBlocks.Bytes)
	assert.Nil(t, err)

	PemBlocks, _ = pem.Decode([]byte(RSAPrivateKey))
	RSAPrivKey, err := ParsePKCS1PrivateKey(PemBlocks.Bytes)
	assert.Nil(t, err)
	key := MarshalPKCS1PrivateKey(RSAPrivKey)
	assert.Equal(t, PemBlocks.Bytes, key)
}

func TestParseAndMarshalPKCS1PublicKey(t *testing.T) {

	//PemBlocks, _ := pem.Decode([]byte(RSAPublicKey))
	//RSAPubKey, err := ParsePKCS1PublicKey(PemBlocks.Bytes)
	//assert.Nil(t, err)
	//key := MarshalPKCS1PublicKey(RSAPubKey)
	//assert.NotNil(t, err)
	//assert.Equal(t, PemBlocks.Bytes, key)

	public, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.Nil(t, err)
	var pubKey interface{}
	pubKey = &rsa.PublicKey{N: public.N, E: public.E}
	pub, ok := pubKey.(*rsa.PublicKey)
	assert.True(t, ok)
	bytes := MarshalPKCS1PublicKey(pub)
	publicKey, err := ParsePKCS1PublicKey(bytes)
	assert.Nil(t, err)
	assert.Equal(t, pub, publicKey)
}

const RSAPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDKafSoerj2aTZvu1X/dXfKXhRFMfiAid14qmGCOJWGS2ek5UzA
DuM7O38cBqFXgD7/n34rq8W6Hwo6B3vIH3ynsFZIoL+VzO1KSHUsL7FIcagUM+lW
0La/vz6a7FI14OPwhOzvK4sspw1nXZHUS9Xv3gFdyRJN3arEtL/wwUcLHQIDAQAB
AoGAGnZvvfcNZ2mp7EGZpKQ+3P4fuEwoKOXdRoE/7j5njf8dtbkkp5dKrdvBanCT
d1UU52Z6oEr8trCILb38uNUk/qulZQtOdy/cdYabAcsE7nJgy4QXR0b7NhrYhJhf
iKrE41iQVaItbbAzZQ5Nfbaobzdbuup/oLnLObE3dmJG/SECQQD1rjfjVv/2c4Om
0WLUFdIblv5if2I/oBCTb+JQfnQl4quqfQeYvwdjk1Aois+VGuTAAF7Llb5L5StY
tudlRRw3AkEA0up+rBf1QqWYpXLGEgZDrsTl3cKI0RLyZXRiiBp6blmG5sG00wE2
yJVsAv6IS3ZEQFYFvGUKJhc+KCGrIUjxSwJBAKy+yDtI1Ad1J4+nUKcxhJ+zpsCZ
Mvrr0Fvq4qWYlJCC9hOVgD7tqwNf9I/dMqJz234JhJ3/d2OkCruBN+jkFDcCQQCM
PHxDAp8BVEedYiXOYDnqX2KTQ0Bi+x0OVgcZhbl327D1h0Aqt/jr/2XUy9Zljlot
CMVBkVDhKL0cQ96b//rnAkEAqA9YVBclpNp5xvSL7cxHGT3VPvmQBWjJZyA7XK9a
goMCvzaQtcrQ6FQ9o1Knbo4XUlRN3LVnu+XSfWhmyH/0rA==
-----END RSA PRIVATE KEY-----`

//nolint: unused
const RSAPublicKey = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`
