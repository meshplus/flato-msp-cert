// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/rand"
	"encoding/asn1"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
	"github.com/meshplus/flato-msp-cert/primitives"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

func TestUnmarshal(t *testing.T) {
	params, _ := asn1.Marshal(pbeParams{
		Salt:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	})
	alg := pkix.AlgorithmIdentifier{
		Algorithm: sha1WithTripleDES,
		Parameters: asn1.RawValue{
			FullBytes: params,
		},
	}
	err := unmarshal(alg.Parameters.FullBytes, &params)
	assert.NotNil(t, err)
}

func TestDecode(t *testing.T) {
	var (
		err                error
		signatureAlgorithm gmx509.SignatureAlgorithm
		privKey            crypto.SignKey
	)
	_, privKey, _ = plugin.GetCryptoEngine().CreateSignKey(false, crypto.Sm2p256v1)
	signatureAlgorithm = gmx509.SM3WithSM2
	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	Subject := pkix.Name{
		CommonName:   "www.hyperchain.cn",
		Organization: []string{"Hyperchain"},
		Country:      []string{"CHN"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			// This should override the Country, above.
			{
				Type:  []int{2, 5, 4, 6},
				Value: "ZH",
			},
		},
	}
	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	engine := plugin.GetSoftwareEngine("")
	cert, err := gmx509.CreateCertificate(rand.Reader, &template, &template, privKey, privKey)

	if err != nil {
		return
	}
	ca, _ := gmx509.ParseCertificate(engine, cert)
	pfxdata, err := Encode(rand.Reader, privKey, ca, nil, "")
	if err != nil {
		return
	}
	pri, _, err := Decode(pfxdata, "")
	if err != nil {
		return
	}
	assert.NotNil(t, pri)
}

func TestGetSafeContentsError(t *testing.T) {
	_, _, err := getSafeContents([]byte(""), nil)
	assert.NotNil(t, err)
}

func TestDecodeChainError(t *testing.T) {
	_, _, _, err := DecodeChain([]byte(""), "")
	assert.NotNil(t, err)
}

func TestEncodeError(t *testing.T) {
	engine := plugin.GetSoftwareEngine("")
	certificate, key, err := primitives.NewSelfSignedCert(engine, "", "", "", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	cert, err := primitives.ParseCertificate(engine, certificate)
	assert.Nil(t, err)
	vk, err := engine.GetSignKey(key, crypto.None)
	assert.Nil(t, err)
	_, err = Encode(rand.Reader, vk, cert, nil, "")
	assert.Nil(t, err)
}
