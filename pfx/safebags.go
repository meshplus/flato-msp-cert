// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"github.com/meshplus/crypto-gm"
	"github.com/meshplus/flato-msp-cert/primitives"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"io"
)

var (
	// see https://tools.ietf.org/html/rfc7292#appendix-D
	oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
	oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
	oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
)

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

func decodePkcs8ShroudedKeyBag(asn1Data, password []byte) (privateKey interface{}, err error) {
	pkinfo := new(encryptedPrivateKeyInfo)
	if err = unmarshal(asn1Data, pkinfo); err != nil {
		return nil, errors.New("pkcs12: error decoding PKCS#8 shrouded key bag: " + err.Error())
	}

	pkData, err := pbDecrypt(pkinfo, password)
	if err != nil {
		return nil, errors.New("pkcs12: error decrypting PKCS#8 shrouded key bag: " + err.Error())
	}

	ret := new(asn1.RawValue)
	if err = unmarshal(pkData, ret); err != nil {
		return nil, errors.New("pkcs12: error unmarshaling decrypted private key: " + err.Error())
	}

	if privateKey, err = primitives.UnmarshalPrivateKey(pkData); err != nil {
		return nil, errors.New("pkcs12: error parsing private key: " + err.Error())
	}

	return privateKey, nil
}

func encodePkcs8ShroudedKeyBag(rand io.Reader, privateKey crypto.Signer, password []byte) (asn1Data []byte, err error) {
	var pkData []byte
	key, ok := privateKey.(*gm.SM2PrivateKey)
	if !ok {
		if pkData, err = gmx509.MarshalPKCS8PrivateKey(privateKey); err != nil {
			return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
		}
	} else {
		if pkData, err = primitives.MarshalPrivateKey(key); err != nil {
			return nil, err
		}
	}

	randomSalt := make([]byte, 8)
	_, _ = rand.Read(randomSalt)
	var paramBytes []byte
	if paramBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: 2048}); err != nil {
		return nil, errors.New("pkcs12: error encoding params: " + err.Error())
	}

	var pkinfo encryptedPrivateKeyInfo
	pkinfo.AlgorithmIdentifier.Algorithm = oidPBEWithSHAAnd3KeyTripleDESCBC
	pkinfo.AlgorithmIdentifier.Parameters.FullBytes = paramBytes

	if err = pbEncrypt(&pkinfo, pkData, password); err != nil {
		return nil, errors.New("pkcs12: error encrypting PKCS#8 shrouded key bag: " + err.Error())
	}

	if asn1Data, err = asn1.Marshal(pkinfo); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 shrouded key bag: " + err.Error())
	}

	return asn1Data, nil
}

func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err error) {
	bag := new(certBag)
	if err := unmarshal(asn1Data, bag); err != nil {
		return nil, errors.New("pkcs12: error decoding cert bag: " + err.Error())
	}
	if !bag.ID.Equal(oidCertTypeX509Certificate) {
		return nil, NotImplementedError("only X509 certificates are supported")
	}
	return bag.Data, nil
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err error) {
	var bag certBag
	bag.ID = oidCertTypeX509Certificate
	bag.Data = x509Certificates
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, errors.New("pkcs12: error encoding cert bag: " + err.Error())
	}
	return asn1Data, nil
}
