package x509

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
)

//SubjectBytesWhenMarshal returns the bytes of subject when marshal a certificate
func SubjectBytesWhenMarshal(cert *Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}
	var ret pkix.RDNSequence
	for _, atv := range cert.Subject.Names {
		ret = append(ret, []pkix.AttributeTypeAndValue{atv})
	}
	return asn1.Marshal(ret)
}

// signParamsForPublicKey returns the parameters to use SignatureAlgorithm
// If requestedSigAlgo is not zero then it overrides the default
// signature algorithm.
func signParamsForPublicKey(requestedSigAlgo SignatureAlgorithm) (hashFunc Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType PublicKeyAlgorithm

	switch requestedSigAlgo {
	case
		MD2WithRSA,
		MD5WithRSA,
		SHA1WithRSA,
		SHA256WithRSA,
		SHA384WithRSA,
		SHA512WithRSA:

		pubType = RSA
		hashFunc = SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.NullRawValue

	case
		ECDSAWithSHA1,
		ECDSAWithSHA256,
		ECDSAWithSHA384,
		ECDSAWithSHA512:

		pubType = ECDSA

		switch requestedSigAlgo {
		case ECDSAWithSHA256:
			hashFunc = SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case ECDSAWithSHA384:
			hashFunc = SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case ECDSAWithSHA512:
			hashFunc = SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}
	case
		SM3WithSM2,
		SHA1WithSM2,
		SHA256WithSM2,
		SHA512WithSM2,
		SHA224WithSM2,
		SHA384WithSM2,
		RMD160WithSM2:

		pubType = SM2

		switch requestedSigAlgo {
		case SM3WithSM2:
			hashFunc = SM3
			sigAlgo.Algorithm = oidSignatureSM3WithSM2
		default:
			err = errors.New("x509: unknown SM2 curve")
		}
	default:
		err = errors.New("x509: only RSA, ECDSA and SM2 keys supported")
	}

	if err != nil {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			if requestedSigAlgo.isRSAPSS() {
				sigAlgo.Parameters = rsaPSSParameters(crypto.Hash(hashFunc))
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}
