package x509

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"io"
	"net"
	"net/url"
)

// CertificateRequest represents a PKCS #10, certificate signature request.
type CertificateRequest struct {
	Raw                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	RawTBSCertificateRequest []byte // Certificate request info part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo  []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject               []byte // DER encoded Subject.

	Version            int
	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	Subject pkix.Name

	// Attributes is the dried husk of a bug and shouldn't be used.
	Attributes []pkix.AttributeTypeAndValueSET

	// Extensions contains raw X.509 extensions. When parsing CSRs, this
	// can be used to extract extensions that are not parsed by this
	// package.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled CSR. Values override any extensions that would otherwise
	// be produced based on the other fields but are overridden by any
	// extensions specified in Attributes.
	//
	// The ExtraExtensions field is not populated when parsing CSRs, see
	// Extensions.
	ExtraExtensions []pkix.Extension

	// Subject Alternate Name values.
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// oidExtensionRequest is a PKCS#9 OBJECT IDENTIFIER that indicates requested
// extensions in a CSR.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func newRawAttributes(attributes []pkix.AttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw CSR Attributes")
	}
	return rawAttributes, nil
}

// parseRawAttributes Unmarshals RawAttributes intos AttributeTypeAndValueSETs.
func parseRawAttributes(rawAttributes []asn1.RawValue) []pkix.AttributeTypeAndValueSET {
	var attributes []pkix.AttributeTypeAndValueSET
	for _, rawAttr := range rawAttributes {
		var attr pkix.AttributeTypeAndValueSET
		rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
		// Ignore attributes that don't parse into pkix.AttributeTypeAndValueSET
		// (i.e.: challengePassword or unstructuredName).
		if err == nil && len(rest) == 0 {
			attributes = append(attributes, attr)
		}
	}
	return attributes
}

// parseCSRExtensions parses the attributes from a CSR and extracts any
// requested extensions.
func parseCSRExtensions(rawAttributes []asn1.RawValue) ([]pkix.Extension, error) {
	// pkcs10Attribute reflects the Attribute structure from section 4.1 of
	// https://tools.ietf.org/html/rfc2986.
	type pkcs10Attribute struct {
		ID     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}

	var ret []pkix.Extension
	for _, rawAttr := range rawAttributes {
		var attr pkcs10Attribute
		if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || len(rest) != 0 || len(attr.Values) == 0 {
			// Ignore attributes that don't parse.
			continue
		}

		if !attr.ID.Equal(oidExtensionRequest) {
			continue
		}

		var extensions []pkix.Extension
		if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &extensions); err != nil {
			return nil, err
		}
		ret = append(ret, extensions...)
	}

	return ret, nil
}

// CreateCertificateRequest creates a new certificate request based on a
// template. The following members of template are used: Attributes, DNSNames,
// EmailAddresses, ExtraExtensions, IPAddresses, URIs, SignatureAlgorithm, and
// Subject. The private key is the private key of the signer.
//
// The returned slice is the certificate request in DER encoding.
//
// All keys types that are implemented via crypto.Signer are supported (This
// includes *rsa.PublicKey and *ecdsa.PublicKey.)
func CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv interface{}) (csr []byte, err error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	var hashFunc Hash
	var sigAlgo pkix.AlgorithmIdentifier
	hashFunc, sigAlgo, err = signingParamsForPublicKey(key.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}

	var extensions []pkix.Extension

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		var sanBytes []byte
		sanBytes, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}

		extensions = append(extensions, pkix.Extension{
			ID:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	extensions = append(extensions, template.ExtraExtensions...)

	var attributes []pkix.AttributeTypeAndValueSET
	attributes = append(attributes, template.Attributes...)

	if len(extensions) > 0 {
		// specifiedExtensions contains all the extensions that we
		// found specified via template.Attributes.
		specifiedExtensions := make(map[string]bool)

		for _, atvSet := range template.Attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) {
				continue
			}

			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}
		}

		atvs := make([]pkix.AttributeTypeAndValue, 0, len(extensions))
		for _, e := range extensions {
			if specifiedExtensions[e.ID.String()] {
				// Attributes already contained a value for
				// this extension and it takes priority.
				continue
			}

			atvs = append(atvs, pkix.AttributeTypeAndValue{
				// There is no place for the critical flag in a CSR.
				Type:  e.ID,
				Value: e.Value,
			})
		}

		// Append the extensions to an existing attribute if possible.
		appended := false
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}

			atvSet.Value[0] = append(atvSet.Value[0], atvs...)
			appended = true
			break
		}

		// Otherwise, add a new attribute for the extensions.
		if !appended {
			attributes = append(attributes, pkix.AttributeTypeAndValueSET{
				Type: oidExtensionRequest,
				Value: [][]pkix.AttributeTypeAndValue{
					atvs,
				},
			})
		}
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return
		}
	}

	rawAttributes, err := newRawAttributes(attributes)
	if err != nil {
		return
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return
	}
	tbsCSR.Raw = tbsCSRContents

	h := hashFunc.New()
	_, _ = h.Write(tbsCSRContents)
	digest := h.Sum(nil)

	var signature []byte
	signature, err = key.Sign(rand, digest, hashFunc)
	if err != nil {
		return
	}

	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}

// ParseCertificateRequest parses a single certificate request from the
// given ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificateRequest(&csr)
}

func parseCertificateRequest(in *certificateRequest) (*CertificateRequest, error) {
	out := &CertificateRequest{
		Raw:                      in.Raw,
		RawTBSCertificateRequest: in.TBSCSR.Raw,
		RawSubjectPublicKeyInfo:  in.TBSCSR.PublicKey.Raw,
		RawSubject:               in.TBSCSR.Subject.FullBytes,

		Signature:          in.SignatureValue.RightAlign(),
		SignatureAlgorithm: getSignatureAlgorithmFromAI(in.SignatureAlgorithm),

		PublicKeyAlgorithm: getPublicKeyAlgorithmFromOID(in.TBSCSR.PublicKey.Algorithm.Algorithm),

		Version:    in.TBSCSR.Version,
		Attributes: parseRawAttributes(in.TBSCSR.RawAttributes),
	}

	var err error
	out.PublicKey, err = parsePublicKey(out.PublicKeyAlgorithm, &in.TBSCSR.PublicKey)
	if err != nil {
		return nil, err
	}

	var subject pkix.RDNSequence
	var rest []byte
	if rest, err = asn1.Unmarshal(in.TBSCSR.Subject.FullBytes, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 Subject")
	}

	out.Subject.FillFromRDNSequence(&subject)

	if out.Extensions, err = parseCSRExtensions(in.TBSCSR.RawAttributes); err != nil {
		return nil, err
	}

	for _, extension := range out.Extensions {
		if extension.ID.Equal(oidExtensionSubjectAltName) {
			out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, err = parseSANExtension(extension.Value)
			if err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// CheckSignature reports whether the signature on c is valid.
func (c *CertificateRequest) CheckSignature() error {
	return checkSignature(c.SignatureAlgorithm, c.RawTBSCertificateRequest, c.Signature, c.PublicKey)
}
