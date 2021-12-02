package x509

import (
	"errors"
	"fmt"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
)

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

//InsecureAlgorithmError An InsecureAlgorithmError
type InsecureAlgorithmError SignatureAlgorithm

func (e InsecureAlgorithmError) Error() string {
	return fmt.Sprintf("x509: cannot verify signature: insecure algorithm %v", SignatureAlgorithm(e))
}

// ConstraintViolationError results when a requested usage is not permitted by
// a certificate. For example: checking a signature when the public key isn't a
// certificate signing key.
type ConstraintViolationError struct{}

func (ConstraintViolationError) Error() string {
	return "x509: invalid signature: parent certificate cannot sign this kind of certificate"
}

//UnhandledCriticalExtension unhandled critical extension
type UnhandledCriticalExtension struct{}

func (h UnhandledCriticalExtension) Error() string {
	return "x509: unhandled critical extension"
}

func signaturePublicKeyAlgoMismatchError(expectedPubKeyAlgo plugin.PublicKeyAlgorithm, pubKey crypto.VerifyKey) error {
	return fmt.Errorf("x509: signature algorithm specifies an %s public key, but have public key with keyInfo %v", expectedPubKeyAlgo.String(), pubKey.GetKeyInfo())
}
