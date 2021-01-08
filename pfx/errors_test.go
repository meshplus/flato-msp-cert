package pkcs12

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNotImplementedError_Error(t *testing.T) {
	e := NotImplementedError("error")
	assert.Equal(t, "pkcs12: error", e.Error())
}
