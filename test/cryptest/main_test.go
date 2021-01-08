package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"runtime"
	"testing"
)

func TestGetCPUInfoString(t *testing.T) {
	a, b := GetCPUInfoString()
	assert.True(t, len(a) > 0)
	sysType := runtime.GOOS
	if sysType == "linux" {
		assert.True(t, b == 0)
	} else {
		assert.True(t, b != 0)
	}
	fmt.Println(a)
}
