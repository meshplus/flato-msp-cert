package plugin

import (
	"github.com/meshplus/crypto"
	"io"
)

const (
	sm2Flag = iota
)

type flag struct {
	f int
	r io.Reader
}

func (f *flag) Read(p []byte) (n int, err error) {
	return f.r.Read(p)
}

func (f *flag) GetFlag() int {
	return f.f
}

//UseSm2Batch use Sm2 batch mode
func UseSm2Batch(reader io.Reader) crypto.FlagReader {
	return &flag{
		f: sm2Flag,
		r: reader,
	}
}
