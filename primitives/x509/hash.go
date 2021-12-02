package x509

import (
	"crypto"
	"crypto/md5"
	"crypto/sha512"
	"github.com/meshplus/crypto-gm"
	h "github.com/meshplus/crypto-standard/hash"
	"golang.org/x/crypto/ripemd160"
	"hash"
	"strconv"
)

func init() {
	RegisterHash(MD4, nil)
	RegisterHash(MD5SHA1, nil)
	RegisterHash(MD5, md5.New)
	RegisterHash(SHA1, func() hash.Hash {
		return h.NewHasher(h.SHA1)
	})
	RegisterHash(SHA224, func() hash.Hash {
		return h.NewHasher(h.SHA2_224)
	})
	RegisterHash(SHA256, func() hash.Hash {
		return h.NewHasher(h.SHA2_256)
	})
	RegisterHash(SHA384, func() hash.Hash {
		return h.NewHasher(h.SHA2_384)
	})
	RegisterHash(SHA512, func() hash.Hash {
		return h.NewHasher(h.SHA2_512)
	})
	RegisterHash(RIPEMD160, ripemd160.New)
	RegisterHash(SHA3_224, func() hash.Hash {
		return h.NewHasher(h.SHA2_224)
	})
	RegisterHash(SHA3_256, func() hash.Hash {
		return h.NewHasher(h.SHA2_256)
	})
	RegisterHash(SHA3_384, func() hash.Hash {
		return h.NewHasher(h.SHA3_384)
	})
	RegisterHash(SHA3_512, func() hash.Hash {
		return h.NewHasher(h.SHA2_512)
	})
	RegisterHash(SHA512_224, sha512.New512_224)
	RegisterHash(SHA512_256, sha512.New512_256)
	RegisterHash(SM3, gm.GetSM3Hasher)
	RegisterHash(SM3WithPublicKey, gm.NewSM3IDHasher)
}

//RegisterHash register hash
func RegisterHash(h Hash, f func() hash.Hash) {
	if h >= maxHash {
		panic("crypto: RegisterHash of unknown hash function")
	}
	hashes[h] = f
}

var digestSizes = []uint8{
	MD4:        16,
	MD5:        16,
	SHA1:       20,
	SHA224:     28,
	SHA256:     32,
	SHA384:     48,
	SHA512:     64,
	SHA512_224: 28,
	SHA512_256: 32,
	SHA3_224:   28,
	SHA3_256:   32,
	SHA3_384:   48,
	SHA3_512:   64,
	MD5SHA1:    36,
	RIPEMD160:  20,
	SM3:        32,
}

//Hash type
type Hash uint

// HashFunc simply returns the value of h so that Hash implements SignerOpts.
func (h Hash) HashFunc() crypto.Hash {
	return crypto.Hash(h)
}

// Size returns the length, in bytes, of a digest resulting from the given hash
// function. It doesn't require that the hash function in question be linked
// into the program.
func (h Hash) Size() int {
	if h > 0 && h < maxHash {
		return int(digestSizes[h])
	}
	panic("crypto: Size of unknown hash function")
}

var hashes = make([]func() hash.Hash, maxHash)

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > 0 && h < maxHash {
		f := hashes[h]
		if f != nil {
			return f()
		}
	}
	panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

// Available reports whether the given hash function is linked into the binary.
func (h Hash) Available() bool {
	return h < maxHash && hashes[h] != nil
}

//Hash Algorithm
const (
	MD4        Hash = 1 + iota // import golang.org/x/crypto/md4
	MD5                        // import crypto/md5
	SHA1                       // import crypto/sha1
	SHA224                     // import crypto/sha256
	SHA256                     // import crypto/sha256
	SHA384                     // import crypto/sha512
	SHA512                     // import crypto/sha512
	MD5SHA1                    // no implementation; MD5+SHA1 used for TLS RSA
	RIPEMD160                  // import golang.org/x/crypto/ripemd160
	SHA3_224                   // import golang.org/x/crypto/sha3
	SHA3_256                   // import golang.org/x/crypto/sha3
	SHA3_384                   // import golang.org/x/crypto/sha3
	SHA3_512                   // import golang.org/x/crypto/sha3
	SHA512_224                 // import crypto/sha512
	SHA512_256                 // import crypto/sha512
	SM3
	SM3WithPublicKey
	maxHash
)
