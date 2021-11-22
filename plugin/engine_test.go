package plugin

import (
	"github.com/meshplus/crypto"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
)

func TestKeyStore(t *testing.T) {
	engine := GetCryptoEngine()
	t.Run("random", func(t *testing.T) {
		buf := make([]byte, 128)
		r, err := engine.Rander()
		assert.Nil(t, err)
		_, err = r.Read(buf)
		assert.Nil(t, err)
		var sun byte
		for i := range buf {
			sun = sun | buf[i]
		}
		assert.True(t, sun != 0)
	})

	t.Run("Key store", func(t *testing.T) {
		//old dir tmp
		tmp := path.Join(os.TempDir(), getRandomStr(10))
		_ = os.MkdirAll(tmp, 0777)
		sEngine := GetSoftwareEngine(tmp)
		_, _, err := sEngine.CreateSignKey(true, crypto.Sm2p256v1)
		assert.Nil(t, err)
		//change dir to tmp2
		tmp2 := path.Join(os.TempDir(), getRandomStr(10))
		_ = os.MkdirAll(tmp2, 0777)
		sEngine.(*EncryptEngineMux).s.keyStorePath = tmp2
		_, _, err = sEngine.CreateSignKey(true, crypto.Sm2p256v1)
		assert.Nil(t, err)

		a, _ := ioutil.ReadDir(tmp)
		assert.Equal(t, 1, len(a))

		b, _ := ioutil.ReadDir(tmp2)
		assert.Equal(t, 1, len(b))

		_ = os.Remove(tmp)
		_ = os.Remove(tmp2)
	})
}

func TestString(t *testing.T) {
	t.Run("EncryptEngineMux", func(t *testing.T) {
		a := &EncryptEngineMux{detail: map[uint64]string{
			getKey(SignImport, crypto.Sm2p256v1):  "plugin_1.so",
			getKey(Random, crypto.None):           "plugin_3.so",
			getKey(Hash, crypto.KECCAK_256):       "plugin_5.so",
			getKey(SignGet, crypto.Sm2p256v1):     "plugin_1.so",
			getKey(Verify, crypto.Secp256k1):      "plugin_6.so",
			getKey(EncKey, crypto.Sm4|crypto.ECB): "plugin_3.so",
		}}
		t.Log(a.String())
		assert.True(t, strings.Contains(a.String(), "[SignGet]       : Sm2p256v1 -> plugin_1.so"))
		assert.True(t, strings.Contains(a.String(), "[Verify]        : Secp256k1 -> plugin_6.so"))
		assert.True(t, strings.Contains(a.String(), "[EncKey]        : SM4_ECB -> plugin_3.so"))
		assert.True(t, strings.Contains(a.String(), "[SignImport]    : Sm2p256v1 -> plugin_1.so"))
		assert.True(t, strings.Contains(a.String(), "[Random]        : None -> plugin_3.so"))
		assert.True(t, strings.Contains(a.String(), "[Hash]          : KECCAK_256 -> plugin_5.so"))
	})
}
