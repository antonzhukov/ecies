package ecies

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/arstd/log"
)

const l = 10240
const kl = 1024

var pk *rsa.PrivateKey
var c []byte
var src []byte

func init() {
	var err error
	pk, err = rsa.GenerateKey(rand.Reader, kl)
	if err != nil {
		panic(err)
	}

	log.Debug(l)
	src = make([]byte, l)
	_, err = rand.Read(src)
	if err != nil {
		panic(err)
	}
	c, err = encrypt(src)
	if err != nil {
		panic(err)
	}
}

func encrypt(msg []byte) ([]byte, error) {
	ct := make([]byte, len(msg)*2)
	var x int
	const ml = kl/8 - 11
	for i := 0; i < len(msg); i += ml {
		var b []byte
		if i+ml >= len(msg) {
			b = msg[i:]
		} else {
			b = msg[i : i+ml]
		}
		ci, err := rsa.EncryptPKCS1v15(rand.Reader, &pk.PublicKey, b)
		if err != nil {
			return nil, err
		}
		x += copy(ct[x:], ci)
	}
	return ct[:x], nil
}

func decrypt(msg []byte) ([]byte, error) {
	ct := make([]byte, len(msg))
	const ml = kl / 8
	var x int
	for i := 0; i < len(msg); i += ml {
		var b []byte
		if i+ml >= len(msg) {
			b = msg[i:]
		} else {
			b = msg[i : i+ml]
		}
		ci, err := rsa.DecryptPKCS1v15(rand.Reader, pk, b)
		if err != nil {
			return nil, err
		}
		x += copy(ct[x:], ci)
	}
	return ct[:x], nil
}

func TestDecrypt(t *testing.T) {
	d, err := decrypt(c)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(src, d) {
		t.FailNow()
	}
}

func BenchmarkRSAEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := encrypt(src)
		if err != nil {
			b.Error(err.Error())
		}
	}
}

func BenchmarkRSADecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := decrypt(c)
		if err != nil {
			b.Error(err.Error())
		}
	}
}
