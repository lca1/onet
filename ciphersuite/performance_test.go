package ciphersuite

import (
	"io"
	"testing"
)

var pkInit PublicKey
var skInit SecretKey
var sigInit Signature

var msg = []byte("Bjorn")

func init() {
	suite := NewHope()
	pk, sk, e := suite.GenerateKeyPair(nil)
	if e != nil {
		panic(e)
	}
	pkInit = pk
	skInit = sk
	sigInit, _ = suite.Sign(sk, msg)
}

func benchmarkGenerateKey(suite CipherSuite, rand io.Reader, b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, e := suite.GenerateKeyPair(rand)
		if e != nil {
			b.FailNow()
		}
	}
}

func BenchmarkGenerateKeyNewHope(b *testing.B) {
	suite := NewHope()
	benchmarkGenerateKey(suite, nil, b)
}

func BenchmarkGenerateKeyEd25519(b *testing.B) {
	suite := NewEd25519CipherSuite()
	benchmarkGenerateKey(suite, nil, b)
}

func benchmarkSign(suite CipherSuite, rand io.Reader, msg []byte, b *testing.B) {
	_, sk, err := suite.GenerateKeyPair(rand)
	if err != nil {
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, e := suite.Sign(sk, msg)
		if e != nil {
			b.FailNow()
		}
	}
}

func BenchmarkSignEd25519(b *testing.B) {
	suite := NewEd25519CipherSuite()
	msg := []byte("deadbeef")
	benchmarkSign(suite, nil, msg, b)
}
func BenchmarkSignNewHope(b *testing.B) {
	suite := NewHope()
	msg := []byte("deadbeef")
	benchmarkSign(suite, nil, msg, b)
}

func benchmarkVerify(s CipherSuite, pk PublicKey, sig Signature, rand io.Reader, m []byte, b *testing.B) {
	for i := 0; i < b.N; i++ {
		everify := s.Verify(pk, sig, m)
		if everify != nil {
			b.Log(everify)
			b.FailNow()
		}
	}
}

func BenchmarkVerifyEd25519(b *testing.B) {
	edSuite := NewEd25519CipherSuite()
	pk, sk, e := edSuite.GenerateKeyPair(nil)
	if e != nil {
		b.Log(e)
		b.FailNow()
	}
	m := []byte("Bjo")
	sig, esign := edSuite.Sign(sk, m)
	if esign != nil {
		b.FailNow()
	}
	benchmarkVerify(edSuite, pk, sig, nil, m, b)
}

func BenchmarkVerifyNewHope(b *testing.B) {
	suite := NewHope()
	benchmarkVerify(suite, pkInit, sigInit, nil, msg, b)
}
