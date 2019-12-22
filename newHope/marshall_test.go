package newHope

import (
	"testing"

	"go.dedis.ch/onet/v3/glyph"
)

func compareCoeffs(coeffs1 []uint32, coeffs2 []uint32) bool {
	for i, c1 := range coeffs1 {
		c2 := coeffs2[i]
		if c2 != c1 {
			return false
		}
	}
	return true
}

func TestPolyMarshall(t *testing.T) {
	ctx := glyph.GetCtx()
	p := ctx.NewUniformPoly()
	pub := glyph.NewPublicKey(p)
	pd, e := pub.Marshall()
	if e != nil {
		t.FailNow()
	}
	pk, e2 := checkPublicKey(pd, ctx)
	if e2 != nil {
		t.FailNow()
	}
	if !compareCoeffs(pk.GetT().Coeffs, pub.GetT().Coeffs) {
		t.Log("Coeffs did not match")
		t.FailNow()
	}
}

func TestSecretMarshall(t *testing.T) {
	ctx := glyph.GetCtx()
	sk, e := glyph.NewPrivateKey(ctx, glyph.GetA(ctx))
	if e != nil {
		t.FailNow()
	}
	z1 := sk.GetS()
	z2 := sk.GetE()
	m, e2 := sk.Marshall()
	if e2 != nil {
		t.FailNow()
	}
	sk2, e3 := checkPrivateKey(m, ctx)
	if e3 != nil {
		t.FailNow()
	}
	z12 := sk2.GetS()
	z22 := sk2.GetE()
	if !compareCoeffs(z1.Coeffs, z12.Coeffs) {
		t.Log("Z1 did not equal")
		t.Fail()
	}

	if !compareCoeffs(z2.Coeffs, z22.Coeffs) {
		t.Log("Z2 did not equal")
		t.Fail()
	}

	pk1 := sk.PK()
	pk2 := sk2.PK()
	if !compareCoeffs(pk1.GetT().Coeffs, pk2.GetT().Coeffs) {
		t.Log("PK did not equal")
		t.Fail()
	}
}

func TestMarshall(t *testing.T) {
	suite := &GlyphSuite{}
	pub, priv, e := suite.GenerateKey(nil)
	if e != nil {
		t.Log(e)
		t.FailNow()
		return
	}
	if priv == nil || pub == nil {
		t.Log("Either key was nil")
		t.FailNow()
	}
	ctx := glyph.GetCtx()
	publicKey, epublicKey := checkPublicKey(pub, ctx)
	if epublicKey != nil {
		t.Log(epublicKey)
		t.FailNow()
	}
	if publicKey == nil {
		t.Log("Public key was nil")
		t.FailNow()
	}

	private, eprivate := checkPrivateKey(priv, ctx)
	if eprivate != nil {
		t.Log(eprivate)
		t.FailNow()
	}
	if private == nil {
		t.Log("Private key was nil")
		t.FailNow()
	}
	testPublic := private.PK()
	if testPublic == nil {
		t.Log("Failed to generate public key")
		t.FailNow()
	}
	if !compareCoeffs(testPublic.GetT().Coeffs, publicKey.GetT().Coeffs) {
		t.Log("Unmarshalled public key is not equal to public key from the unmarshalled private key")
		t.FailNow()
	}
}
