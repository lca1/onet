package newHope

import (
	"fmt"
	"testing"

	"github.com/lca1/lattigo/newhope"

	"go.dedis.ch/onet/v3/glyph"
)

func TestPolyMarshall(t *testing.T) {
	ctx := glyph.GetCtx()
	p := ctx.NewUniformPoly()
	pub := glyph.NewPublicKey(p)
	pd, e := pub.Marshall()
	if e != nil {
		fmt.Println("Bjozzi")
		t.FailNow()
	}
	pk, e2 := checkPublicKey(pd, ctx)
	if e2 != nil {
		fmt.Println("Bjoggi")
		t.FailNow()
	}
	comparePolies(pk.GetT(), pub.GetT(), t)
}

func comparePolies(p1, p2 *newhope.Poly, t *testing.T) {
	coeff1, coeff2 := p1.Coeffs, p2.Coeffs
	if len(coeff1) != len(coeff2) {
		t.Log("Not the same size")
		t.FailNow()
	}
	for j, c := range coeff1 {
		c2 := coeff2[j]
		if c != c2 {
			t.Log("Not the same public key")
			t.FailNow()
		}
	}
}

func TestSecretMarshall(t *testing.T) {
	ctx := glyph.GetCtx()
	sk, e := glyph.NewPrivateKey(ctx, glyph.GetA(ctx))
	if e != nil {
		fmt.Println("Could not generate sk")
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
		fmt.Println("Lukas")
		t.FailNow()
	}
	z12 := sk2.GetS()
	z22 := sk2.GetE()
	comparePolies(z1, z12, t)
	comparePolies(z2, z22, t)

	pk1 := sk.PK()
	pk2 := sk2.PK()
	comparePolies(pk1.GetT(), pk2.GetT(), t)
}

func TestMarshall(t *testing.T) {
	pub, priv, e := GenerateKey(nil)
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
	fmt.Println(len(pub), NewHopePublicKeySize)
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
	comparePolies(testPublic.GetT(), publicKey.GetT(), t)
}
