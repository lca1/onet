package glyph

import "testing"

func BenchmarkEncodeSparsePolynomial(t *testing.B) {
	msg := []byte("deadbeef")
	ctx := GetCtx()
	sampler := ctx.NewTernarySampler()
	p := ctx.NewPoly()
	sampler.Sample(0.33, p)
	for i := 0; i < t.N; i++ {
		h := hash(p, msg, ctx.N())
		encodeSparsePolynomial(ctx, omega, h)
	}
}
