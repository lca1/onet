package glyph

import "testing"

func BenchmarkSign(b *testing.B) {
	ctx := GetCtx()
	msg := []byte("Bjorn")
	sk, _ := NewPrivateKey(ctx, GetA(ctx))
	for i := 0; i < b.N; i++ {
		sk.Sign(msg)
	}
}

func BenchmarkSignParallel(b *testing.B) {
	ctx := GetCtx()
	msg := []byte("Bjorn")
	sk, _ := NewPrivateKey(ctx, GetA(ctx))
	for i := 0; i < b.N; i++ {
		sk.SignParallel(msg)
	}
}

func BenchmarkDeterministicSign(b *testing.B) {
	ctx := GetCtx()
	msg := []byte("Bjorn")
	sk, _ := NewPrivateKey(ctx, GetA(ctx))
	for i := 0; i < b.N; i++ {
		y1, y2 := ctx.NewUniformPoly(), ctx.NewUniformPoly()
		y1Temp := make([]uint32, len(y1.Coeffs))
		for j, v2 := range y1.Coeffs {
			v := v2
			for {
				v &= ^(^0 << (bBits + 1))
				if v <= 2*constB+1 {
					break
				}
			}
			if v > constB {
				v = constQ - (y1.Coeffs[j] - constB)
			}
			y1Temp[j] = v
		}
		y1.Coeffs = y1Temp
		y2Temp := make([]uint32, len(y2.Coeffs))
		for j, v2 := range y2.Coeffs {
			v := v2
			for {
				v &= ^(^0 << (bBits + 1))
				if v <= 2*constB+1 {
					break
				}
			}
			if v > constB {
				v = constQ - (y2.Coeffs[j] - constB)
			}
			y2Temp[j] = v
		}
		y2.Coeffs = y2Temp
		sk.deterministicSign(y1, y2, msg)
	}
}
