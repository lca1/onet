package newHope

import (
	"go.dedis.ch/onet/v3/glyph"
)

const omega = 16

const NewHopeName = "New Hope"

const sizeOfCoefficient = 4 //Assuming the coefficients are uint64 so 64 / 8

const NewHopePublicKeySize = 1 + numberOfModulie*numberOfCoefficients*sizeOfCoefficient

const numberOfModulie = 1

const numberOfCoefficients = 1024

const NewHopePrivateKeySize = numberOfModulie * 2 * NewHopePolySize

const NewHopeSignatureSize = numberOfModulie * (2*NewHopePolySize + int(2*omega))

const NewHopePolySize = numberOfCoefficients*numberOfModulie*sizeOfCoefficient + 1

//PublicKey marshalled
type PublicKey []byte

//PrivateKey marshalled
type PrivateKey []byte

//GlyphSuite uses large ring elements
type GlyphSuite struct {
	// This struct signs with Glyph
	// using larger ring elements
}

//NewSignSuite returns the default suite to be used.
func NewSignSuite() NewHope {
	return &GlyphSuite{} //This will be the default suite then.
}

func (g *GlyphSuite) SizeOfPolynomial() int {
	return glyph.PolySize
}

func (g *GlyphSuite) SizeOfSignature() int {
	return int(glyph.SignatureSize)
}

func (g *GlyphSuite) SizeOfPublicKey() int {
	return glyph.PublicKeySize
}
func (g *GlyphSuite) SizeOfPrivateKey() int {
	return glyph.PrivateKeySize
}
