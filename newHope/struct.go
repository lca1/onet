package newHope

const NewHopeName = "New Hope"

const sizeOfCoefficient = 4 //Assuming the coefficients are uint32 so 32 / 8

const NewHopePublicKeySize = 1 + numberOfModulie*numberOfCoefficients*sizeOfCoefficient

const numberOfModulie = 1

const numberOfCoefficients = 1024

const NewHopePrivateKeySize = numberOfModulie * 2 * NewHopePolySize

const NewHopeSignatureSize = numberOfModulie * 3 * NewHopePolySize

const NewHopePolySize = 1 + numberOfCoefficients*numberOfModulie*sizeOfCoefficient

type PublicKey []byte

type PrivateKey []byte
