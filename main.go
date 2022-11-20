package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"golang.org/x/crypto/hkdf"
	"io"
	"os"
	"strings"
)

func getCurve(s string) *curves.Curve {

	if strings.Contains(s, "p256") {
		return curves.P256()
	} else if strings.Contains(s, "k256") {
		return curves.K256()
	} else if strings.Contains(s, "25519") {
		return curves.ED25519()
	} else if strings.Contains(s, "G1") {
		return curves.BLS12381G1()
	} else if strings.Contains(s, "G2") {
		return curves.BLS12381G2()
	} else if strings.Contains(s, "PALLAS") {
		return curves.PALLAS()
	}

	return curves.K256()

}
func ECDH(ctype string) {
	argCount := len(os.Args[1:])

	if argCount > 0 {
		ctype = os.Args[1]
	}
	curve := getCurve(ctype)
	fmt.Printf("Curve type: [%s]\n", curve.Name)

	a := curve.Scalar.Random(rand.Reader)
	A := curve.Point.Generator().Mul(a)
	fmt.Printf("a = %x\n", a.Bytes())
	fmt.Printf("aG = %x\n", A.ToAffineUncompressed())

	b := curve.Scalar.Random(rand.Reader)
	B := curve.Point.Generator().Mul(b)
	fmt.Printf("b = %x\n", b.Bytes())
	fmt.Printf("bG = %xn\n\n", B.ToAffineUncompressed())

	K1 := A.Mul(b)
	K2 := B.Mul(a)
	fmt.Printf("K1 = %x\n", K1.ToAffineUncompressed())
	fmt.Printf("K2 = %x\n", K2.ToAffineUncompressed())

	kdf := hkdf.New(sha256.New, K1.ToAffineUncompressed(), []byte(""), []byte(""))
	key1 := make([]byte, 16)
	_, _ = io.ReadFull(kdf, key1)

	fmt.Printf("Derived key (after HKDF) = %x\n", key1)
}

func main() {

}
