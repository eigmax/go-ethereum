//go:build !ziren

package bn256

import "math/big"

func fieldMul(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(a, b)
}

func fieldAdd(a, b *big.Int) *big.Int {
	return new(big.Int).Add(a, b)
}

func fieldSub(a, b *big.Int) *big.Int {
	return new(big.Int).Sub(a, b)
}

func fieldModInverse(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, P)
}

func fieldReduce(v *big.Int) *big.Int {
	return new(big.Int).Mod(v, P)
}
