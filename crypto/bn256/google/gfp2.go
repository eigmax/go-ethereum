// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bn256

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

import (
	"math/big"
)

// gfP2 implements a field of size p² as a quadratic extension of the base
// field where i²=-1.
type gfP2 struct {
	x, y *big.Int // value is xi+y.
}

func newGFp2(pool *bnPool) *gfP2 {
	return &gfP2{pool.Get(), pool.Get()}
}

func (e *gfP2) String() string {
	x := new(big.Int).Mod(e.x, P)
	y := new(big.Int).Mod(e.y, P)
	return "(" + x.String() + "," + y.String() + ")"
}

func (e *gfP2) Put(pool *bnPool) {
	pool.Put(e.x)
	pool.Put(e.y)
}

func (e *gfP2) Set(a *gfP2) *gfP2 {
	e.x.Set(a.x)
	e.y.Set(a.y)
	return e
}

func (e *gfP2) SetZero() *gfP2 {
	e.x.SetInt64(0)
	e.y.SetInt64(0)
	return e
}

func (e *gfP2) SetOne() *gfP2 {
	e.x.SetInt64(0)
	e.y.SetInt64(1)
	return e
}

func (e *gfP2) Minimal() {
	if e.x.Sign() < 0 || e.x.Cmp(P) >= 0 {
		e.x.Mod(e.x, P)
	}
	if e.y.Sign() < 0 || e.y.Cmp(P) >= 0 {
		e.y.Mod(e.y, P)
	}
}

func (e *gfP2) IsZero() bool {
	return e.x.Sign() == 0 && e.y.Sign() == 0
}

func (e *gfP2) IsOne() bool {
	if e.x.Sign() != 0 {
		return false
	}
	words := e.y.Bits()
	return len(words) == 1 && words[0] == 1
}

func (e *gfP2) Conjugate(a *gfP2) *gfP2 {
	e.y.Set(a.y)
	e.x.Neg(a.x)
	return e
}

func (e *gfP2) Negative(a *gfP2) *gfP2 {
	e.x.Neg(a.x)
	e.y.Neg(a.y)
	return e
}

func (e *gfP2) Add(a, b *gfP2) *gfP2 {
	e.x.Add(a.x, b.x)
	e.y.Add(a.y, b.y)
	return e
}

func (e *gfP2) Sub(a, b *gfP2) *gfP2 {
	e.x.Sub(a.x, b.x)
	e.y.Sub(a.y, b.y)
	return e
}

func (e *gfP2) Double(a *gfP2) *gfP2 {
	e.x.Lsh(a.x, 1)
	e.y.Lsh(a.y, 1)
	return e
}

func (c *gfP2) Exp(a *gfP2, power *big.Int, pool *bnPool) *gfP2 {
	sum := newGFp2(pool)
	sum.SetOne()
	t := newGFp2(pool)

	for i := power.BitLen() - 1; i >= 0; i-- {
		t.Square(sum, pool)
		if power.Bit(i) != 0 {
			sum.Mul(t, a, pool)
		} else {
			sum.Set(t)
		}
	}

	c.Set(sum)

	sum.Put(pool)
	t.Put(pool)

	return c
}

// See "Multiplication and Squaring in Pairing-Friendly Fields",
// http://eprint.iacr.org/2006/471.pdf
func (e *gfP2) Mul(a, b *gfP2, pool *bnPool) *gfP2 {
	// (xi+y)(x'i+y') = (xy'+x'y)i + (yy'-xx')
	tx := pool.Get().Set(fieldMul(a.x, b.y))
	t := pool.Get().Set(fieldMul(b.x, a.y))
	tx.Add(tx, t)
	tx.Mod(tx, P)

	ty := pool.Get().Set(fieldMul(a.y, b.y))
	t.Set(fieldMul(a.x, b.x))
	ty.Sub(ty, t)
	ty.Mod(ty, P)

	e.x.Set(tx)
	e.y.Set(ty)

	pool.Put(tx)
	pool.Put(ty)
	pool.Put(t)

	return e
}

func (e *gfP2) MulScalar(a *gfP2, b *big.Int) *gfP2 {
	e.x.Set(fieldMul(a.x, b))
	e.y.Set(fieldMul(a.y, b))
	return e
}

// MulXi sets e=ξa where ξ=i+9 and then returns e.
func (e *gfP2) MulXi(a *gfP2, pool *bnPool) *gfP2 {
	// (xi+y)(i+9) = (9x+y)i+(9y-x)
	// Use fieldMul for 9*x and 9*y to keep values mod P (< 256 bits).
	nine := big.NewInt(9)
	nx := fieldMul(a.x, nine) // (9*x) mod P
	ny := fieldMul(a.y, nine) // (9*y) mod P

	tx := pool.Get().Add(nx, a.y) // < 2P, fits 256 bits
	ty := pool.Get().Sub(ny, a.x) // could be negative, |v| < P

	e.x.Set(tx)
	e.y.Set(ty)

	pool.Put(tx)
	pool.Put(ty)

	return e
}

func (e *gfP2) Square(a *gfP2, pool *bnPool) *gfP2 {
	// (xi+y)² = (x+y)(y-x) + 2xyi
	t1 := pool.Get().Sub(a.y, a.x)
	t2 := pool.Get().Add(a.x, a.y)
	ty := pool.Get().Set(fieldMul(t1, t2))
	ty.Mod(ty, P)

	t1.Set(fieldMul(a.x, a.y))
	t1.Lsh(t1, 1)

	e.x.Mod(t1, P)
	e.y.Set(ty)

	pool.Put(t1)
	pool.Put(t2)
	pool.Put(ty)

	return e
}

func (e *gfP2) Invert(a *gfP2, pool *bnPool) *gfP2 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	t := pool.Get()
	t.Set(fieldMul(a.y, a.y))
	t2 := pool.Get()
	t2.Set(fieldMul(a.x, a.x))
	t.Add(t, t2)

	inv := pool.Get()
	inv.Set(fieldModInverse(t))

	e.x.Neg(a.x)
	e.x.Set(fieldMul(e.x, inv))
	e.x.Mod(e.x, P)

	e.y.Set(fieldMul(a.y, inv))
	e.y.Mod(e.y, P)

	pool.Put(t)
	pool.Put(t2)
	pool.Put(inv)

	return e
}

func (e *gfP2) Real() *big.Int {
	return e.x
}

func (e *gfP2) Imag() *big.Int {
	return e.y
}
