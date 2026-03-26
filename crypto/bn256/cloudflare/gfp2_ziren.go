//go:build ziren

package bn256

import (
	"unsafe"

	"github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime"
)

// gfP2 implements a field of size p² as a quadratic extension of the base field
// where i²=-1.
type gfP2 struct {
	x, y gfP // value is xi+y.
}

func gfP2Decode(in *gfP2) *gfP2 {
	out := &gfP2{}
	montDecode(&out.x, &in.x)
	montDecode(&out.y, &in.y)
	return out
}

func (e *gfP2) String() string {
	return "(" + e.x.String() + ", " + e.y.String() + ")"
}

func (e *gfP2) Set(a *gfP2) *gfP2 {
	e.x.Set(&a.x)
	e.y.Set(&a.y)
	return e
}

func (e *gfP2) SetZero() *gfP2 {
	e.x = gfP{0}
	e.y = gfP{0}
	return e
}

func (e *gfP2) SetOne() *gfP2 {
	e.x = gfP{0}
	e.y = *newGFp(1)
	return e
}

func (e *gfP2) IsZero() bool {
	zero := gfP{0}
	return e.x == zero && e.y == zero
}

func (e *gfP2) IsOne() bool {
	zero, one := gfP{0}, *newGFp(1)
	return e.x == zero && e.y == one
}

func (e *gfP2) Conjugate(a *gfP2) *gfP2 {
	e.y.Set(&a.y)
	gfpNeg(&e.x, &a.x)
	return e
}

func (e *gfP2) Neg(a *gfP2) *gfP2 {
	gfpNeg(&e.x, &a.x)
	gfpNeg(&e.y, &a.y)
	return e
}

// fp2Layout converts gfP2 (Go: [imag][real]) to executor format ([real][imag])
// as [16]uint32 LE. Each gfP = [4]uint64 = [8]uint32 in memory on MIPS-LE.
type fp2Syscall [16]uint32

func fp2FromGfP2(a *gfP2) fp2Syscall {
	var s fp2Syscall
	// Executor layout: [real(y)][imag(x)]
	// Go layout: [imag(x)][real(y)]
	// Copy y (real) to s[0:8], x (imag) to s[8:16]
	*(*[4]uint64)(unsafe.Pointer(&s[0])) = a.y
	*(*[4]uint64)(unsafe.Pointer(&s[8])) = a.x
	return s
}

func fp2ToGfP2(s *fp2Syscall, e *gfP2) {
	// s[0:8] = real(y), s[8:16] = imag(x)
	e.y = *(*gfP)(unsafe.Pointer(&s[0]))
	e.x = *(*gfP)(unsafe.Pointer(&s[8]))
}

func (e *gfP2) Add(a, b *gfP2) *gfP2 {
	// Fp2Add preserves Montgomery form: (a*R + b*R) = (a+b)*R
	sa := fp2FromGfP2(a)
	sb := fp2FromGfP2(b)
	zkvm_runtime.SyscallBn254Fp2Add(unsafe.Pointer(&sa), unsafe.Pointer(&sb))
	fp2ToGfP2(&sa, e)
	return e
}

func (e *gfP2) Sub(a, b *gfP2) *gfP2 {
	// Fp2Sub preserves Montgomery form: (a*R - b*R) = (a-b)*R
	sa := fp2FromGfP2(a)
	sb := fp2FromGfP2(b)
	zkvm_runtime.SyscallBn254Fp2Sub(unsafe.Pointer(&sa), unsafe.Pointer(&sb))
	fp2ToGfP2(&sa, e)
	return e
}

// Mul computes e = a * b in Fp2 using the Fp2Mul syscall.
//
// Inputs are in Montgomery form: a = (ax*R, ay*R), b = (bx*R, by*R).
// The Fp2Mul syscall does plain modular arithmetic:
//   c0 = a0*b0 - a1*b1 mod p
//   c1 = a0*b1 + a1*b0 mod p
//
// With Montgomery inputs: c0 = ay*R*by*R - ax*R*bx*R = (ay*by - ax*bx)*R² mod p
// We need (ay*by - ax*bx)*R mod p, so we multiply each component by R^{-1}.
func (e *gfP2) Mul(a, b *gfP2) *gfP2 {
	sa := fp2FromGfP2(a)
	sb := fp2FromGfP2(b)
	zkvm_runtime.SyscallBn254Fp2Mul(unsafe.Pointer(&sa), unsafe.Pointer(&sb))

	// Result is in R² form, correct to R form by multiplying each component by R^{-1}
	var rInv [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&rInv)) = rN1Plain
	zkvm_runtime.SyscallBn254FpMul(unsafe.Pointer(&sa[0]), unsafe.Pointer(&rInv))
	zkvm_runtime.SyscallBn254FpMul(unsafe.Pointer(&sa[8]), unsafe.Pointer(&rInv))

	fp2ToGfP2(&sa, e)
	return e
}

func (e *gfP2) MulScalar(a *gfP2, b *gfP) *gfP2 {
	gfpMul(&e.x, &a.x, b)
	gfpMul(&e.y, &a.y, b)
	return e
}

// MulXi sets e=ξa where ξ=i+9 and then returns e.
func (e *gfP2) MulXi(a *gfP2) *gfP2 {
	// (xi+y)(i+9) = (9x+y)i+(9y-x)
	tx := &gfP{}
	gfpAdd(tx, &a.x, &a.x)
	gfpAdd(tx, tx, tx)
	gfpAdd(tx, tx, tx)
	gfpAdd(tx, tx, &a.x)

	gfpAdd(tx, tx, &a.y)

	ty := &gfP{}
	gfpAdd(ty, &a.y, &a.y)
	gfpAdd(ty, ty, ty)
	gfpAdd(ty, ty, ty)
	gfpAdd(ty, ty, &a.y)

	gfpSub(ty, ty, &a.x)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

// Square computes e = a² using Fp2Mul syscall (a*a).
func (e *gfP2) Square(a *gfP2) *gfP2 {
	return e.Mul(a, a)
}

func (e *gfP2) Invert(a *gfP2) *gfP2 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	t1, t2 := &gfP{}, &gfP{}
	gfpMul(t1, &a.x, &a.x)
	gfpMul(t2, &a.y, &a.y)
	gfpAdd(t1, t1, t2)

	inv := &gfP{}
	gfpInvertZiren(inv, t1) // Use uint256_mul-accelerated inversion

	gfpNeg(t1, &a.x)

	gfpMul(&e.x, t1, inv)
	gfpMul(&e.y, &a.y, inv)
	return e
}
