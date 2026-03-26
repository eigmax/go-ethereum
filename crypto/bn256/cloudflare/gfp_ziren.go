//go:build ziren

package bn256

import (
	"unsafe"

	"github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime"
)

// rN1Plain is R^{-1} mod p in plain (non-Montgomery) form.
// R = 2^256, p = BN254 field prime.
// This is the same value as rN1 in constants.go (which is already in plain form).
// Used to convert: Montgomery_mul(a,b) = plain_mul(plain_mul(a,b), R^{-1})
var rN1Plain = gfP{0xed84884a014afa37, 0xeb2022850278edf8, 0xcf63e9cfb74492d9, 0x2e67157159e5c639}

func gfpCarry(a *gfP, head uint64) {
	b := &gfP{}
	var carry uint64
	for i, pi := range p2 {
		ai := a[i]
		bi := ai - pi - carry
		b[i] = bi
		if bi > ai || (carry != 0 && bi == ai) {
			carry = 1
		} else {
			carry = 0
		}
	}
	// If head is nonzero or no borrow, use the subtracted value.
	if head != 0 || carry == 0 {
		*a = *b
	}
}

func gfpNeg(c, a *gfP) {
	// c = p - a (when a != 0), c = 0 (when a == 0)
	var carry uint64
	for i, pi := range p2 {
		// p2 is p, the field prime
		ai := a[i]
		ci := pi - ai - carry
		c[i] = ci
		if ci > pi || (carry != 0 && ci == pi) {
			carry = 1
		} else {
			carry = 0
		}
	}
	// Check if a was zero
	zero := true
	for _, ai := range a {
		if ai != 0 {
			zero = false
			break
		}
	}
	if zero {
		*c = gfP{}
	}
}

func gfpAdd(c, a, b *gfP) {
	// gfP [4]uint64 LE = [8]uint32 LE in memory on mipsle
	var ac, bc [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&ac)) = *a
	*(*[4]uint64)(unsafe.Pointer(&bc)) = *b
	zkvm_runtime.SyscallBn254FpAdd(unsafe.Pointer(&ac), unsafe.Pointer(&bc))
	*c = *(*gfP)(unsafe.Pointer(&ac))
}

func gfpSub(c, a, b *gfP) {
	var ac, bc [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&ac)) = *a
	*(*[4]uint64)(unsafe.Pointer(&bc)) = *b
	zkvm_runtime.SyscallBn254FpSub(unsafe.Pointer(&ac), unsafe.Pointer(&bc))
	*c = *(*gfP)(unsafe.Pointer(&ac))
}

// BN254 field prime p in [8]uint32 LE format for SyscallUint256Mul.
var bn254P_u32 = func() [8]uint32 {
	var out [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&out)) = p2
	return out
}()

// BN254 field prime p-2 in [8]uint32 LE format for Fermat inversion.
var bn254PMin2_u32 = func() [8]uint32 {
	// p2 is the BN254 prime. p-2 = p2 with the lowest limb decremented by 2.
	pMinus2 := p2
	pMinus2[0] -= 2
	var out [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&out)) = pMinus2
	return out
}()

// R² mod p in [8]uint32 LE format (for Montgomery encode).
var r2_u32 = func() [8]uint32 {
	var out [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&out)) = *r2
	return out
}()

// gfpInvertZiren computes e = f^{-1} in the field using Fermat's little theorem:
// f^{-1} = f^{p-2} mod p. Uses SyscallUint256Mul for fast modular exponentiation.
// Input f is in Montgomery form (f*R mod p). Output is also in Montgomery form.
func gfpInvertZiren(e, f *gfP) {
	// Fermat's little theorem: f^{p-2} mod p via SyscallUint256Mul

	// Step 1: Montgomery decode
	var plain [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&plain)) = *f
	var rInvArr [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&rInvArr)) = rN1Plain
	zkvm_runtime.SyscallBn254FpMul(unsafe.Pointer(&plain), unsafe.Pointer(&rInvArr))

	// Step 2: Square-and-multiply
	result := [8]uint32{1, 0, 0, 0, 0, 0, 0, 0}
	base := plain
	var baseYmod, resultYmod [16]uint32
	copy(baseYmod[8:16], bn254P_u32[:])
	copy(resultYmod[8:16], bn254P_u32[:])
	exp := bn254PMin2_u32
	for i := 0; i < 256; i++ {
		wordIdx := i / 32
		bitIdx := uint(i % 32)
		if (exp[wordIdx]>>bitIdx)&1 == 1 {
			copy(resultYmod[0:8], base[:])
			zkvm_runtime.SyscallUint256Mul(unsafe.Pointer(&result), unsafe.Pointer(&resultYmod))
		}
		copy(baseYmod[0:8], base[:])
		zkvm_runtime.SyscallUint256Mul(unsafe.Pointer(&base), unsafe.Pointer(&baseYmod))
	}

	// Step 3: Montgomery encode
	zkvm_runtime.SyscallBn254FpMul(unsafe.Pointer(&result), unsafe.Pointer(&r2_u32))
	*e = *(*gfP)(unsafe.Pointer(&result))
}


func gfpMul(c, a, b *gfP) {
	// Montgomery multiplication: c = a * b * R^{-1} mod p
	// Decomposed as:
	//   temp = a * b mod p          (BN254_FP_MUL syscall)
	//   c    = temp * R^{-1} mod p  (BN254_FP_MUL syscall)

	var ac, bc [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&ac)) = *a
	*(*[4]uint64)(unsafe.Pointer(&bc)) = *b

	// Step 1: ac = a * b mod p
	zkvm_runtime.SyscallBn254FpMul(unsafe.Pointer(&ac), unsafe.Pointer(&bc))

	// Step 2: ac = ac * R^{-1} mod p
	var rInv [8]uint32
	*(*[4]uint64)(unsafe.Pointer(&rInv)) = rN1Plain
	zkvm_runtime.SyscallBn254FpMul(unsafe.Pointer(&ac), unsafe.Pointer(&rInv))

	*c = *(*gfP)(unsafe.Pointer(&ac))
}

// gfpInvert is the ziren-accelerated field inversion using SyscallUint256Mul.
func gfpInvert(e, f *gfP) {
	gfpInvertZiren(e, f)
}
