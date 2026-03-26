//go:build ziren

package bn256

import (
	"fmt"
	"math/big"
	"os"
	"unsafe"

	"github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime"
)

// p_u32 is BN254 prime P in [8]uint32 LE for SyscallUint256Mul modulus.
var p_u32 [8]uint32

func init() {
	bigIntToU32LE(P, &p_u32)
}

// --- Conversion helpers ---

func bigIntToU32LE(v *big.Int, out *[8]uint32) {
	// Must ensure value is non-negative and fits in 256 bits (32 bytes).
	// Values in [0, 2^256) are fine — the executor's % modulus handles > P.
	// Negative or > 256 bit values: reduce using SyscallUint256Mul(v, 1, P).
	val := v
	if v.Sign() < 0 || v.BitLen() > 256 {
		// Use uint256_mul(v mod 2^256, 1, P) to reduce.
		// For negative: first make non-negative via Go Mod (guaranteed correct).
		val = new(big.Int).Mod(v, P) // Go's Mod always returns [0, P)
	}
	b := val.Bytes()
	var lebuf [32]byte
	for i := 0; i < len(b) && i < 32; i++ {
		lebuf[i] = b[len(b)-1-i]
	}
	for i := 0; i < 8; i++ {
		out[i] = uint32(lebuf[i*4]) |
			uint32(lebuf[i*4+1])<<8 |
			uint32(lebuf[i*4+2])<<16 |
			uint32(lebuf[i*4+3])<<24
	}
}

func u32LEtoBigInt(v *[8]uint32) *big.Int {
	var buf [32]byte
	for i := 0; i < 8; i++ {
		buf[i*4] = byte(v[i])
		buf[i*4+1] = byte(v[i] >> 8)
		buf[i*4+2] = byte(v[i] >> 16)
		buf[i*4+3] = byte(v[i] >> 24)
	}
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return new(big.Int).SetBytes(buf[:])
}

// --- Field operations using BN254 Fp syscalls ---

// fieldMul computes (a * b) mod P using SyscallUint256Mul.
func fieldMul(a, b *big.Int) *big.Int {
	var aU, bU [8]uint32
	bigIntToU32LE(a, &aU)
	bigIntToU32LE(b, &bU)

	var ymod [16]uint32
	copy(ymod[0:8], bU[:])
	copy(ymod[8:16], p_u32[:])

	zkvm_runtime.SyscallUint256Mul(unsafe.Pointer(&aU[0]), unsafe.Pointer(&ymod[0]))
	return u32LEtoBigInt(&aU)
}

// fieldAdd computes (a + b) mod P using BN254_FP_ADD syscall.
func fieldAdd(a, b *big.Int) *big.Int {
	var aU, bU [8]uint32
	bigIntToU32LE(a, &aU)
	bigIntToU32LE(b, &bU)
	zkvm_runtime.SyscallBn254FpAdd(unsafe.Pointer(&aU), unsafe.Pointer(&bU))
	return u32LEtoBigInt(&aU)
}

// fieldSub computes (a - b) mod P using BN254_FP_SUB syscall.
func fieldSub(a, b *big.Int) *big.Int {
	var aU, bU [8]uint32
	bigIntToU32LE(a, &aU)
	bigIntToU32LE(b, &bU)
	zkvm_runtime.SyscallBn254FpSub(unsafe.Pointer(&aU), unsafe.Pointer(&bU))
	return u32LEtoBigInt(&aU)
}

// fieldModInverse computes a^{-1} mod P using Fermat's little theorem via SyscallUint256Mul.
func fieldModInverse(a *big.Int) *big.Int {
	var base [8]uint32
	bigIntToU32LE(a, &base)

	var pMinus2 [8]uint32
	bigIntToU32LE(new(big.Int).Sub(P, big.NewInt(2)), &pMinus2)

	result := [8]uint32{1, 0, 0, 0, 0, 0, 0, 0}

	var baseYmod [16]uint32
	var resultYmod [16]uint32
	copy(baseYmod[8:16], p_u32[:])
	copy(resultYmod[8:16], p_u32[:])

	for i := 0; i < 256; i++ {
		wordIdx := i / 32
		bitIdx := uint(i % 32)
		if (pMinus2[wordIdx]>>bitIdx)&1 == 1 {
			copy(resultYmod[0:8], base[:])
			zkvm_runtime.SyscallUint256Mul(unsafe.Pointer(&result), unsafe.Pointer(&resultYmod))
		}
		copy(baseYmod[0:8], base[:])
		zkvm_runtime.SyscallUint256Mul(unsafe.Pointer(&base), unsafe.Pointer(&baseYmod))
	}

	return u32LEtoBigInt(&result)
}

// fieldReduce reduces v to [0, P) using SyscallBn254FpAdd(v, 0).
// Much faster than big.Int.Mod on MIPS (1 syscall vs software division).
// Input must fit in 256 bits (guaranteed if values come from gfP2 Add/Sub/Double).
func fieldReduce(v *big.Int) *big.Int {
	var aU [8]uint32
	bigIntToU32LE(v, &aU)
	var zero [8]uint32
	zkvm_runtime.SyscallBn254FpAdd(unsafe.Pointer(&aU), unsafe.Pointer(&zero))
	return u32LEtoBigInt(&aU)
}

var _ = fmt.Fprintf
var _ = os.Stderr
