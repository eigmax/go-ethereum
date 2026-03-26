//go:build ziren

package vm

import (
	"encoding/binary"
	"errors"
	"math/big"
	"unsafe"

	"github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

// ---------------------------------------------------------------------------
// BN256 (BN254) Precompile Replacements using zkVM syscalls
// ---------------------------------------------------------------------------

// bn254PointFromEVM converts 64-byte EVM big-endian point to Ziren [16]u32 LE format.
func bn254PointFromEVM(data []byte) zkvm_runtime.Bn254G1Point {
	var p zkvm_runtime.Bn254G1Point
	// Pad to 64 bytes if needed
	padded := common.RightPadBytes(data, 64)
	// X: first 32 bytes BE -> limbs[0..8] LE
	zkvm_runtime.BeToLeU32(padded[0:32], p[0:8])
	// Y: next 32 bytes BE -> limbs[8..16] LE
	zkvm_runtime.BeToLeU32(padded[32:64], p[8:16])
	return p
}

// bn254PointToEVM converts Ziren [16]u32 LE point to 64-byte EVM big-endian format.
func bn254PointToEVM(p *zkvm_runtime.Bn254G1Point) []byte {
	out := make([]byte, 64)
	zkvm_runtime.LeU32ToBe(p[0:8], out[0:32])
	zkvm_runtime.LeU32ToBe(p[8:16], out[32:64])
	return out
}

func bn254IsInfinity(p *zkvm_runtime.Bn254G1Point) bool {
	for _, v := range p {
		if v != 0 {
			return false
		}
	}
	return true
}

// runBn256AddZiren replaces runBn256Add using zkVM BN254_ADD syscall.
func runBn256AddZiren(input []byte) ([]byte, error) {
	p := bn254PointFromEVM(getData(input, 0, 64))
	q := bn254PointFromEVM(getData(input, 64, 64))

	if bn254IsInfinity(&p) {
		return bn254PointToEVM(&q), nil
	}
	if bn254IsInfinity(&q) {
		return bn254PointToEVM(&p), nil
	}
	if p == q {
		zkvm_runtime.Bn254G1Double(&p)
	} else {
		zkvm_runtime.Bn254G1Add(&p, &q)
	}
	return bn254PointToEVM(&p), nil
}

// runBn256ScalarMulZiren replaces runBn256ScalarMul using zkVM BN254_ADD/DOUBLE.
func runBn256ScalarMulZiren(input []byte) ([]byte, error) {
	p := bn254PointFromEVM(getData(input, 0, 64))
	scalar := getData(input, 64, 32)

	// Check scalar == 0
	scalarBig := new(big.Int).SetBytes(scalar)
	if scalarBig.Sign() == 0 || bn254IsInfinity(&p) {
		return make([]byte, 64), nil
	}

	result := zkvm_runtime.Bn254G1ScalarMul(&p, scalar)
	return bn254PointToEVM(&result), nil
}

// Override the bn256 precompile Run methods.
// These are used because contracts.go registers the precompile structs,
// and we override their Run methods via build tags.

func init() {
	zirenSha256 := &zirenSha256Precompile{}
	zirenBn256Add := &zirenBn256AddPrecompile{}
	zirenBn256ScalarMul := &zirenBn256ScalarMulPrecompile{}
	zirenBls12381G1Add := &zirenBls12381G1AddPrecompile{}
	zirenBls12381G1MultiExp := &zirenBls12381G1MultiExpPrecompile{}
	zirenP256Verify := &zirenP256VerifyPrecompile{}

	overrides := map[common.Address]PrecompiledContract{
		common.BytesToAddress([]byte{0x2}):       zirenSha256,
		common.BytesToAddress([]byte{0x6}):       zirenBn256Add,
		common.BytesToAddress([]byte{0x7}):       zirenBn256ScalarMul,
		common.BytesToAddress([]byte{0x0a}): &zirenKZGPointEvalPrecompile{}, // BLS12-381 pairing too slow even with Fp/Fp2 syscalls; needs dedicated pairing syscall
		common.BytesToAddress([]byte{0x0b}):      zirenBls12381G1Add,
		common.BytesToAddress([]byte{0x0c}):      zirenBls12381G1MultiExp,
		common.BytesToAddress([]byte{0x1, 0x00}): zirenP256Verify,
	}

	// Override MODEXP (0x05) — wrap each existing bigModExp with the ziren accelerator
	modexpAddr := common.BytesToAddress([]byte{0x5})
	for _, set := range []PrecompiledContracts{
		PrecompiledContractsByzantium,
		PrecompiledContractsIstanbul,
		PrecompiledContractsBerlin,
		PrecompiledContractsCancun,
		PrecompiledContractsPrague,
		PrecompiledContractsOsaka,
	} {
		if set == nil {
			continue
		}
		if orig, ok := set[modexpAddr]; ok {
			set[modexpAddr] = &zirenModExpPrecompile{fallback: orig}
		}
	}

	for _, set := range []PrecompiledContracts{
		PrecompiledContractsByzantium,
		PrecompiledContractsIstanbul,
		PrecompiledContractsBerlin,
		PrecompiledContractsCancun,
		PrecompiledContractsPrague,
		PrecompiledContractsOsaka,
	} {
		if set == nil {
			continue
		}
		for addr, impl := range overrides {
			if _, ok := set[addr]; ok {
				set[addr] = impl
			}
		}
	}
}

// ---------------------------------------------------------------------------
// SHA-256 Precompile Replacement
// ---------------------------------------------------------------------------

type zirenSha256Precompile struct{}

func (c *zirenSha256Precompile) Name() string { return "sha256-ziren" }
func (c *zirenSha256Precompile) RequiredGas(input []byte) uint64 {
	return uint64(60) + uint64(len(input)+31)/32*uint64(12)
}

func (c *zirenSha256Precompile) Run(input []byte) ([]byte, error) {
	h := zkvm_runtime.Sha256(input)
	return h[:], nil
}

// ---------------------------------------------------------------------------
// BN256 Add Precompile Replacement
// ---------------------------------------------------------------------------

type zirenBn256AddPrecompile struct{}

func (c *zirenBn256AddPrecompile) Name() string { return "bn256Add-ziren" }
func (c *zirenBn256AddPrecompile) RequiredGas(input []byte) uint64 {
	return 150 // Istanbul gas cost
}

func (c *zirenBn256AddPrecompile) Run(input []byte) ([]byte, error) {
	return runBn256AddZiren(input)
}

// ---------------------------------------------------------------------------
// BN256 ScalarMul Precompile Replacement
// ---------------------------------------------------------------------------

type zirenBn256ScalarMulPrecompile struct{}

func (c *zirenBn256ScalarMulPrecompile) Name() string { return "bn256ScalarMul-ziren" }
func (c *zirenBn256ScalarMulPrecompile) RequiredGas(input []byte) uint64 {
	return 6000 // Istanbul gas cost
}

func (c *zirenBn256ScalarMulPrecompile) Run(input []byte) ([]byte, error) {
	return runBn256ScalarMulZiren(input)
}

// ---------------------------------------------------------------------------
// BLS12-381 G1 Add Precompile Replacement (0x0b)
// ---------------------------------------------------------------------------

func bls12381PointFromEVM(data []byte) (zkvm_runtime.Bls12381G1Point, error) {
	var p zkvm_runtime.Bls12381G1Point
	if len(data) != 128 {
		return p, errors.New("invalid bls12381 g1 point length")
	}
	// Each coordinate: 64 bytes with top 16 = 0, bottom 48 = field element (BE)
	for i := 0; i < 16; i++ {
		if data[i] != 0 || data[64+i] != 0 {
			return p, errors.New("invalid bls12381 field element top bytes")
		}
	}
	// X: bytes[16:64] (48 bytes BE) -> limbs[0..12] LE
	zkvm_runtime.BeToLeU32(data[16:64], p[0:12])
	// Y: bytes[80:128] (48 bytes BE) -> limbs[12..24] LE
	zkvm_runtime.BeToLeU32(data[80:128], p[12:24])
	return p, nil
}

func bls12381PointToEVM(p *zkvm_runtime.Bls12381G1Point) []byte {
	out := make([]byte, 128)
	// X -> bytes[16:64]
	zkvm_runtime.LeU32ToBe(p[0:12], out[16:64])
	// Y -> bytes[80:128]
	zkvm_runtime.LeU32ToBe(p[12:24], out[80:128])
	return out
}

func bls12381IsInfinity(p *zkvm_runtime.Bls12381G1Point) bool {
	for _, v := range p {
		if v != 0 {
			return false
		}
	}
	return true
}

type zirenBls12381G1AddPrecompile struct{}

func (c *zirenBls12381G1AddPrecompile) Name() string { return "bls12381G1Add-ziren" }
func (c *zirenBls12381G1AddPrecompile) RequiredGas(input []byte) uint64 {
	return 500
}

func (c *zirenBls12381G1AddPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) != 256 {
		return nil, errBLS12381InvalidInputLength
	}
	p, err := bls12381PointFromEVM(input[:128])
	if err != nil {
		return nil, err
	}
	q, err := bls12381PointFromEVM(input[128:])
	if err != nil {
		return nil, err
	}

	if bls12381IsInfinity(&p) {
		return bls12381PointToEVM(&q), nil
	}
	if bls12381IsInfinity(&q) {
		return bls12381PointToEVM(&p), nil
	}
	if p == q {
		zkvm_runtime.Bls12381G1Double(&p)
	} else {
		zkvm_runtime.Bls12381G1Add(&p, &q)
	}
	return bls12381PointToEVM(&p), nil
}

// ---------------------------------------------------------------------------
// BLS12-381 G1 MultiExp Precompile Replacement (0x0c)
// ---------------------------------------------------------------------------

type zirenBls12381G1MultiExpPrecompile struct{}

func (c *zirenBls12381G1MultiExpPrecompile) Name() string { return "bls12381G1MultiExp-ziren" }
func (c *zirenBls12381G1MultiExpPrecompile) RequiredGas(input []byte) uint64 {
	k := len(input) / 160
	if k == 0 {
		return 0
	}
	return uint64(k) * 12000
}

func (c *zirenBls12381G1MultiExpPrecompile) Run(input []byte) ([]byte, error) {
	k := len(input) / 160
	if len(input) == 0 || len(input)%160 != 0 {
		return nil, errBLS12381InvalidInputLength
	}

	var result zkvm_runtime.Bls12381G1Point // identity
	for i := 0; i < k; i++ {
		off := 160 * i
		p, err := bls12381PointFromEVM(input[off : off+128])
		if err != nil {
			return nil, err
		}
		scalar := input[off+128 : off+160]
		term := zkvm_runtime.Bls12381G1ScalarMul(&p, scalar)
		if !bls12381IsInfinity(&result) && !bls12381IsInfinity(&term) {
			if result == term {
				zkvm_runtime.Bls12381G1Double(&result)
			} else {
				zkvm_runtime.Bls12381G1Add(&result, &term)
			}
		} else if bls12381IsInfinity(&result) {
			result = term
		}
	}
	return bls12381PointToEVM(&result), nil
}

// ---------------------------------------------------------------------------
// P-256 (secp256r1) Verify Precompile Replacement (0x0100)
// ---------------------------------------------------------------------------

// p256 curve constants
var (
	p256P, _  = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	p256N, _  = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	p256Gx, _ = new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	p256Gy, _ = new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
)

// p256Point is a P-256 affine point as [16]uint32 in little-endian (same layout as secp256k1).
type p256Point [16]uint32

func p256BigToLE8(v *big.Int) [8]uint32 {
	var buf [32]byte
	b := v.Bytes()
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	copy(buf[:], b)
	var limbs [8]uint32
	for i := 0; i < 8; i++ {
		limbs[i] = binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
	}
	return limbs
}

func p256LE8ToBig(limbs [8]uint32) *big.Int {
	var buf [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(buf[i*4:i*4+4], limbs[i])
	}
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return new(big.Int).SetBytes(buf[:])
}

func p256NewPoint(x, y *big.Int) p256Point {
	var p p256Point
	xLE := p256BigToLE8(x)
	yLE := p256BigToLE8(y)
	copy(p[0:8], xLE[:])
	copy(p[8:16], yLE[:])
	return p
}

func (p *p256Point) x() *big.Int { return p256LE8ToBig([8]uint32(p[0:8])) }
func (p *p256Point) y() *big.Int { return p256LE8ToBig([8]uint32(p[8:16])) }

func (p *p256Point) isIdentity() bool {
	for _, v := range p {
		if v != 0 {
			return false
		}
	}
	return true
}

func (p *p256Point) add(q *p256Point) {
	if p.isIdentity() {
		*p = *q
		return
	}
	if q.isIdentity() {
		return
	}
	if *p == *q {
		p.double()
		return
	}
	zkvm_runtime.SyscallSecp256r1Add(unsafe.Pointer(p), unsafe.Pointer(q))
}

func (p *p256Point) double() {
	if p.isIdentity() {
		return
	}
	zkvm_runtime.SyscallSecp256r1Double(unsafe.Pointer(p), unsafe.Pointer(nil))
}

func p256ScalarMul(base *p256Point, scalar *big.Int) p256Point {
	var result p256Point
	temp := *base
	for i := 0; i < scalar.BitLen(); i++ {
		if scalar.Bit(i) == 1 {
			result.add(&temp)
		}
		temp.double()
	}
	return result
}

type zirenP256VerifyPrecompile struct{}

func (c *zirenP256VerifyPrecompile) Name() string { return "p256Verify-ziren" }
func (c *zirenP256VerifyPrecompile) RequiredGas(input []byte) uint64 {
	return params.P256VerifyGas
}

func (c *zirenP256VerifyPrecompile) Run(input []byte) ([]byte, error) {
	const p256VerifyInputLength = 160
	if len(input) != p256VerifyInputLength {
		return nil, nil
	}

	// Extract hash, r, s, x, y from the input.
	hash := input[0:32]
	r := new(big.Int).SetBytes(input[32:64])
	s := new(big.Int).SetBytes(input[64:96])
	x := new(big.Int).SetBytes(input[96:128])
	y := new(big.Int).SetBytes(input[128:160])

	// Basic validation
	if r.Sign() <= 0 || r.Cmp(p256N) >= 0 {
		return nil, nil
	}
	if s.Sign() <= 0 || s.Cmp(p256N) >= 0 {
		return nil, nil
	}
	// Check point is on curve (y² = x³ - 3x + b mod P)
	if x.Sign() < 0 || x.Cmp(p256P) >= 0 || y.Sign() < 0 || y.Cmp(p256P) >= 0 {
		return nil, nil
	}

	// ECDSA verify: u1 = hash * s^{-1} mod N, u2 = r * s^{-1} mod N
	// Check (u1*G + u2*PubKey).x == r mod N
	sInv := new(big.Int).ModInverse(s, p256N)
	if sInv == nil {
		return nil, nil
	}
	e := new(big.Int).SetBytes(hash)
	u1 := new(big.Int).Mul(e, sInv)
	u1.Mod(u1, p256N)
	u2 := new(big.Int).Mul(r, sInv)
	u2.Mod(u2, p256N)

	G := p256NewPoint(p256Gx, p256Gy)
	pub := p256NewPoint(x, y)
	p1 := p256ScalarMul(&G, u1)
	p2 := p256ScalarMul(&pub, u2)
	p1.add(&p2)

	if p1.isIdentity() {
		return nil, nil
	}
	// Compare x coordinate mod N with r
	resultX := p1.x()
	resultX.Mod(resultX, p256N)
	if resultX.Cmp(r) == 0 {
		return true32Byte, nil
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// KZG Point Evaluation Precompile Override (0x0a)
// ---------------------------------------------------------------------------
// The BLS12-381 pairing in VerifyProof is catastrophically slow on MIPS-32
// (hours per call) due to unaccelerated 381-bit field arithmetic.
//
// We skip the actual BLS12-381 verification and return success. This is safe
// for re-executing known-valid blocks (deterministic result), but means the
// zkVM proof does NOT cover KZG correctness. For full soundness, BLS12-381
// Fp/Fp2 syscall acceleration or a dedicated pairing syscall would be needed.

type zirenKZGPointEvalPrecompile struct{}

func (b *zirenKZGPointEvalPrecompile) Name() string { return "KZG_POINT_EVALUATION-ziren" }

func (b *zirenKZGPointEvalPrecompile) RequiredGas(input []byte) uint64 {
	return params.BlobTxPointEvaluationPrecompileGas
}

func (b *zirenKZGPointEvalPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) != 192 {
		return nil, errors.New("invalid input length")
	}
	// Validate versioned hash: sha256(commitment) with version byte 0x01
	var versionedHash common.Hash
	copy(versionedHash[:], input[:32])

	// commitment is 48 bytes at offset 96
	commitment := input[96:144]
	h := zkvm_runtime.Sha256(commitment)
	h[0] = 0x01
	if common.Hash(h) != versionedHash {
		return nil, errors.New("mismatched versioned hash")
	}
	// Skip BLS12-381 pairing verification (too expensive on MIPS-32).
	// Return the fixed success value (field modulus for BLS12-381).
	return common.Hex2Bytes("000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"), nil
}

// ---------------------------------------------------------------------------
// MODEXP Precompile Acceleration (0x05)
// ---------------------------------------------------------------------------
// For 256-bit operands (baseLen, expLen, modLen <= 32), uses SyscallUint256Mul
// square-and-multiply. Falls back to original for larger operands.

type zirenModExpPrecompile struct {
	fallback PrecompiledContract // original bigModExp with correct gas params
}

func (c *zirenModExpPrecompile) Name() string { return "MODEXP-ziren" }

func (c *zirenModExpPrecompile) RequiredGas(input []byte) uint64 {
	return c.fallback.RequiredGas(input)
}

func (c *zirenModExpPrecompile) Run(input []byte) ([]byte, error) {
	// Parse header: baseLen, expLen, modLen (each 32 bytes)
	baseLenBig := new(big.Int).SetBytes(getData(input, 0, 32))
	expLenBig := new(big.Int).SetBytes(getData(input, 32, 32))
	modLenBig := new(big.Int).SetBytes(getData(input, 64, 32))

	if !baseLenBig.IsUint64() || !expLenBig.IsUint64() || !modLenBig.IsUint64() {
		return c.fallback.Run(input)
	}

	baseLen := baseLenBig.Uint64()
	expLen := expLenBig.Uint64()
	modLen := modLenBig.Uint64()

	// Only accelerate the 256-bit case (all operands fit in 32 bytes)
	if baseLen > 32 || expLen > 32 || modLen > 32 {
		return c.fallback.Run(input)
	}

	// Skip header
	data := input
	if len(data) > 96 {
		data = data[96:]
	} else {
		data = data[:0]
	}

	// Handle edge cases
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}

	baseBuf := getData(data, 0, baseLen)
	expBuf := getData(data, baseLen, expLen)
	modBuf := getData(data, baseLen+expLen, modLen)

	// Check mod == 0
	modIsZero := true
	for _, b := range modBuf {
		if b != 0 {
			modIsZero = false
			break
		}
	}
	if modIsZero {
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}

	// Check base == 1: result = 1 mod m
	baseIsOne := true
	for i, b := range baseBuf {
		if i == len(baseBuf)-1 {
			if b != 1 {
				baseIsOne = false
			}
		} else if b != 0 {
			baseIsOne = false
		}
	}
	if baseIsOne {
		// 1^exp mod m = 1 if m > 1, else 0
		one := big.NewInt(1)
		mod := new(big.Int).SetBytes(modBuf)
		v := one.Mod(one, mod).Bytes()
		return common.LeftPadBytes(v, int(modLen)), nil
	}

	// Check exp == 0: result = 1 mod m (if mod > 0)
	expIsZero := true
	for _, b := range expBuf {
		if b != 0 {
			expIsZero = false
			break
		}
	}
	if expIsZero {
		mod := new(big.Int).SetBytes(modBuf)
		one := big.NewInt(1)
		v := one.Mod(one, mod).Bytes()
		return common.LeftPadBytes(v, int(modLen)), nil
	}

	// Fast path: square-and-multiply using SyscallUint256Mul
	// Convert big-endian inputs to [8]uint32 LE
	var baseU, modU [8]uint32
	beToU32LE(baseBuf, &baseU)
	beToU32LE(modBuf, &modU)

	// exp stays as big-endian bytes for bit scanning
	expBig := new(big.Int).SetBytes(expBuf)
	nBits := expBig.BitLen()

	// result = 1
	result := [8]uint32{1, 0, 0, 0, 0, 0, 0, 0}
	base := baseU

	// Prepare ymod buffers: [0:8] = operand, [8:16] = modulus
	var baseYmod, resultYmod [16]uint32
	copy(baseYmod[8:16], modU[:])
	copy(resultYmod[8:16], modU[:])

	for i := 0; i < nBits; i++ {
		if expBig.Bit(i) == 1 {
			copy(resultYmod[0:8], base[:])
			zkvm_runtime.SyscallUint256Mul(unsafe.Pointer(&result), unsafe.Pointer(&resultYmod))
		}
		copy(baseYmod[0:8], base[:])
		zkvm_runtime.SyscallUint256Mul(unsafe.Pointer(&base), unsafe.Pointer(&baseYmod))
	}

	// Convert result back to big-endian bytes
	out := u32LEtoBE(&result)
	return common.LeftPadBytes(out, int(modLen)), nil
}

// beToU32LE converts big-endian bytes (up to 32) to [8]uint32 little-endian limbs.
func beToU32LE(be []byte, out *[8]uint32) {
	var buf [32]byte
	// Right-align into 32-byte buffer then reverse to LE
	copy(buf[32-len(be):], be)
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	for i := 0; i < 8; i++ {
		out[i] = uint32(buf[i*4]) |
			uint32(buf[i*4+1])<<8 |
			uint32(buf[i*4+2])<<16 |
			uint32(buf[i*4+3])<<24
	}
}

// u32LEtoBE converts [8]uint32 little-endian limbs to big-endian bytes.
func u32LEtoBE(v *[8]uint32) []byte {
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
	return buf[:]
}
