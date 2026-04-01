// Copyright 2025 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

//go:build ziren

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime"
)

// secp256k1 curve constants (prefixed to avoid collision with crypto.go)
var (
	zirenSecp256k1P, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	zirenSecp256k1N, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	zirenSecp256k1halfN = new(big.Int).Div(zirenSecp256k1N, big.NewInt(2))
	zirenSecp256k1Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	zirenSecp256k1Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

// ---------------------------------------------------------------------------
// uint256 modular arithmetic using SyscallUint256Mul
// ---------------------------------------------------------------------------

// u256 is a 256-bit value stored as [8]uint32 in little-endian limb order.
type u256 [8]uint32

var u256One = u256{1, 0, 0, 0, 0, 0, 0, 0}

// u256ModMul computes x = (x * y) % modulus in-place using the zkVM precompile.
// ymod must contain [8]u32 y followed by [8]u32 modulus.
func u256ModMul(x *u256, ymod *[16]uint32) {
	zkvm_runtime.SyscallUint256Mul(unsafe.Pointer(x), unsafe.Pointer(ymod))
}

// u256ModInverse computes a^{-1} mod n using Fermat's little theorem: a^{n-2} mod n.
// All computation stays in [8]uint32 format — no big.Int conversion in the hot loop.
func u256ModInverse(a *u256, n *u256) u256 {
	// Compute n-2
	var nMinus2 u256
	borrow := uint32(0)
	for i := 0; i < 8; i++ {
		sub := uint64(n[i]) - uint64(borrow)
		if i == 0 {
			sub -= 2
		}
		nMinus2[i] = uint32(sub)
		if sub > uint64(n[i]) {
			borrow = 1
		} else {
			borrow = 0
		}
	}

	// Square-and-multiply: result = a^(n-2) mod n
	result := u256One
	base := *a

	// Pre-build ymod buffers with modulus in upper half (reused across iterations)
	var baseYmod [16]uint32
	var resultYmod [16]uint32
	copy(baseYmod[8:16], n[:])
	copy(resultYmod[8:16], n[:])

	for i := 0; i < 256; i++ {
		wordIdx := i / 32
		bitIdx := uint(i % 32)
		if (nMinus2[wordIdx]>>bitIdx)&1 == 1 {
			// result = result * base mod n
			copy(resultYmod[0:8], base[:])
			u256ModMul(&result, &resultYmod)
		}
		// base = base * base mod n
		copy(baseYmod[0:8], base[:])
		u256ModMul(&base, &baseYmod)
	}
	return result
}

// uint256ModMul computes (a * b) % modulus using the zkVM precompile.
// Convenience wrapper that converts big.Int ↔ u256.
func uint256ModMul(a, b, modulus *big.Int) *big.Int {
	aU := bigToLE8(a)
	bU := bigToLE8(b)
	mU := bigToLE8(modulus)

	var ymod [16]uint32
	copy(ymod[0:8], bU[:])
	copy(ymod[8:16], mU[:])

	x := u256(aU)
	u256ModMul(&x, &ymod)

	return le8ToBig([8]uint32(x))
}

// uint256ModInverse computes a^{-1} mod n. Convenience wrapper using big.Int.
func uint256ModInverse(a, n *big.Int) *big.Int {
	aU := u256(bigToLE8(a))
	nU := u256(bigToLE8(n))
	result := u256ModInverse(&aU, &nU)
	return le8ToBig([8]uint32(result))
}

// affinePoint represents a secp256k1 affine point as [16]uint32 in little-endian.
// Layout: limbs[0..8] = x (LE), limbs[8..16] = y (LE).
type affinePoint [16]uint32

func bigToLE8(v *big.Int) [8]uint32 {
	var buf [32]byte
	b := v.Bytes()
	// big.Int.Bytes() is big-endian; we need little-endian bytes
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

func le8ToBig(limbs [8]uint32) *big.Int {
	var buf [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(buf[i*4:i*4+4], limbs[i])
	}
	// Convert LE bytes to big-endian for big.Int
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return new(big.Int).SetBytes(buf[:])
}

func newAffinePoint(x, y *big.Int) affinePoint {
	var p affinePoint
	xLE := bigToLE8(x)
	yLE := bigToLE8(y)
	copy(p[0:8], xLE[:])
	copy(p[8:16], yLE[:])
	return p
}

func (p *affinePoint) x() *big.Int { return le8ToBig([8]uint32(p[0:8])) }
func (p *affinePoint) y() *big.Int { return le8ToBig([8]uint32(p[8:16])) }

func (p *affinePoint) isIdentity() bool {
	for i := 0; i < 16; i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}

// add performs p = p + q using the zkVM precompile.
func (p *affinePoint) add(q *affinePoint) {
	if p.isIdentity() {
		*p = *q
		return
	}
	if q.isIdentity() {
		return
	}
	// If p == q, use double instead
	if *p == *q {
		p.double()
		return
	}
	zkvm_runtime.SyscallSecp256k1Add(unsafe.Pointer(p), unsafe.Pointer(q))
}

// double performs p = 2*p using the zkVM precompile.
func (p *affinePoint) double() {
	if p.isIdentity() {
		return
	}
	zkvm_runtime.SyscallSecp256k1Double(unsafe.Pointer(p), unsafe.Pointer(nil))
}

// scalarMul computes p = scalar * p using double-and-add (LSB first).
func scalarMul(base *affinePoint, scalar *big.Int) affinePoint {
	var result affinePoint // identity (all zeros)
	temp := *base

	for i := 0; i < scalar.BitLen(); i++ {
		if scalar.Bit(i) == 1 {
			result.add(&temp)
		}
		temp.double()
	}
	return result
}

// shamirMultiMul computes u1*P + u2*Q using Shamir's trick (MSB-first).
// Shares the doubling steps, reducing doubles from ~512 to ~256.
func shamirMultiMul(P, Q *affinePoint, u1, u2 *big.Int) affinePoint {
	// Precompute P+Q
	PplusQ := *P
	PplusQ.add(Q)

	maxBit := u1.BitLen()
	if u2.BitLen() > maxBit {
		maxBit = u2.BitLen()
	}

	var result affinePoint // identity
	for i := maxBit - 1; i >= 0; i-- {
		result.double()
		b1 := u1.Bit(i)
		b2 := u2.Bit(i)
		if b1 == 1 && b2 == 1 {
			result.add(&PplusQ)
		} else if b1 == 1 {
			result.add(P)
		} else if b2 == 1 {
			result.add(Q)
		}
	}
	return result
}

// scalarMulGTable computes u1*G using the precomputed gTable (no doubling needed).
// gTable[i] = 2^i * G, so u1*G = sum of gTable[i] for each bit i set in u1.
func scalarMulGTable(u1 *big.Int) affinePoint {
	var result affinePoint // identity
	for i := 0; i < u1.BitLen(); i++ {
		if u1.Bit(i) == 1 {
			pt := gTable[i]
			result.add(&pt)
		}
	}
	return result
}

// ecrecoverMultiMul computes u1*G + u2*R optimally:
//   - u1*G via precomputed gTable: 0 doubles, ~128 adds
//   - u2*R via scalarMul: ~256 doubles, ~128 adds
//   - final addition: 1 add
// Total: ~256 doubles + ~257 adds
func ecrecoverMultiMul(R *affinePoint, u1, u2 *big.Int) affinePoint {
	p1 := scalarMulGTable(u1)
	p2 := scalarMul(R, u2)
	p1.add(&p2)
	return p1
}

// decompress decompresses a 33-byte compressed public key using the zkVM precompile.
func decompress(pubkey []byte) (*big.Int, *big.Int, error) {
	if len(pubkey) != 33 {
		return nil, nil, errors.New("invalid compressed public key length")
	}
	prefix := pubkey[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, nil, errors.New("invalid compressed public key prefix")
	}
	isOdd := uint32(prefix & 1)

	// The executor expects memory layout: [Y (output)][X (input)]
	// Both as [8]uint32 in little-endian limb order.
	// ptr+0:  Y output (8 x uint32 LE) — written by syscall
	// ptr+32: X input  (8 x uint32 LE) — read by syscall
	var pt affinePoint // [16]uint32: pt[0..8]=Y, pt[8..16]=X

	// Convert X from big-endian bytes to LE uint32 limbs, place in pt[8..16]
	xBig := new(big.Int).SetBytes(pubkey[1:33])
	xLE := bigToLE8(xBig)
	copy(pt[8:16], xLE[:])

	zkvm_runtime.SyscallSecp256k1Decompress(unsafe.Pointer(&pt[0]), isOdd)

	// After syscall: pt[0..8] = Y in LE uint32, pt[8..16] = X in LE uint32
	y := le8ToBig([8]uint32(pt[0:8]))
	x := le8ToBig([8]uint32(pt[8:16]))
	return x, y, nil
}

// ---------------------------------------------------------------------------
// Montgomery batch inversion
// ---------------------------------------------------------------------------

// batchModInverse computes the modular inverse of each element in vals mod n,
// using Montgomery's trick: only 1 actual inversion + 3(N-1) modular multiplications.
func batchModInverse(vals []*big.Int, n *big.Int) []*big.Int {
	k := len(vals)
	if k == 0 {
		return nil
	}
	if k == 1 {
		return []*big.Int{uint256ModInverse(vals[0], n)}
	}

	// Step 1: compute prefix products
	// prefix[i] = vals[0] * vals[1] * ... * vals[i] mod n
	prefix := make([]*big.Int, k)
	prefix[0] = new(big.Int).Set(vals[0])
	for i := 1; i < k; i++ {
		prefix[i] = uint256ModMul(prefix[i-1], vals[i], n)
	}

	// Step 2: invert the total product (only 1 ModInverse!)
	inv := uint256ModInverse(prefix[k-1], n)

	// Step 3: compute individual inverses by "peeling off" from the right
	result := make([]*big.Int, k)
	for i := k - 1; i > 0; i-- {
		// result[i] = inv * prefix[i-1]  (inv currently = (vals[i]*...*vals[k-1])^{-1})
		result[i] = uint256ModMul(inv, prefix[i-1], n)
		// inv = inv * vals[i] = (vals[i-1]*...*vals[k-1])^{-1} * vals[i] ... no
		// Actually: inv = inv * vals[i] → becomes inverse of prefix[i-1]
		inv = uint256ModMul(inv, vals[i], n)
	}
	result[0] = inv

	return result
}

// BatchEcrecover pre-recovers all transaction senders using batch modular inversion.
// This replaces N independent ModInverse operations (each ~450 uint256_mul) with
// 1 ModInverse + 3(N-1) ModMul, saving ~99% of uint256_mul syscalls.
//
// Returns a slice of uncompressed public keys (65 bytes each), or nil entries on error.
func BatchEcrecover(hashes [][]byte, sigs [][]byte) [][]byte {
	n := len(hashes)
	if n != len(sigs) || n == 0 {
		return nil
	}

	type ecrecoverInput struct {
		hash []byte
		r    *big.Int
		s    *big.Int
		v    byte
	}

	// Parse all signatures
	inputs := make([]ecrecoverInput, n)
	rVals := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		if len(sigs[i]) != SignatureLength || len(hashes[i]) != DigestLength {
			continue
		}
		inputs[i].hash = hashes[i]
		inputs[i].r = new(big.Int).SetBytes(sigs[i][:32])
		inputs[i].s = new(big.Int).SetBytes(sigs[i][32:64])
		inputs[i].v = sigs[i][RecoveryIDOffset]
		rVals[i] = inputs[i].r
	}

	// Batch compute all r^{-1} mod N
	rInvs := batchModInverse(rVals, zirenSecp256k1N)

	// Now recover each public key using pre-computed r^{-1}
	results := make([][]byte, n)
	G := newAffinePoint(zirenSecp256k1Gx, zirenSecp256k1Gy)

	for i := 0; i < n; i++ {
		in := inputs[i]
		if in.r == nil || in.r.Sign() == 0 || rInvs[i] == nil || rInvs[i].Sign() == 0 {
			continue
		}

		// Decompress R
		compressed := make([]byte, 33)
		if in.v == 0 {
			compressed[0] = 0x02
		} else {
			compressed[0] = 0x03
		}
		rBytes := in.r.Bytes()
		copy(compressed[33-len(rBytes):], rBytes)
		rxDec, ryDec, err := decompress(compressed)
		if err != nil {
			continue
		}
		R := newAffinePoint(rxDec, ryDec)

		// u1 = -hash * rInv mod N
		e := new(big.Int).SetBytes(in.hash)
		negE := new(big.Int).Sub(zirenSecp256k1N, new(big.Int).Mod(e, zirenSecp256k1N))
		u1 := uint256ModMul(negE, rInvs[i], zirenSecp256k1N)

		// u2 = s * rInv mod N
		u2 := uint256ModMul(in.s, rInvs[i], zirenSecp256k1N)

		// Q = u1*G + u2*R
		p1 := shamirMultiMul(&G, &R, u1, u2)
		if p1.isIdentity() {
			continue
		}

		// Return uncompressed public key
		ret := make([]byte, 65)
		ret[0] = 0x04
		xBytes := p1.x().Bytes()
		yBytes := p1.y().Bytes()
		copy(ret[1+32-len(xBytes):33], xBytes)
		copy(ret[33+32-len(yBytes):65], yBytes)
		results[i] = ret
	}

	return results
}

// recoverPublicKey implements ECDSA public key recovery for secp256k1.
// Given (r, s, v, hash), it recovers the public key.
func recoverPublicKey(hash []byte, r, s *big.Int, v byte) (*big.Int, *big.Int, error) {
	// 1. Compute R point from r
	//    R.x = r (+ N*recid for recid >= 2, but Ethereum only uses v=0,1)
	rx := new(big.Int).Set(r)
	if rx.Cmp(zirenSecp256k1P) >= 0 {
		return nil, nil, errors.New("invalid signature: r >= P")
	}

	// Compress R to get the 33-byte compressed point
	compressed := make([]byte, 33)
	if v == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	rBytes := rx.Bytes()
	copy(compressed[33-len(rBytes):], rBytes)

	// Decompress to get R = (rx, ry)
	rxDec, ryDec, err := decompress(compressed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decompress R: %w", err)
	}

	R := newAffinePoint(rxDec, ryDec)

	// 2. Compute r_inv = r^(-1) mod N using Fermat's little theorem with uint256_mul syscall
	rInv := uint256ModInverse(r, zirenSecp256k1N)
	if rInv.Sign() == 0 {
		return nil, nil, errors.New("r has no modular inverse")
	}

	// 3. Compute u1 = -hash * r_inv mod N
	e := new(big.Int).SetBytes(hash)
	negE := new(big.Int).Sub(zirenSecp256k1N, new(big.Int).Mod(e, zirenSecp256k1N))
	u1 := uint256ModMul(negE, rInv, zirenSecp256k1N)

	// 4. Compute u2 = s * r_inv mod N
	u2 := uint256ModMul(s, rInv, zirenSecp256k1N)

	// 5. Compute Q = u1*G + u2*R using Shamir's trick (shared doubling)
	G := newAffinePoint(zirenSecp256k1Gx, zirenSecp256k1Gy)
	p1 := shamirMultiMul(&G, &R, u1, u2)

	if p1.isIdentity() {
		return nil, nil, errors.New("recovered point is at infinity")
	}

	return p1.x(), p1.y(), nil
}

// Ecrecover returns the uncompressed public key that created the given signature.
func Ecrecover(hash, sig []byte) ([]byte, error) {
	if len(sig) != SignatureLength {
		return nil, errors.New("invalid signature length")
	}
	if len(hash) != DigestLength {
		return nil, fmt.Errorf("hash is required to be exactly %d bytes (%d)", DigestLength, len(hash))
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := sig[RecoveryIDOffset]

	if r.Sign() == 0 || s.Sign() == 0 {
		return nil, errors.New("invalid signature: r or s is zero")
	}
	if r.Cmp(zirenSecp256k1N) >= 0 || s.Cmp(zirenSecp256k1N) >= 0 {
		return nil, errors.New("invalid signature: r or s >= N")
	}

	pubX, pubY, err := recoverPublicKey(hash, r, s, v)
	if err != nil {
		return nil, err
	}

	// Return uncompressed public key: 0x04 || X || Y (65 bytes)
	ret := make([]byte, 65)
	ret[0] = 0x04
	xBytes := pubX.Bytes()
	yBytes := pubY.Bytes()
	copy(ret[1+32-len(xBytes):33], xBytes)
	copy(ret[33+32-len(yBytes):65], yBytes)
	return ret, nil
}

// SigToPub returns the public key that created the given signature.
func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	s, err := Ecrecover(hash, sig)
	if err != nil {
		return nil, err
	}
	return UnmarshalPubkey(s)
}

// Sign is not supported in the zkVM (no private key operations needed for block verification).
func Sign(hash []byte, prv *ecdsa.PrivateKey) ([]byte, error) {
	return nil, errors.New("signing not supported in zkVM")
}

// VerifySignature checks that the given public key created signature over hash.
// Uses software verification (no precompile needed as this is less common in block validation).
func VerifySignature(pubkey, hash, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	// Parse public key
	if len(pubkey) == 0 {
		return false
	}

	var x, y *big.Int
	switch pubkey[0] {
	case 0x04: // uncompressed
		if len(pubkey) != 65 {
			return false
		}
		x = new(big.Int).SetBytes(pubkey[1:33])
		y = new(big.Int).SetBytes(pubkey[33:65])
	case 0x02, 0x03: // compressed
		var err error
		x, y, err = decompress(pubkey)
		if err != nil {
			return false
		}
	default:
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(zirenSecp256k1N) >= 0 || s.Cmp(zirenSecp256k1N) >= 0 {
		return false
	}
	// Reject malleable signatures
	if s.Cmp(zirenSecp256k1halfN) > 0 {
		return false
	}

	// ECDSA verify: compute u1 = hash * s^-1, u2 = r * s^-1, check (u1*G + u2*PubKey).x == r
	sInv := uint256ModInverse(s, zirenSecp256k1N)
	e := new(big.Int).SetBytes(hash)
	u1 := uint256ModMul(e, sInv, zirenSecp256k1N)
	u2 := uint256ModMul(r, sInv, zirenSecp256k1N)

	G := newAffinePoint(zirenSecp256k1Gx, zirenSecp256k1Gy)
	pub := newAffinePoint(x, y)
	p1 := shamirMultiMul(&G, &pub, u1, u2)

	if p1.isIdentity() {
		return false
	}
	return p1.x().Cmp(r) == 0
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	x, y, err := decompress(pubkey)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: S256(),
		X:     x,
		Y:     y,
	}, nil
}

// CompressPubkey encodes a public key to the 33-byte compressed format.
func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	ret := make([]byte, 33)
	xBytes := pubkey.X.Bytes()
	copy(ret[1+32-len(xBytes):], xBytes)
	if pubkey.Y.Bit(0) == 0 {
		ret[0] = 0x02
	} else {
		ret[0] = 0x03
	}
	return ret
}

// S256 returns an instance of the secp256k1 curve.
func S256() EllipticCurve {
	return &zirenCurve{}
}

// zirenCurve is a minimal secp256k1 EllipticCurve implementation for the zkVM.
type zirenCurve struct{}

func (c *zirenCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       zirenSecp256k1P,
		N:       zirenSecp256k1N,
		B:       big.NewInt(7),
		Gx:      zirenSecp256k1Gx,
		Gy:      zirenSecp256k1Gy,
		BitSize: 256,
		Name:    "secp256k1",
	}
}

func (c *zirenCurve) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ + 7 mod P
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, zirenSecp256k1P)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, big.NewInt(7))
	x3.Mod(x3, zirenSecp256k1P)
	return y2.Cmp(x3) == 0
}

func (c *zirenCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1 := newAffinePoint(x1, y1)
	p2 := newAffinePoint(x2, y2)
	p1.add(&p2)
	return p1.x(), p1.y()
}

func (c *zirenCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p := newAffinePoint(x1, y1)
	p.double()
	return p.x(), p.y()
}

func (c *zirenCurve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	scalar := new(big.Int).SetBytes(k)
	scalar.Mod(scalar, zirenSecp256k1N)
	p := newAffinePoint(x1, y1)
	result := scalarMul(&p, scalar)
	return result.x(), result.y()
}

func (c *zirenCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.ScalarMult(zirenSecp256k1Gx, zirenSecp256k1Gy, k)
}

func (c *zirenCurve) Marshal(x, y *big.Int) []byte {
	byteLen := 32
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(ret[1+byteLen-len(xBytes):1+byteLen], xBytes)
	copy(ret[1+2*byteLen-len(yBytes):], yBytes)
	return ret
}

func (c *zirenCurve) Unmarshal(data []byte) (x, y *big.Int) {
	byteLen := 32
	if len(data) != 1+2*byteLen || data[0] != 4 {
		return nil, nil
	}
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	return
}
