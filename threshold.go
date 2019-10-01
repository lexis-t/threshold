// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package threshold

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1"
)

// Signature is a type representing a Schnorr signature.
type Signature struct {
	R *big.Int
	S *big.Int
}

// SignatureSize is the size of an encoded Schnorr signature.
const SignatureSize = 64

// Sha256VersionStringRFC6979 is the RFC6979 nonce version for a Schnorr signature
// over the secp256k1 curve using SHA256 as the hash function.
var Sha256VersionStringRFC6979 = []byte("Schnorr+SHA256  ")

// BlakeVersionStringRFC6979 is the RFC6979 nonce version for a Schnorr signature
// over the secp256k1 curve using BLAKE256 as the hash function.
var BlakeVersionStringRFC6979 = []byte("Schnorr+BLAKE256")

// combinePubkeys combines a slice of public keys into a single public key
// by adding them together with point addition.

// scalarSize is the size of an encoded big endian scalar.
const scalarSize = 32

var (
	// bigZero is the big representation of zero.
	bigZero = new(big.Int).SetInt64(0)

	// ecTypeSecSchnorr is the ECDSA type for the chainec interface.
	ecTypeSecSchnorr = 2
)

// NewSignature instantiates a new signature given some R,S values.
func NewSignature(r, s *big.Int) *Signature {
	return &Signature{r, s}
}

// Serialize returns the Schnorr signature in the more strict format.
//
// The signatures are encoded as
//   sig[0:32]  R, a point encoded as big endian
//   sig[32:64] S, scalar multiplication/addition results = (ab+c) mod l
//     encoded also as big endian
func (sig Signature) Serialize() []byte {
	rBytes := bigIntToEncodedBytes(sig.R)
	sBytes := bigIntToEncodedBytes(sig.S)

	all := append(rBytes[:], sBytes[:]...)

	return all
}

// CombinePubkeys combines a slice of public keys into a single public key
// by adding them together with point addition.
func CombinePubkeys(pks []*secp256k1.PublicKey) *secp256k1.PublicKey {
	numPubKeys := len(pks)
	curve := secp256k1.S256()

	// Have to have at least two pubkeys.
	if numPubKeys < 1 {
		return nil
	}
	if numPubKeys == 1 {
		return pks[0]
	}
	if pks[0] == nil || pks[1] == nil {
		return nil
	}

	var pkSumX *big.Int
	var pkSumY *big.Int

	pkSumX, pkSumY = curve.Add(pks[0].GetX(), pks[0].GetY(),
		pks[1].GetX(), pks[1].GetY())

	if numPubKeys > 2 {
		for i := 2; i < numPubKeys; i++ {
			pkSumX, pkSumY = curve.Add(pkSumX, pkSumY,
				pks[i].GetX(), pks[i].GetY())
		}
	}

	if !curve.IsOnCurve(pkSumX, pkSumY) {
		return nil
	}

	return secp256k1.NewPublicKey(pkSumX, pkSumY)
}

// NonceRFC6979 is a local instantiation of deterministic nonce generation
// by the standards of RFC6979.
func NonceRFC6979(privkey []byte, hash []byte, extra []byte, version []byte) []byte {
	pkD := new(big.Int).SetBytes(privkey)
	defer pkD.SetInt64(0)
	bigK := secp256k1.NonceRFC6979(pkD, hash, extra, version)
	defer bigK.SetInt64(0)
	k := bigIntToEncodedBytes(bigK)
	return k[:]
}

// SchnorrPartialSign creates a partial Schnorr signature which may be combined
// with other Schnorr signatures to create a valid signature for a group pubkey.
func SchnorrPartialSign(msg []byte, priv []byte, privNonce []byte,
	pubSum *secp256k1.PublicKey, hashFunc func([]byte) []byte) (*Signature, error) {
	// Sanity checks.
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return nil, schnorrError(ErrBadInputSize, str)
	}
	if len(priv) != scalarSize {
		str := fmt.Sprintf("wrong size for privkey (got %v, want %v)",
			len(priv), scalarSize)
		return nil, schnorrError(ErrBadInputSize, str)
	}
	if len(privNonce) != scalarSize {
		str := fmt.Sprintf("wrong size for privnonce (got %v, want %v)",
			len(privNonce), scalarSize)
		return nil, schnorrError(ErrBadInputSize, str)
	}
	if pubSum == nil {
		str := fmt.Sprintf("nil pubkey")
		return nil, schnorrError(ErrInputValue, str)
	}

	curve := secp256k1.S256()
	privBig := new(big.Int).SetBytes(priv)
	if privBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("priv scalar is zero")
		return nil, schnorrError(ErrInputValue, str)
	}
	if privBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("priv scalar is out of bounds")
		return nil, schnorrError(ErrInputValue, str)
	}
	privBig.SetInt64(0)

	privNonceBig := new(big.Int).SetBytes(privNonce)
	if privNonceBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("privNonce scalar is zero")
		return nil, schnorrError(ErrInputValue, str)
	}
	if privNonceBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("privNonce scalar is out of bounds")
		return nil, schnorrError(ErrInputValue, str)
	}
	privNonceBig.SetInt64(0)

	if !curve.IsOnCurve(pubSum.GetX(), pubSum.GetY()) {
		str := fmt.Sprintf("public key sum is off curve")
		return nil, schnorrError(ErrInputValue, str)
	}

	return SchnorrSign(msg, priv, privNonce, pubSum.GetX(),
		pubSum.GetY(), hashFunc)
}

// SchnorrCombineSigs combines a list of partial Schnorr signatures s values
// into a complete signature s for some group public key. This is achieved
// by simply adding the s values of the partial signatures as scalars.
func SchnorrCombineSigs(sigss [][]byte) (*big.Int,
	error) {
	curve := secp256k1.S256()
	combinedSigS := new(big.Int).SetInt64(0)
	for i, sigs := range sigss {
		sigsBI := encodedBytesToBigInt(copyBytes(sigs))
		if sigsBI.Cmp(bigZero) == 0 {
			str := fmt.Sprintf("sig s %v is zero", i)
			return nil, schnorrError(ErrInputValue, str)
		}
		if sigsBI.Cmp(curve.N) >= 0 {
			str := fmt.Sprintf("sig s %v is out of bounds", i)
			return nil, schnorrError(ErrInputValue, str)
		}

		combinedSigS.Add(combinedSigS, sigsBI)
		combinedSigS.Mod(combinedSigS, curve.N)
	}

	if combinedSigS.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("combined sig s %v is zero", combinedSigS)
		return nil, schnorrError(ErrZeroSigS, str)
	}

	return combinedSigS, nil
}

// CombineSigs is the generalized and exported version of
// generateNoncePair.
func CombineSigs(sigs []*Signature) (*Signature, error) {
	sigss := make([][]byte, len(sigs))
	for i, sig := range sigs {
		if sig == nil {
			return nil, fmt.Errorf("nil signature")
		}

		if i > 0 {
			if sigs[i-1].GetR().Cmp(sig.GetR()) != 0 {
				str := fmt.Sprintf("nonmatching r values for idx %v, %v",
					i, i-1)
				return nil, schnorrError(ErrNonmatchingR, str)
			}
		}

		sigss[i] = bigIntToEncodedBytes(sig.GetS())[:]
	}

	combinedSigS, err := SchnorrCombineSigs(sigss)
	if err != nil {
		return nil, err
	}

	return NewSignature(sigs[0].R, combinedSigS), nil
}

// SchnorrSign signs a Schnorr signature using a specified hash function
// and the given nonce, private key, message, and optional public nonce.
// CAVEAT: Lots of variable time algorithms using both the private key and
// k, which can expose the signer to constant time attacks. You have been
// warned! DO NOT use this algorithm where you might have the possibility
// of someone having EM field/cache/etc access.
// Memory management is also kind of sloppy and whether or not your keys
// or nonces can be found in memory later is likely a product of when the
// garbage collector runs.
// TODO Use field elements with constant time algorithms to prevent said
// attacks.
// This is identical to the Schnorr signature function found in libsecp256k1:
// https://github.com/bitcoin/secp256k1/tree/master/src/modules/schnorr
func SchnorrSign(msg []byte, ps []byte, k []byte,
	pubNonceX *big.Int, pubNonceY *big.Int,
	hashFunc func([]byte) []byte) (*Signature, error) {
	curve := secp256k1.S256()
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return nil, schnorrError(ErrBadInputSize, str)
	}
	if len(ps) != scalarSize {
		str := fmt.Sprintf("wrong size for privkey (got %v, want %v)",
			len(ps), scalarSize)
		return nil, schnorrError(ErrBadInputSize, str)
	}
	if len(k) != scalarSize {
		str := fmt.Sprintf("wrong size for nonce k (got %v, want %v)",
			len(k), scalarSize)
		return nil, schnorrError(ErrBadInputSize, str)
	}

	psBig := new(big.Int).SetBytes(ps)
	bigK := new(big.Int).SetBytes(k)

	if psBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("secret scalar is zero")
		return nil, schnorrError(ErrInputValue, str)
	}
	if psBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("secret scalar is out of bounds")
		return nil, schnorrError(ErrInputValue, str)
	}
	if bigK.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("k scalar is zero")
		return nil, schnorrError(ErrInputValue, str)
	}
	if bigK.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("k scalar is out of bounds")
		return nil, schnorrError(ErrInputValue, str)
	}

	// R = kG
	var Rpx, Rpy *big.Int
	Rpx, Rpy = curve.ScalarBaseMult(k)
	if pubNonceX != nil && pubNonceY != nil {
		// Optional: if k' exists then R = R+k'
		Rpx, Rpy = curve.Add(Rpx, Rpy, pubNonceX, pubNonceY)
	}

	// Check if the field element that would be represented by Y is odd.
	// If it is, just keep k in the group order.
	if Rpy.Bit(0) == 1 {
		bigK.Mod(bigK, curve.N)
		bigK.Sub(curve.N, bigK)
	}

	// h = Hash(r || m)
	Rpxb := bigIntToEncodedBytes(Rpx)
	hashInput := make([]byte, 0, scalarSize*2)
	hashInput = append(hashInput, Rpxb[:]...)
	hashInput = append(hashInput, msg...)
	h := hashFunc(hashInput)
	hBig := new(big.Int).SetBytes(h)

	// If the hash ends up larger than the order of the curve, abort.
	if hBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("hash of (R || m) too big")
		return nil, schnorrError(ErrSchnorrHashValue, str)
	}

	// s = k - hx
	// TODO Speed this up a bunch by using field elements, not
	// big ints. That we multiply the private scalar using big
	// ints is also probably bad because we can only assume the
	// math isn't in constant time, thus opening us up to side
	// channel attacks. Using a constant time field element
	// implementation will fix this.
	sBig := new(big.Int)
	sBig.Mul(hBig, psBig)
	sBig.Sub(bigK, sBig)
	sBig.Mod(sBig, curve.N)

	if sBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("sig s %v is zero", sBig)
		return nil, schnorrError(ErrZeroSigS, str)
	}

	// Zero out the private key and nonce when we're done with it.
	bigK.SetInt64(0)
	zeroSlice(k)
	psBig.SetInt64(0)
	zeroSlice(ps)

	return &Signature{Rpx, sBig}, nil
}

// zeroSlice zeroes the memory of a scalar byte slice.
func zeroSlice(s []byte) {
	for i := 0; i < scalarSize; i++ {
		s[i] = 0x00
	}
}

// GetR satisfies the chainec PublicKey interface.
func (sig Signature) GetR() *big.Int {
	return sig.R
}

// GetS satisfies the chainec PublicKey interface.
func (sig Signature) GetS() *big.Int {
	return sig.S
}

// GetType satisfies the chainec Signature interface.
func (sig Signature) GetType() int {
	return ecTypeSecSchnorr
}

// SchnorrVerify is the internal function for verification of a secp256k1
// Schnorr signature. A secure hash function may be passed for the calculation
// of r.
// This is identical to the Schnorr verification function found in libsecp256k1:
// https://github.com/bitcoin/secp256k1/tree/master/src/modules/schnorr
func SchnorrVerify(sig []byte,
	pubkey *secp256k1.PublicKey, msg []byte, hashFunc func([]byte) []byte) (bool,
	error) {
	curve := secp256k1.S256()
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return false, schnorrError(ErrBadInputSize, str)
	}

	if len(sig) != SignatureSize {
		str := fmt.Sprintf("wrong size for signature (got %v, want %v)",
			len(sig), SignatureSize)
		return false, schnorrError(ErrBadInputSize, str)
	}
	if pubkey == nil {
		str := fmt.Sprintf("nil pubkey")
		return false, schnorrError(ErrInputValue, str)
	}

	if !curve.IsOnCurve(pubkey.GetX(), pubkey.GetY()) {
		str := fmt.Sprintf("pubkey point is not on curve")
		return false, schnorrError(ErrPointNotOnCurve, str)
	}

	sigR := sig[:32]
	sigS := sig[32:]
	sigRCopy := make([]byte, scalarSize)
	copy(sigRCopy, sigR)
	toHash := append(sigRCopy, msg...)
	h := hashFunc(toHash)
	hBig := new(big.Int).SetBytes(h)

	// If the hash ends up larger than the order of the curve, abort.
	// Same thing for hash == 0 (as unlikely as that is...).
	if hBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("hash of (R || m) too big")
		return false, schnorrError(ErrSchnorrHashValue, str)
	}
	if hBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("hash of (R || m) is zero value")
		return false, schnorrError(ErrSchnorrHashValue, str)
	}

	// Convert s to big int.
	sBig := encodedBytesToBigInt(copyBytes(sigS))

	// We also can't have s greater than the order of the curve.
	if sBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("s value is too big")
		return false, schnorrError(ErrInputValue, str)
	}

	// r can't be larger than the curve prime.
	rBig := encodedBytesToBigInt(copyBytes(sigR))
	if rBig.Cmp(curve.P) == 1 {
		str := fmt.Sprintf("given R was greater than curve prime")
		return false, schnorrError(ErrBadSigRNotOnCurve, str)
	}

	// r' = hQ + sG
	lx, ly := curve.ScalarMult(pubkey.GetX(), pubkey.GetY(), h)
	rx, ry := curve.ScalarBaseMult(sigS)
	rlx, rly := curve.Add(lx, ly, rx, ry)

	if rly.Bit(0) == 1 {
		str := fmt.Sprintf("calculated R y-value was odd")
		return false, schnorrError(ErrBadSigRYValue, str)
	}
	if !curve.IsOnCurve(rlx, rly) {
		str := fmt.Sprintf("calculated R point was not on curve")
		return false, schnorrError(ErrBadSigRNotOnCurve, str)
	}
	rlxB := bigIntToEncodedBytes(rlx)

	// r == r' --> valid signature
	if !bytes.Equal(sigR, rlxB[:]) {
		str := fmt.Sprintf("calculated R point was not given R")
		return false, schnorrError(ErrUnequalRValues, str)
	}

	return true, nil
}
