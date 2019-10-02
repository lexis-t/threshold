package threshold_test

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/lcpo/threshold"
)

// This example demonstrates signing a secp256k1 private key message for two parties
func Example_ForTwoNodes_signMessage() {
	// Generate public and private keys
	// for node 1
	private1, _ := secp256k1.GeneratePrivateKey()
	public1 := secp256k1.NewPublicKey(private1.Public())
	// for node 2
	private2, _ := secp256k1.GeneratePrivateKey()
	public2 := secp256k1.NewPublicKey(private2.Public())

	messageHash := threshold.SchnorrSha256Hash([]byte("test message"))

	fmt.Println("")

	fmt.Printf("private1: %x\n", private1.Serialize())
	fmt.Printf("private2: %x\n", private2.Serialize())
	fmt.Println("")
	fmt.Printf("public1: %x\n", public1.Serialize())
	fmt.Printf("public2: %x\n", public2.Serialize())
	fmt.Println("")
	fmt.Printf("messageH: %x\n", messageHash)
	// for node 1
	nonce1 := threshold.NonceRFC6979(private1.Serialize(), messageHash, nil, threshold.Sha256VersionStringRFC6979)
	// for node 2
	nonce2 := threshold.NonceRFC6979(private2.Serialize(), messageHash, nil, threshold.Sha256VersionStringRFC6979)
	fmt.Println("")
	fmt.Printf("nonce1: %x\n", nonce1)
	fmt.Printf("nonce2: %x\n", nonce2)
	fmt.Println("")
	// for node 1
	_, pubNonce1 := secp256k1.PrivKeyFromBytes(nonce1)
	// for node 2
	_, pubNonce2 := secp256k1.PrivKeyFromBytes(nonce2)
	fmt.Printf("pubNonce1: %x\n", pubNonce1.Serialize())
	fmt.Printf("pubNonce2: %x\n", pubNonce2.Serialize())
	fmt.Println("")

	partialSignatures := make([]*threshold.Signature, 2)
	// Each party must sign the message with foreign public keys.
	// for node1
	pubKeys1 := make([]*secp256k1.PublicKey, 1)
	pubKeys1[0] = pubNonce2
	combinedPubKeys1 := threshold.CombinePubkeys(pubKeys1)

	fmt.Printf("combinedPubKeys1: %x\n", combinedPubKeys1.Serialize())
	sig1, _ := threshold.SchnorrPartialSign(messageHash, private1.Serialize(), nonce1, combinedPubKeys1, threshold.SchnorrSha256Hash)
	partialSignatures[0] = sig1
	fmt.Printf("Sig1: %x\n", sig1.Serialize())

	// Each party must sign the message with foreign public keys.
	// for node2
	pubKeys2 := make([]*secp256k1.PublicKey, 1)
	pubKeys2[0] = pubNonce1
	combinedPubKeys2 := threshold.CombinePubkeys(pubKeys2)
	fmt.Printf("combinedPubKeys2: %x\n", combinedPubKeys2.Serialize())

	sig2, _ := threshold.SchnorrPartialSign(messageHash, private2.Serialize(), nonce2, combinedPubKeys2, threshold.SchnorrSha256Hash)
	partialSignatures[1] = sig2
	fmt.Printf("Sig2: %x\n", sig2.Serialize())

	// for all nodes
	fmt.Println("")
	// Combine signatures.
	combinedSignatures, _ := threshold.CombineSigs(partialSignatures)
	fmt.Printf("combinedSignatures: %x\n", combinedSignatures.Serialize())
	// Combine public keys.
	allPubkeys := make([]*secp256k1.PublicKey, 2)
	allPubkeys[0] = public1
	allPubkeys[1] = public2
	allPksSum := threshold.CombinePubkeys(allPubkeys)
	fmt.Printf("allPksSum: %x\n", allPksSum.Serialize())
	// Signature Verification
	verified, _ := threshold.SchnorrVerify(combinedSignatures.Serialize(), allPksSum, messageHash, threshold.SchnorrSha256Hash)
	fmt.Printf("Signature Verified? %v\n", verified)

}
