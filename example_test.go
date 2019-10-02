package threshold_test

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/lcpo/threshold"
)

// This example demonstrates signing a secp256k1 private key message for two parties
func Example_ForTwoNodesSignMessage() {
	// Generate public and private keys
	// for node 1
	private1, public1, _ := threshold.GenerateKeys()
	// for node 2
	private2, public2, _ := threshold.GenerateKeys()

	// for all nodes
	messageHash := threshold.SchnorrSha256Hash([]byte("test message"))

	// for node 1
	nonce1, pubNonce1 := threshold.GenerateNonces(private1, messageHash)
	// for node 2
	nonce2, pubNonce2 := threshold.GenerateNonces(private2, messageHash)

	partialSignatures := make([]*threshold.Signature, 2)
	// Each party must sign the message with foreign public keys.
	// for node 1
	pubKeys1 := make([]*secp256k1.PublicKey, 1)
	pubKeys1[0] = pubNonce2
	combinedPubKeys1 := threshold.CombinePubkeys(pubKeys1)
	sig1, _ := threshold.SchnorrPartialSign(messageHash, private1.Serialize(), nonce1,
		combinedPubKeys1, threshold.SchnorrSha256Hash)
	partialSignatures[0] = sig1

	// for node 2
	pubKeys2 := make([]*secp256k1.PublicKey, 1)
	pubKeys2[0] = pubNonce1
	combinedPubKeys2 := threshold.CombinePubkeys(pubKeys2)
	sig2, _ := threshold.SchnorrPartialSign(messageHash, private2.Serialize(), nonce2,
		combinedPubKeys2, threshold.SchnorrSha256Hash)
	partialSignatures[1] = sig2

	// for all nodes

	// Combine signatures.
	combinedSignatures, _ := threshold.CombineSigs(partialSignatures)

	// Combine public keys.
	allPubkeys := make([]*secp256k1.PublicKey, 2)
	allPubkeys[0] = public1
	allPubkeys[1] = public2
	allPksSum := threshold.CombinePubkeys(allPubkeys)

	// Signature Verification
	verified, _ := threshold.SchnorrVerify(combinedSignatures.Serialize(), allPksSum, messageHash, threshold.SchnorrSha256Hash)
	fmt.Printf("Signature Verified? %v\n", verified)

	// Output:
	// Signature Verified? true

}

// This example demonstrates signing a secp256k1 private key message for three parties
func Example_ForThreeNodesSignMessage() {
	// Generate public and private keys
	// for node 1
	private1, public1, _ := threshold.GenerateKeys()
	// for node 2
	private2, public2, _ := threshold.GenerateKeys()
	// for node 3
	private3, public3, _ := threshold.GenerateKeys()

	// for all nodes
	messageHash := threshold.SchnorrSha256Hash([]byte("test message"))

	// for node 1
	nonce1, pubNonce1 := threshold.GenerateNonces(private1, messageHash)
	// for node 2
	nonce2, pubNonce2 := threshold.GenerateNonces(private2, messageHash)
	// for node 3
	nonce3, pubNonce3 := threshold.GenerateNonces(private3, messageHash)

	partialSignatures := make([]*threshold.Signature, 3)
	// Each party must sign the message with foreign public keys.

	// for node 1
	pubKeys1 := make([]*secp256k1.PublicKey, 2)
	pubKeys1[0] = pubNonce2
	pubKeys1[1] = pubNonce3
	combinedPubKeys1 := threshold.CombinePubkeys(pubKeys1)
	sig1, _ := threshold.SchnorrPartialSign(messageHash, private1.Serialize(), nonce1,
		combinedPubKeys1, threshold.SchnorrSha256Hash)
	partialSignatures[0] = sig1

	// for node 2
	pubKeys2 := make([]*secp256k1.PublicKey, 2)
	pubKeys2[0] = pubNonce1
	pubKeys2[1] = pubNonce3
	combinedPubKeys2 := threshold.CombinePubkeys(pubKeys2)
	sig2, _ := threshold.SchnorrPartialSign(messageHash, private2.Serialize(), nonce2,
		combinedPubKeys2, threshold.SchnorrSha256Hash)
	partialSignatures[1] = sig2

	// for node 3
	pubKeys3 := make([]*secp256k1.PublicKey, 2)
	pubKeys3[0] = pubNonce1
	pubKeys3[1] = pubNonce2
	combinedPubKeys3 := threshold.CombinePubkeys(pubKeys3)
	sig3, _ := threshold.SchnorrPartialSign(messageHash, private3.Serialize(), nonce3,
		combinedPubKeys3, threshold.SchnorrSha256Hash)
	partialSignatures[2] = sig3
	// for all nodes

	// Combine signatures.
	combinedSignatures, _ := threshold.CombineSigs(partialSignatures)

	// Combine public keys.
	allPubkeys := make([]*secp256k1.PublicKey, 3)
	allPubkeys[0] = public1
	allPubkeys[1] = public2
	allPubkeys[2] = public3
	allPksSum := threshold.CombinePubkeys(allPubkeys)

	// Signature Verification
	verified, _ := threshold.SchnorrVerify(combinedSignatures.Serialize(), allPksSum, messageHash, threshold.SchnorrSha256Hash)
	fmt.Printf("Signature Verified? %v\n", verified)

	// Output:
	// Signature Verified? true
}
