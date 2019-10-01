package threshold_test

import (
	"encoding/hex"
	"fmt"

	// "github.com/davecgh/btcd/chaincfg/chainhash"
	// "github.com/davecgh/btcd/dcrec/secp256k1"
	// "github.com/davecgh/btcd/dcrec/secp256k1/schnorr"
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1"
	//"github.com/decred/dcrd/dcrec/secp256k1/schnorr"
	"github.com/lcpo/threshold"
)

func testSchnorrSha256Hash(msg []byte) []byte {
	sha := sha256.Sum256(msg)
	return sha[:]
}

func main() {
	// Generate public and private keys
	//private1, _ := secp256k1.GeneratePrivateKey()
	//public1 := secp256k1.NewPublicKey(private1.Public())
	//private2, _ := secp256k1.GeneratePrivateKey()
	//public2 := secp256k1.NewPublicKey(private2.Public())

	prvK1, _ := hex.DecodeString("23527007EB04CA9E0789C3F452A0B154338FCDEF1FF8C88C2FD52066E3684E52")
	private1, public1 := secp256k1.PrivKeyFromBytes(prvK1)

	prvK2, _ := hex.DecodeString("CB7ADC7097149F4A803D06F772DB7787BCCAFEB2EB9B83BCD87F8E1DB7C7DEB4")
	private2, public2 := secp256k1.PrivKeyFromBytes(prvK2)

	prvK3, _ := hex.DecodeString("13F64737DB01990CFB23DCF911EE9544821367BABF250E8D14278518523AE2EE")
	private3, public3 := secp256k1.PrivKeyFromBytes(prvK3)

	prvK4, _ := hex.DecodeString("F969F8FFA6320EFE7450AFDED4802DBB65EC0FC634831282898A9E1A148A672D")
	private4, public4 := secp256k1.PrivKeyFromBytes(prvK4)

	prvK5, _ := hex.DecodeString("7290D1CE9CED9EA92826BB930746B62C0D6476233778A25B46602B2CDD22521C")
	private5, public5 := secp256k1.PrivKeyFromBytes(prvK5)

	pubKeys := make([]*secp256k1.PublicKey, 5)
	pubKeys[0] = public1
	pubKeys[1] = public2
	pubKeys[2] = public3
	pubKeys[3] = public4
	pubKeys[4] = public5
	combinedPubKeys := threshold.CombinePubkeys(pubKeys)

	//messageHash := sha256.Sum256([]byte("test message"))
	messageHash, _ := hex.DecodeString("07BE073995BF78D440B660AF7B06DC0E9BA120A8D686201989BA99AA384ADF12")

	nonce1 := threshold.NonceRFC6979(private1.Serialize(), messageHash[:], nil, threshold.Sha256VersionStringRFC6979) //not work
	nonce2 := threshold.NonceRFC6979(private2.Serialize(), messageHash[:], nil, threshold.Sha256VersionStringRFC6979) //not work
	nonce3 := threshold.NonceRFC6979(private3.Serialize(), messageHash[:], nil, threshold.Sha256VersionStringRFC6979) //not work
	nonce4 := threshold.NonceRFC6979(private4.Serialize(), messageHash[:], nil, threshold.Sha256VersionStringRFC6979) //not work
	nonce5 := threshold.NonceRFC6979(private5.Serialize(), messageHash[:], nil, threshold.Sha256VersionStringRFC6979) //not work

	sig1, _ := threshold.SchnorrPartialSign(messageHash[:], private1.Serialize(), nonce1, combinedPubKeys, testSchnorrSha256Hash)
	sig2, _ := threshold.SchnorrPartialSign(messageHash[:], private2.Serialize(), nonce2, combinedPubKeys, testSchnorrSha256Hash)
	sig3, _ := threshold.SchnorrPartialSign(messageHash[:], private3.Serialize(), nonce3, combinedPubKeys, testSchnorrSha256Hash)
	sig4, _ := threshold.SchnorrPartialSign(messageHash[:], private4.Serialize(), nonce4, combinedPubKeys, testSchnorrSha256Hash)
	sig5, _ := threshold.SchnorrPartialSign(messageHash[:], private5.Serialize(), nonce5, combinedPubKeys, testSchnorrSha256Hash)

	fmt.Printf("private1: %x\n", private1.Serialize())
	fmt.Printf("private2: %x\n", private2.Serialize())
	fmt.Printf("private3: %x\n", private3.Serialize())
	fmt.Printf("private4: %x\n", private4.Serialize())
	fmt.Printf("private5: %x\n", private5.Serialize())
	fmt.Println("")
	fmt.Printf("public1: %x\n", public1.Serialize())
	fmt.Printf("public2: %x\n", public2.Serialize())
	fmt.Printf("public3: %x\n", public3.Serialize())
	fmt.Printf("public4: %x\n", public4.Serialize())
	fmt.Printf("public5: %x\n", public5.Serialize())
	fmt.Println("")
	fmt.Printf("messageH: %x\n", messageHash)
	fmt.Println("")
	fmt.Printf("nonce1: %x\n", nonce1)
	fmt.Printf("nonce2: %x\n", nonce2)
	fmt.Printf("nonce3: %x\n", nonce3)
	fmt.Printf("nonce4: %x\n", nonce4)
	fmt.Printf("nonce5: %x\n", nonce5)
	fmt.Println("")
	fmt.Printf("Sig1: %x\n", sig1.Serialize())
	fmt.Printf("Sig2: %x\n", sig2.Serialize())
	fmt.Printf("Sig3: %x\n", sig3.Serialize())
	fmt.Printf("Sig4: %x\n", sig4.Serialize())
	fmt.Printf("Sig5: %x\n", sig5.Serialize())

	partialSignatures := make([]*threshold.Signature, 5)
	partialSignatures[0] = sig1
	partialSignatures[1] = sig2
	partialSignatures[2] = sig3
	partialSignatures[3] = sig4
	partialSignatures[4] = sig5
	combinedSignatures, err := threshold.CombineSigs(partialSignatures)
	if err != nil {
		fmt.Printf("3 unexpected error %s, \n", err)
	}
	// Verify the signature for the message using the public key.
	signature1, _ := private1.Sign(messageHash[:])
	verified := signature1.Verify(messageHash[:], public1)
	fmt.Printf("Signature Verified? %v\n", verified)
	//------------------------------------------------------------
	//r, s, _ := schnorr.Sign(private1, messageHash[:])
	//verified2 := schnorr.Verify(combinedPubKeys, messageHash[:], r, s)
	//fmt.Printf("Signature Verified? %v\n", verified2)
	//-----------------------------------------------------------------
	fmt.Println("publicKey1: ", hex.EncodeToString(public1.Serialize()))
	fmt.Println("privateKey1: ", hex.EncodeToString(private1.Serialize()))
	fmt.Println("publicKey2: ", hex.EncodeToString(public2.Serialize()))
	fmt.Println("privateKey2: ", hex.EncodeToString(private2.Serialize()))
	fmt.Println("final publicKey: ", hex.EncodeToString(combinedPubKeys.Serialize()))
	fmt.Printf("Signature1: %x\n", signature1.Serialize())
	fmt.Printf("final Signature2: %x\n", combinedSignatures)
}
