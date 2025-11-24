package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/stretchr/testify/assert"
)

// THE PTLC IMPLEMENTATION HERE IS HIGHLY EXPERIMENTAL
// IT DOES NOT PROVIDE PROTECTION AGAINST KEY CANCELLATION ATTACKS
// IT IS HOWEVER A GOOD STARTING POINT TO UNDERSTAND THE PTLC CONCEPT

// go test -v -run ^TestPTLCAliceSig$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestPTLCAliceSig(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	// Alice, Bob key pair
	_, pair_1 := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, pair_2 := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)
	var alice_pub_point btcec.JacobianPoint
	pair_1.Pub.AsJacobian(&alice_pub_point)
	var bob_pub_point btcec.JacobianPoint
	pair_2.Pub.AsJacobian(&bob_pub_point)
	// P' = P_A + P_B
	var aggr_key_point btcec.JacobianPoint
	btcec.AddNonConst(&alice_pub_point, &bob_pub_point, &aggr_key_point)
	aggr_key_point.ToAffine()
	aggrKey := btcec.NewPublicKey(&aggr_key_point.X, &aggr_key_point.Y)

	// generate a random 32 bytes (btec has a way to generate deterministic nonce)
	secret := s.Generate32BSeed()
	nonce := s.Generate32BSeed()

	secret_t, _ := btcec.PrivKeyFromBytes(secret[:])

	r, _ := btcec.PrivKeyFromBytes(nonce[:])

	// calculate r + t
	var secret_r_t btcec.ModNScalar
	secret_r_t.Add2(&secret_t.Key, &r.Key)
	t.Logf("Nonce + Secret: %v\n", secret_r_t)

	// STEP 1: Alice creates a signature with secret (s, R+T)
	// sign with custom nonce: r + t
	// s_A = r + t + H(R + T, P_A + P_B, m) * p_A
	sigHashes := sha256.Sum256([]byte("signature hash"))
	customPTLCSignA(&s, r.Key, secret_t.Key, aggrKey, pair_1.GetTestPriv(), sigHashes)
}

// go test -v -run ^TestPTLCCombinedSig$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestPTLCCombinedSig(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	// Alice, Bob key pair
	_, pair_1 := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, pair_2 := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)
	var alice_pub_point btcec.JacobianPoint
	pair_1.Pub.AsJacobian(&alice_pub_point)
	var bob_pub_point btcec.JacobianPoint
	pair_2.Pub.AsJacobian(&bob_pub_point)
	// P' = P_A + P_B
	var aggr_key_point btcec.JacobianPoint
	btcec.AddNonConst(&alice_pub_point, &bob_pub_point, &aggr_key_point)
	aggr_key_point.ToAffine()
	aggrKey := btcec.NewPublicKey(&aggr_key_point.X, &aggr_key_point.Y)

	// generate a random 32 bytes (btec has a way to generate deterministic nonce)
	secret := s.Generate32BSeed()
	nonce := s.Generate32BSeed()

	// T, R here is not yet normalized to ensure that y - value is even
	secret_t, _ := btcec.PrivKeyFromBytes(secret[:])
	r, _ := btcec.PrivKeyFromBytes(nonce[:])

	// STEP 1: Alice creates a signature with secret (s, R+T)
	// sign with custom nonce: r + t
	// s_A = r + t + H(R + T, P_A + P_B, m) * p_A
	sigHashes := sha256.Sum256([]byte("signature hash"))
	R, T, sig_A, parityFactor := customPTLCSignA(&s, r.Key, secret_t.Key, aggrKey, pair_1.GetTestPriv(), sigHashes)

	// STEP 2: Bob creates adaptor signture with secret (s', R, T)
	sig_B := customPTLCSignB(&s, R, T, aggrKey, pair_2.GetTestPriv(), sigHashes)

	// step 3: Alice construct combined signature of sig_A + t + sig_B to claim the funds
	sig_A_bytes := sig_A.Serialize()
	var sig_A_s btcec.ModNScalar
	sig_A_s.SetBytes((*[32]byte)(sig_A_bytes[32:64]))
	var sig_A_r btcec.FieldVal
	sig_A_r.SetBytes((*[32]byte)(sig_A_bytes[0:32]))

	sig_B_bytes := sig_B.Serialize()
	var sig_B_s btcec.ModNScalar
	sig_B_s.SetBytes((*[32]byte)(sig_B_bytes[32:64]))
	var sig_B_r btcec.FieldVal
	sig_B_r.SetBytes((*[32]byte)(sig_B_bytes[0:32]))

	parity_t := new(btcec.ModNScalar).Mul2(&secret_t.Key, parityFactor)
	var combined_sig_s btcec.ModNScalar
	combined_sig_s.Add2(&sig_A_s, &sig_B_s)
	combined_sig_s.Add(parity_t)
	var combined_sig_r btcec.FieldVal
	combined_sig_r.Add2(&sig_A_r, &sig_B_r)
	combined_sig := schnorr.NewSignature(&combined_sig_r, &combined_sig_s)
	assert.True(t, combined_sig.Verify(sigHashes[:], aggrKey))

	// step 4: Bob now sees the combined signature (sig_A + t + sig_B) and will extract t from it
	var recovered_t btcec.ModNScalar
	recovered_t.Add(&combined_sig_s).Add(sig_A_s.Negate()).Add(sig_B_s.Negate())
	assert.Equal(t, parity_t, &recovered_t)
}

// go test -v -run ^TestPTLC$ github.com/nghuyenthevinh2000/bitcoin-playground
// the PTLC is between Alice and Bob, and Bob has to send Alice 1 btc, if Alice can provide private data x
func TestPTLC(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t, log.Default())

	// Alice, Bob key pair
	_, pair_1 := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, pair_2 := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)

	// Alice, Bob aggregated pubkey
	var alice_pub_point btcec.JacobianPoint
	pair_1.Pub.AsJacobian(&alice_pub_point)
	var bob_pub_point btcec.JacobianPoint
	pair_2.Pub.AsJacobian(&bob_pub_point)
	// P' = P_A + P_B
	var aggr_key_point btcec.JacobianPoint
	btcec.AddNonConst(&alice_pub_point, &bob_pub_point, &aggr_key_point)
	aggr_key_point.ToAffine()
	aggrKey := btcec.NewPublicKey(&aggr_key_point.X, &aggr_key_point.Y)

	// B challenge to A
	var tapLeafs []txscript.TapLeaf
	// how the verification of secret a and point x works in script?
	// in a way that she has to reveal a, but also not public?
	// I don't fully understand PTLC yet
	builder_1 := txscript.NewScriptBuilder()
	// the challenge that B sets out for A
	builder_1.AddData(schnorr.SerializePubKey(aggrKey))
	builder_1.AddOp(txscript.OP_CHECKSIG)
	pkScript_1, err := builder_1.Script()
	assert.Nil(t, err)
	tapLeafs = append(tapLeafs, txscript.NewBaseTapLeaf(pkScript_1))

	// how to set time value here?
	// need to understand how OP_CHECKLOCKTIMEVERIFY works?
	builder_2 := txscript.NewScriptBuilder()
	builder_2.AddInt64(5)
	builder_2.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
	builder_2.AddOp(txscript.OP_DROP)
	builder_2.AddData(schnorr.SerializePubKey(pair_2.Pub))
	builder_2.AddOp(txscript.OP_CHECKSIG)
	pkScript_2, err := builder_2.Script()
	assert.Nil(t, err)
	tapLeafs = append(tapLeafs, txscript.NewBaseTapLeaf(pkScript_2))

	tapTree := txscript.AssembleTaprootScriptTree(tapLeafs...)

	// calculate tweaked public key
	tapTreeCommitment := tapTree.RootNode.TapHash()
	_, internal_pair := s.NewHDKeyPairFromSeed(OMNIMAN_WALLET_SEED)
	q := txscript.ComputeTaprootOutputKey(internal_pair.Pub, tapTreeCommitment[:])
	taproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(q), s.BtcdChainConfig)
	assert.Nil(t, err)
	fmt.Printf("Taproot address: %s\n", taproot.String())

	p2tr, err := txscript.NewScriptBuilder().AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(q)).Script()
	assert.Nil(t, err)

	// SCENARIO 1: Alice reveals the secret t to Bob, and claims the funds
	// Alice gives her adaptor signature to Bob (s_A', R, T)
	// Bbob gives his adaptor signature to Alice (s_B)
	// Alice reveals (s_A' + t + s_B) to claim the funds
	// Bob derives t = (s_A' + t + s_B) - s_A' - s_B
	// enable tracing to see how the script is executed
	backendLog := btclog.NewBackend(os.Stdout)
	testLog := backendLog.Logger("MAIN")
	testLog.SetLevel(btclog.LevelTrace)
	txscript.UseLogger(testLog)

	// control block bytes for leaf 0
	inclusionProof_0 := tapTree.LeafMerkleProofs[0]
	controlBlock_0 := inclusionProof_0.ToControlBlock(internal_pair.Pub)
	ctrlBlockBytes_0, err := controlBlock_0.ToBytes()
	assert.Nil(t, err)

	var alice_adaptor_sig []byte
	var bob_adaptor_sig []byte
	var alice_combined_sig []byte
	var alice_secret []byte
	s.ValidateScript(p2tr, 1, func(t assert.TestingT, prevOut *wire.TxOut, tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int) wire.TxWitness {
		// calculating sighash
		inputFetcher := txscript.NewCannedPrevOutputFetcher(
			prevOut.PkScript,
			prevOut.Value,
		)
		hType := txscript.SigHashDefault
		sigHash, err := txscript.CalcTapscriptSignaturehash(sigHashes, hType, tx, idx, inputFetcher, tapLeafs[0])
		assert.Nil(t, err)

		// STEP 1: Alice gives her adaptor signature to Bob (s_A', R, T)
		secret := s.Generate32BSeed()
		nonce := s.Generate32BSeed()

		secret_t, _ := btcec.PrivKeyFromBytes(secret[:])
		alice_secret = secret[:]
		r, _ := btcec.PrivKeyFromBytes(nonce[:])

		R, T, sig_A, parityFactor := customPTLCSignA(&s, r.Key, secret_t.Key, aggrKey, pair_1.GetTestPriv(), ([32]byte)(sigHash))
		alice_adaptor_sig = sig_A.Serialize()

		// STEP 2: Bob gives his adaptor signature to Alice (s_B)
		sig_B := customPTLCSignB(&s, R, T, aggrKey, pair_2.GetTestPriv(), ([32]byte)(sigHash))
		bob_adaptor_sig = sig_B.Serialize()

		// STEP 3: Alice reveals (s_A' + t + s_B) to claim the funds
		sig_A_bytes := sig_A.Serialize()
		var sig_A_s btcec.ModNScalar
		sig_A_s.SetBytes((*[32]byte)(sig_A_bytes[32:64]))
		var sig_A_r btcec.FieldVal
		sig_A_r.SetBytes((*[32]byte)(sig_A_bytes[0:32]))

		sig_B_bytes := sig_B.Serialize()
		var sig_B_s btcec.ModNScalar
		sig_B_s.SetBytes((*[32]byte)(sig_B_bytes[32:64]))
		var sig_B_r btcec.FieldVal
		sig_B_r.SetBytes((*[32]byte)(sig_B_bytes[0:32]))

		parity_t := new(btcec.ModNScalar).Mul2(&secret_t.Key, parityFactor)
		var combined_sig_s btcec.ModNScalar
		combined_sig_s.Add2(&sig_A_s, &sig_B_s)
		combined_sig_s.Add(parity_t)
		var combined_sig_r btcec.FieldVal
		combined_sig_r.Add2(&sig_A_r, &sig_B_r)
		combined_sig := schnorr.NewSignature(&combined_sig_r, &combined_sig_s)

		alice_combined_sig = combined_sig.Serialize()
		if hType != txscript.SigHashDefault {
			alice_combined_sig = append(alice_combined_sig, byte(hType))
		}

		// precheck the signature
		assert.True(t, combined_sig.Verify(sigHash[:], aggrKey))

		witness := wire.TxWitness{
			alice_combined_sig, tapLeafs[0].Script, ctrlBlockBytes_0,
		}

		return witness
	})

	// with alice_combined_sig revealed on Bitcoin, Bob can now extract the secret t
	var recovered_sig_r btcec.FieldVal
	recovered_sig_r.SetBytes((*[32]byte)(alice_combined_sig[0:32]))
	var recovered_sig_s btcec.ModNScalar
	recovered_sig_s.SetBytes((*[32]byte)(alice_combined_sig[32:64]))

	var recovered_sig_A_r btcec.FieldVal
	recovered_sig_A_r.SetBytes((*[32]byte)(alice_adaptor_sig[0:32]))
	var recovered_sig_A_s btcec.ModNScalar
	recovered_sig_A_s.SetBytes((*[32]byte)(alice_adaptor_sig[32:64]))

	var recovered_sig_B_r btcec.FieldVal
	recovered_sig_B_r.SetBytes((*[32]byte)(bob_adaptor_sig[0:32]))
	var recovered_sig_B_s btcec.ModNScalar
	recovered_sig_B_s.SetBytes((*[32]byte)(bob_adaptor_sig[32:64]))

	var recovered_t btcec.ModNScalar
	recovered_t.Add(&recovered_sig_s).Add(recovered_sig_A_s.Negate()).Add(recovered_sig_B_s.Negate())
	recovered_secret := btcec.PrivKeyFromScalar(&recovered_t)
	assert.Equal(t, alice_secret, recovered_secret.Serialize())

	// SCENARIO 2: timeout and Bob retrieves his funds
	// control block bytes for leaf 1
	inclusionProof_1 := tapTree.LeafMerkleProofs[1]
	controlBlock_1 := inclusionProof_1.ToControlBlock(internal_pair.Pub)
	ctrlBlockBytes_1, err := controlBlock_1.ToBytes()
	assert.Nil(t, err)

	s.ValidateScript(p2tr, 10, func(t assert.TestingT, prevOut *wire.TxOut, tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int) wire.TxWitness {
		// Bob signature
		sig, err := txscript.RawTxInTapscriptSignature(tx, sigHashes, idx, prevOut.Value, p2tr, tapLeafs[1], txscript.SigHashDefault, pair_2.GetTestPriv())
		assert.Nil(t, err)

		witness := wire.TxWitness{
			sig, tapLeafs[1].Script, ctrlBlockBytes_1,
		}

		return witness
	})
}

// these are the information that A has access to
// s_A = r + t + H(R + T, P_A + P_B, m) * p_A
// return (even - y R, even - y T, s)
func customPTLCSignA(suite *testhelper.TestSuite, r, t btcec.ModNScalar, aggrPubKey *btcec.PublicKey, signingA *btcec.PrivateKey, m [32]byte) (*btcec.PublicKey, *btcec.PublicKey, *schnorr.Signature, *btcec.ModNScalar) {
	// rt = r + t
	var rt btcec.ModNScalar
	rt.Add2(&r, &t)
	// calculate H(R + T, P_A + P_B, m)
	var p_A_scalar btcec.ModNScalar
	p_A_scalar.Set(&signingA.Key)
	// P_A + P_B
	aggrPubKeyBytes := aggrPubKey.SerializeCompressed()
	// I don't know how public key whose Y coordinate is odd can bring problems?
	if aggrPubKeyBytes[0] == secp.PubKeyFormatCompressedOdd {
		p_A_scalar.Negate()
	}
	// calculate nonce
	// public nonce derivation
	// RT = rG + tG
	var RT btcec.JacobianPoint
	var rG btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&r, &rG)
	var tG btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&t, &tG)
	btcec.AddNonConst(&rG, &tG, &RT)
	RT.ToAffine()
	// parity factor helps propagating the sign of y - value of r and t
	parityFactor := new(btcec.ModNScalar).SetInt(1)
	if RT.Y.IsOdd() {
		r.Negate()
		t.Negate()
		parityFactor.Negate()
	}

	// e = tagged_hash("BIP0340/challenge", bytes(RT) || bytes(P_A + P_B) || m) mod n
	commitment := chainhash.TaggedHash(
		chainhash.TagBIP0340Challenge, RT.X.Bytes()[:], aggrPubKeyBytes[1:], m[:],
	)
	var e btcec.ModNScalar
	overflow := e.SetBytes((*[32]byte)(commitment))
	assert.Equal(suite.T, overflow, uint32(0), "overflow")

	// s = r + t + e*p_A mod n
	s := new(btcec.ModNScalar).Mul2(&e, &p_A_scalar).Add(&r).Add(&t)
	sig_r := RT.X

	// quick verify
	// sG == R + T + eP_A
	var sG btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(s, &sG)
	// P_A = p_A*G
	var P_A btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&p_A_scalar, &P_A)
	// eP_A
	var eP_A btcec.JacobianPoint
	btcec.ScalarMultNonConst(&e, &P_A, &eP_A)
	// R + T + eP_A
	if RT.Y.IsOdd() {
		rG.Y.Negate(1)
		rG.Y.Normalize()
		tG.Y.Negate(1)
		tG.Y.Normalize()
	}
	var RT_eP btcec.JacobianPoint
	btcec.AddNonConst(&rG, &tG, &RT_eP)
	btcec.AddNonConst(&RT_eP, &eP_A, &RT_eP)
	// calculate sG - eP_A
	e.Negate()
	btcec.ScalarMultNonConst(&e, &P_A, &eP_A)
	var sG_eP btcec.JacobianPoint
	btcec.AddNonConst(&sG, &eP_A, &sG_eP)
	// sG == R + T + eP_A
	RT_eP.ToAffine()
	sG.ToAffine()
	assert.Equal(suite.T, RT_eP.X, sG.X)
	// R + T == sG - eP_A
	sG_eP.ToAffine()
	assert.Equal(suite.T, sig_r, sG_eP.X)

	// s' = s - t
	s.Add(t.Negate())
	sig := schnorr.NewSignature(&sig_r, s)
	rG.ToAffine()
	tG.ToAffine()
	return btcec.NewPublicKey(&rG.X, &rG.Y), btcec.NewPublicKey(&tG.X, &tG.Y), sig, parityFactor
}

// these are the information that B has access to
// B return a signature adaptor to A with only s_B = e*p_B mod n
func customPTLCSignB(suite *testhelper.TestSuite, R, T, aggrPubKey *btcec.PublicKey, signingB *btcec.PrivateKey, m [32]byte) *schnorr.Signature {
	// calculate H(R + T, P_A + P_B, m)
	var p_B_scalar btcec.ModNScalar
	p_B_scalar.Set(&signingB.Key)
	// P_A + P_B
	aggrPubKeyBytes := aggrPubKey.SerializeCompressed()
	// I don't know how public key whose Y coordinate is odd can bring problems?
	if aggrPubKeyBytes[0] == secp.PubKeyFormatCompressedOdd {
		p_B_scalar.Negate()
	}
	// calculate nonce
	// public nonce derivation
	// RT = rG + tG
	var RT btcec.JacobianPoint
	var rG btcec.JacobianPoint
	R.AsJacobian(&rG)
	var tG btcec.JacobianPoint
	T.AsJacobian(&tG)
	btcec.AddNonConst(&rG, &tG, &RT)
	RT.ToAffine()
	assert.False(suite.T, RT.Y.IsOdd(), "RT.Y is odd")

	// calculate challenge e
	// e = tagged_hash("BIP0340/challenge", bytes(RT) || bytes(P_A + P_B) || m) mod n
	commitment := chainhash.TaggedHash(
		chainhash.TagBIP0340Challenge, RT.X.Bytes()[:], aggrPubKeyBytes[1:], m[:],
	)
	var e btcec.ModNScalar
	overflow := e.SetBytes((*[32]byte)(commitment))
	assert.Equal(suite.T, overflow, uint32(0), "overflow")

	// calculate s =  e*p_B mod n
	s := new(btcec.ModNScalar).Mul2(&e, &p_B_scalar)
	sig_r := btcec.FieldVal{}
	sig_r.Zero()
	sig := schnorr.NewSignature(&sig_r, s)

	return sig
}
