package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// this is an example of key spend path
// go test -v -run ^TestMuSig2$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestMuSig2(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t)

	// create aggregated public key
	_, pair_1 := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, pair_2 := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)
	pubPair := []*btcec.PublicKey{pair_1.Pub, pair_2.Pub}
	q, trScript := constructMuSig2Channel(&s, pubPair)

	// create aggregated nonces
	nonce_1, err := musig2.GenNonces(musig2.WithPublicKey(pair_1.Pub))
	assert.Nil(s.T, err)
	nonce_2, err := musig2.GenNonces(musig2.WithPublicKey(pair_2.Pub))
	assert.Nil(s.T, err)
	aggrNonces, err := musig2.AggregateNonces([][66]byte{nonce_1.PubNonce, nonce_2.PubNonce})
	assert.Nil(s.T, err)

	// verify aggregated signature
	// check aggregated R value, it should be the same as when signing
	s.ValidateScript(trScript, 1, func(t *testing.T, prevOut *wire.TxOut, tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int) wire.TxWitness {
		// calculating sighash
		inputFetcher := txscript.NewCannedPrevOutputFetcher(
			prevOut.PkScript,
			prevOut.Value,
		)
		hType := txscript.SigHashDefault
		sigHash, err := txscript.CalcTaprootSignatureHash(sigHashes, hType, tx, idx, inputFetcher)
		assert.Nil(t, err)

		// generate partial signatures for each participant
		// sign already negates nonce with odd y - value
		// s1, R
		ps_1, err := musig2.Sign(nonce_1.SecNonce, pair_1.GetTestPriv(), aggrNonces, pubPair, ([32]byte)(sigHash))
		assert.Nil(t, err)
		// s2, R
		ps_2, err := musig2.Sign(nonce_2.SecNonce, pair_2.GetTestPriv(), aggrNonces, pubPair, ([32]byte)(sigHash))
		assert.Nil(t, err)

		// aggregate partial signatures
		// the combined nonce is in each partial signature R value
		schnorrSig := musig2.CombineSigs(ps_2.R, []*musig2.PartialSignature{ps_1, ps_2})

		// I can add sighash flag to the end of the schnorr signature, thus changing sighash
		// if sighash default, then 64 bytes in size, else 65 bytes
		schnorrSigBytes := schnorrSig.Serialize()
		if hType != txscript.SigHashDefault {
			schnorrSigBytes = append(schnorrSigBytes, byte(hType))
		}

		// precheck the signature
		res := schnorrSig.Verify(sigHash[:], q)
		assert.True(t, res)

		witness := wire.TxWitness{
			schnorrSigBytes,
		}

		return witness
	})
}

// a test for 2/3 multisig using Taproot OP_CHECKSIGADD
// first test will linearly combine the public keys
// go test -v -run ^TestLinearTaprootMuSig$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestLinearTaprootMuSig(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t)

	_, pair_1 := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, pair_2 := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)
	_, pair_3 := s.NewHDKeyPairFromSeed(OLIVIA_WALLET_SEED)

	// STEP 1: BUILDING LINEAR MULTISIG SCRIPT
	// OP_CHECKSIGADD is only available in Taproot
	builder := txscript.NewScriptBuilder()
	// sig_1 will be verified against pub_1, if valid then 1, else 0
	// use schnorr pubkey for taproot OP_CHECKSIG
	// pub hex: 2bc2cfa7264c496a23e3f735b2bb586ea7ace3953fb5556206a68f744406fc45
	// priv hex: 4ec4caf5e470d93f2b76847543052200909762bd547b82454751193968992f52
	builder.AddData(schnorr.SerializePubKey(pair_1.Pub))
	builder.AddOp(txscript.OP_CHECKSIG)
	// sig_2 will be verified against pub_2, if valid then +1, else +0
	// pub hex: d9b98ef2c580416ca828801f5c3d0afb81b10639f5b5a1abe81dad89af7779af
	// priv hex: 5cb063214fff61270093e7959f2778255dd6c633425be5977c2347ecb7515938
	builder.AddData(schnorr.SerializePubKey(pair_2.Pub))
	builder.AddOp(txscript.OP_CHECKSIGADD)
	// sig_3 will be verified against pub_3, if valid then +1, else +0
	// pub hex: e0fce228941493bb4dbab3c38e9b762dc0c500b0d4f5485734efd39a37dfd067
	// priv hex: 9bfa621ce43f4a0ba1961b01508fc8d17a83f36aa94a6ef5bb98cd1387dacad4
	builder.AddData(schnorr.SerializePubKey(pair_3.Pub))
	builder.AddOp(txscript.OP_CHECKSIGADD)
	// it will check if the sum of the results is equal to 2 thus satisfying 2/3 multisig
	builder.AddOp(txscript.OP_2)
	builder.AddOp(txscript.OP_EQUAL)
	pkScript, err := builder.Script()
	assert.Nil(t, err)

	// STEP 2: CALCULATE TWEAKED PUBLIC KEY
	// calculate tweak: create a taproot tree
	// TODO: I am curious how btcd handle tree construction, should test with more tapleafs in another test
	tapleaf := txscript.NewBaseTapLeaf(pkScript)
	taptree := txscript.AssembleTaprootScriptTree(tapleaf)

	// 202bc2cfa7264c496a23e3f735b2bb586ea7ace3953fb5556206a68f744406fc45ac7c20d9b98ef2c580416ca828801f5c3d0afb81b10639f5b5a1abe81dad89af7779afba7c20e0fce228941493bb4dbab3c38e9b762dc0c500b0d4f5485734efd39a37dfd067ba0287
	// 202bc2cfa7264c496a23e3f735b2bb586ea7ace3953fb5556206a68f744406fc45ac7c20d9b98ef2c580416ca828801f5c3d0afb81b10639f5b5a1abe81dad89af7779afba7c20e0fce228941493bb4dbab3c38e9b762dc0c500b0d4f5485734efd39a37dfd067ba5287
	fmt.Printf("tap script = %s\n", hex.EncodeToString(tapleaf.Script))

	// get internal private key P
	// pub hex: 7dec1d4eb66497d20ad3ce1a8f7e99d207e5dadf4a093a3dede664dd89d9ac10
	_, internal_pair := s.NewHDKeyPairFromSeed(OMNIMAN_WALLET_SEED)
	fmt.Printf("pub_internal: %s\n", s.BytesToHexStr(schnorr.SerializePubKey(internal_pair.Pub)))

	// tr pub Q = P + t*G
	taptreeRootCommitment := taptree.RootNode.TapHash()
	fmt.Printf("Taproot tree: %s\n", hex.EncodeToString(taptreeRootCommitment[:]))

	q := txscript.ComputeTaprootOutputKey(internal_pair.Pub, taptreeRootCommitment[:])
	assert.NotNil(t, q)
	taproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(q), s.BtcdChainConfig)
	assert.Nil(t, err)
	fmt.Printf("Taproot address: %s\n", taproot.String())

	// STEP 3: CREATE WITNESS FOR EVALUATION
	// OP_1 to signify SegWit v1: Taproot
	p2trScript, err := txscript.
		NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(q)).
		Script()
	assert.Nil(t, err)

	// create control block
	// get inclusion proof of tapleaf at position 0
	inclusionProof := taptree.LeafMerkleProofs[0]
	controlBlock := inclusionProof.ToControlBlock(
		internal_pair.Pub,
	)
	controlBlockBytes, err := controlBlock.ToBytes()
	assert.Nil(t, err)

	// enable tracing to see how the script is executed
	backendLog := btclog.NewBackend(os.Stdout)
	testLog := backendLog.Logger("MAIN")
	testLog.SetLevel(btclog.LevelTrace)
	txscript.UseLogger(testLog)

	s.ValidateScript(p2trScript, 1, func(t *testing.T, prevOut *wire.TxOut, tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int) wire.TxWitness {
		sig_1 := []byte{}

		sig_2, err := txscript.RawTxInTapscriptSignature(tx, sigHashes, idx, prevOut.Value, p2trScript, tapleaf, txscript.SigHashDefault, pair_2.GetTestPriv())
		assert.Nil(t, err)

		sig_3, err := txscript.RawTxInTapscriptSignature(tx, sigHashes, idx, prevOut.Value, p2trScript, tapleaf, txscript.SigHashDefault, pair_3.GetTestPriv())
		assert.Nil(t, err)

		// first participant should be nil
		// to satisfy 2/3 multisig
		// the witness data will be pushed onto a stack
		// sig_3 will be at bottom, then sig_2, then sig_1 on top
		witness := wire.TxWitness{
			sig_3, sig_2, sig_1, pkScript, controlBlockBytes,
		}

		return witness
	})
}

// second test will use three subset of 2/2
// public keys as spending conditions for multisg 2/3
// can I combine it with MuSig2? yes, I can use MuSig2
// I will try to spend with key 1 and key 3
// go test -v -run ^TestSubsetTaprootMuSig$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestSubsetTaprootMuSig(t *testing.T) {
	s := testhelper.TestSuite{}
	s.SetupStaticSimNetSuite(t)

	_, pair_1 := s.NewHDKeyPairFromSeed(ALICE_WALLET_SEED)
	_, pair_2 := s.NewHDKeyPairFromSeed(BOB_WALLET_SEED)
	_, pair_3 := s.NewHDKeyPairFromSeed(OLIVIA_WALLET_SEED)

	subset := [][]*btcec.PublicKey{
		{pair_1.Pub, pair_2.Pub},
		{pair_1.Pub, pair_3.Pub},
		{pair_2.Pub, pair_3.Pub},
	}

	var tapLeaf []txscript.TapLeaf

	// STEP 1: BUILDING SUBSET MULTISIG SCRIPT
	for i := 0; i < len(subset); i++ {
		// create subset of 2/3 multisig
		aggrPub, _, _, err := musig2.AggregateKeys(subset[i], false)
		assert.Nil(s.T, err)

		builder := txscript.NewScriptBuilder()
		builder.AddData(schnorr.SerializePubKey(aggrPub.FinalKey))
		//
		builder.AddOp(txscript.OP_CHECKSIG)
		pkScript, err := builder.Script()
		assert.Nil(t, err)
		tapLeaf = append(tapLeaf, txscript.NewBaseTapLeaf(pkScript))
	}

	// STEP 2: CALCULATE TWEAKED PUBLIC KEY Q
	// calculate tweak: create a taproot tree
	taptree := txscript.AssembleTaprootScriptTree(tapLeaf...)

	// get internal private key P
	_, internal_pair := s.NewHDKeyPairFromSeed(OMNIMAN_WALLET_SEED)

	// tr pub Q = P + t*G
	taptreeRootCommitment := taptree.RootNode.TapHash()
	fmt.Printf("Taproot tree: %s\n", hex.EncodeToString(taptreeRootCommitment[:]))

	q := txscript.ComputeTaprootOutputKey(internal_pair.Pub, taptreeRootCommitment[:])
	assert.NotNil(t, q)
	taproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(q), s.BtcdChainConfig)
	assert.Nil(t, err)
	fmt.Printf("Taproot address: %s\n", taproot.String())

	// STEP 3: CREATE WITNESS FOR EVALUATION
	// OP_1 to signify SegWit v1: Taproot
	p2trScript, err := txscript.
		NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(q)).
		Script()
	assert.Nil(t, err)

	// create control block
	// get inclusion proof of tapleaf at position 1
	inclusionProof := taptree.LeafMerkleProofs[1]
	controlBlock := inclusionProof.ToControlBlock(
		internal_pair.Pub,
	)
	controlBlockBytes, err := controlBlock.ToBytes()
	assert.Nil(t, err)

	// enable tracing to see how the script is executed
	backendLog := btclog.NewBackend(os.Stdout)
	testLog := backendLog.Logger("MAIN")
	testLog.SetLevel(btclog.LevelTrace)
	txscript.UseLogger(testLog)

	s.ValidateScript(p2trScript, 1, func(t *testing.T, prevOut *wire.TxOut, tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int) wire.TxWitness {
		// create aggregated nonces
		nonce_1, err := musig2.GenNonces(musig2.WithPublicKey(pair_1.Pub))
		assert.Nil(s.T, err)
		nonce_2, err := musig2.GenNonces(musig2.WithPublicKey(pair_3.Pub))
		assert.Nil(s.T, err)
		aggrNonces, err := musig2.AggregateNonces([][66]byte{nonce_1.PubNonce, nonce_2.PubNonce})
		assert.Nil(s.T, err)

		// construct MuSig2 aggregated signature
		// calculating sighash
		inputFetcher := txscript.NewCannedPrevOutputFetcher(
			prevOut.PkScript,
			prevOut.Value,
		)
		hType := txscript.SigHashDefault
		sigHash, err := txscript.CalcTapscriptSignaturehash(sigHashes, hType, tx, idx, inputFetcher, tapLeaf[1])
		assert.Nil(t, err)

		// generate partial signatures for each participant
		// sign already negates nonce with odd y - value
		// s1, R
		ps_1, err := musig2.Sign(nonce_1.SecNonce, pair_1.GetTestPriv(), aggrNonces, subset[1], ([32]byte)(sigHash))
		assert.Nil(t, err)
		// s2, R
		ps_2, err := musig2.Sign(nonce_2.SecNonce, pair_3.GetTestPriv(), aggrNonces, subset[1], ([32]byte)(sigHash))
		assert.Nil(t, err)

		// aggregate partial signatures
		// the combined nonce is in each partial signature R value
		schnorrSig := musig2.CombineSigs(ps_2.R, []*musig2.PartialSignature{ps_1, ps_2})
		schnorrSigBytes := schnorrSig.Serialize()
		if hType != txscript.SigHashDefault {
			schnorrSigBytes = append(schnorrSigBytes, byte(hType))
		}

		// basic check
		aggrPub, _, _, err := musig2.AggregateKeys(subset[1], false)
		assert.Nil(t, err)
		res := schnorrSig.Verify(sigHash[:], aggrPub.FinalKey)
		assert.True(t, res)

		witness := wire.TxWitness{
			schnorrSigBytes, tapLeaf[1].Script, controlBlockBytes,
		}
		return witness
	})
}

// setup musig2 channel between alice and bob
func constructMuSig2Channel(s *testhelper.TestSuite, pubPair []*btcec.PublicKey) (*btcec.PublicKey, []byte) {
	// STEP 1: construct MuSig2 aggregated public key
	// constructing an aggregate public key
	aggrPubKey, _, _, err := musig2.AggregateKeys(pubPair, false)
	assert.Nil(s.T, err)

	// STEP 2: CREATE WITNESS FOR EVALUATION
	// OP_1 to signify SegWit v1: Taproot
	p2trScript, err := txscript.
		NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(aggrPubKey.FinalKey)).
		Script()
	assert.Nil(s.T, err)

	return aggrPubKey.FinalKey, p2trScript
}
