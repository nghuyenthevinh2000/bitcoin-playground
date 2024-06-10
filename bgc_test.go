package main

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
)

func (s *TestSuite) buildBallGameWitnessScript(aliceKey *btcutil.WIF, bobKey *btcutil.WIF) ([32]byte, []byte) {

	// result hash of the game between VN and TL
	vn := sha256.Sum256([]byte("VN wins"))
	tl := sha256.Sum256([]byte("TL wins"))

	// Alice bets that VN wins
	// Bob bets that TL wins
	builder := txscript.NewScriptBuilder()

	// INPUT:
	// | "TL wins" |
	// | alice key |
	// | signature |
	// check if INPUT is equal to vn hash
	// result
	// | OP_EQUAL result (0x0)   |
	// | OP_SHA256 ("TL wins")   |
	builder.AddOp(txscript.OP_SHA256)
	builder.AddOp(txscript.OP_DUP)
	builder.AddData(vn[:])
	builder.AddOp(txscript.OP_EQUAL)

	// evaluate if "OP_EQUAL result" is 0x01
	builder.AddOp(txscript.OP_IF)
	// drop value OP_SHA256 ("VN wins") since there is no need to check it in the next else
	builder.AddOp(txscript.OP_DROP)
	// duplicate alice key, one for checking pubkey hash and one for signature
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(aliceKey.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)

	// evaluate if "OP_EQUAL result" is 0x00
	builder.AddOp(txscript.OP_ELSE)

	// compare value to sha256("TL wins") and then remove both
	builder.AddData(tl[:])
	builder.AddOp(txscript.OP_EQUALVERIFY)

	// duplicate bob key, one for checking pubkey hash and one for signature
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(bobKey.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)

	// end if and check signature
	builder.AddOp(txscript.OP_ENDIF)
	builder.AddOp(txscript.OP_CHECKSIG)
	pkScript, err := builder.Script()
	assert.Nil(s.t, err)

	witnessScriptCommitment := sha256.Sum256(pkScript)

	return witnessScriptCommitment, pkScript
}

func (s *TestSuite) buildSpendingPsbt(wif *btcutil.WIF) []byte {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(wif.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	pkScript, err := builder.Script()
	assert.Nil(s.t, err)

	return pkScript
}
