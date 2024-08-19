package main

import (
	"crypto/sha256"
	"log"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// go test -v -run ^TestBallGameContract$ github.com/nghuyenthevinh2000/bitcoin-playground
// the test is highly flaky, probably due to the fact that different processes are not synced.
// first run will always fail
// second run will always pass, but amount of alice is not updated
// third run will always fail, but amount of alice is updated
func TestBallGameContract(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupSimNetSuite(t, log.Default())

	// Alice, Bob wallet
	alice := suite.OpenWallet(t, ALICE_WALLET_SEED, "alice")
	bob := suite.OpenWallet(t, BOB_WALLET_SEED, "bob")

	// fund wallet if less than 0.1 BTC
	amt, err := alice.CalculateBalance(1)
	assert.Nil(t, err)
	if amt < btcutil.Amount(10000000) {
		suite.FundWallet(alice, btcutil.Amount(10000000))
	}

	amt, err = bob.CalculateBalance(1)
	assert.Nil(t, err)
	if amt < btcutil.Amount(10000000) {
		suite.FundWallet(bob, btcutil.Amount(10000000))
	}

	// alice initial balance
	amt, err = alice.CalculateBalance(1)
	assert.Nil(t, err)
	t.Logf("Alice balance: %d", amt)

	// Alice bets that VN wins
	// Bob bets that TL wins
	aliceWif := suite.ExportWIFPriv(alice)
	bobWif := suite.ExportWIFPriv(bob)
	witnessScriptCommitment, ballGameWitnessScript := buildBallGameWitnessScript(&suite, aliceWif, bobWif)

	// create a P2WSH address
	address, err := btcutil.NewAddressWitnessScriptHash(witnessScriptCommitment[:], suite.BtcdChainConfig)
	assert.Nil(t, err)
	t.Logf("P2SH address: %s", address.EncodeAddress())

	// witness script funding transaction
	commitHash, err := suite.WalletClient.SendToAddress(address, btcutil.Amount(10000000))
	assert.Nil(t, err)

	// generate a block to confirm the transaction
	time.Sleep(3 * time.Second)
	suite.GenerateBlocks(1)

	// settle the bet through unlocking that witness script
	// if alice includes vn hash, then she can withdraw the funds
	// if bob includes tl hash, then he can withdraw the funds
	rawCommitTx, err := suite.ChainClient.GetRawTransaction(commitHash)
	assert.Nil(t, err)

	t.Logf("Commitment tx: %+v", rawCommitTx.MsgTx())

	// create a new spending psbt
	aliceSpendPubScript := buildSpendingPsbt(&suite, aliceWif)
	prevTxOut := rawCommitTx.MsgTx().TxOut[0]

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *rawCommitTx.Hash(),
			Index: 0,
		},
	})
	txOut := wire.NewTxOut(1e3, aliceSpendPubScript)
	tx.AddTxOut(txOut)

	// constructing witness field
	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		prevTxOut.PkScript,
		prevTxOut.Value,
	)
	// BIP0143 outlines a new hashing algorithm for the signature verification process
	// read more in knowledge/BIP0143.md
	// signing the transaction
	sigHashes := txscript.NewTxSigHashes(tx, inputFetcher)
	sig, err := txscript.RawTxInWitnessSignature(tx, sigHashes, 0, prevTxOut.Value, ballGameWitnessScript, txscript.SigHashSingle, aliceWif.PrivKey)
	assert.Nil(t, err)

	// add witness information to prove that alice has won the bet
	witness := wire.TxWitness{
		sig, aliceWif.SerializePubKey(), []byte("VN wins"), ballGameWitnessScript,
	}
	tx.TxIn[0].Witness = witness

	// check that this tx in is valid before sending
	blockUtxos := blockchain.NewUtxoViewpoint()
	sigCache := txscript.NewSigCache(50000)
	hashCache := txscript.NewHashCache(50000)

	blockUtxos.AddTxOut(btcutil.NewTx(rawCommitTx.MsgTx()), 0, 1)
	hashCache.AddSigHashes(tx, inputFetcher)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(t, err)

	// send the raw transaction
	_, err = suite.WalletClient.SendRawTransaction(tx, false)
	assert.Nil(t, err)

	// generate a block to confirm the transaction
	time.Sleep(3 * time.Second)
	suite.GenerateBlocks(1)

	// check the balance of alice
	time.Sleep(3 * time.Second)
	amt, err = alice.CalculateBalance(1)
	assert.Nil(t, err)
	t.Logf("Alice balance: %d", amt)

	// test that after alice amount is higher than previous alice amount
}

func buildBallGameWitnessScript(s *testhelper.TestSuite, aliceKey *btcutil.WIF, bobKey *btcutil.WIF) ([32]byte, []byte) {

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
	assert.Nil(s.T, err)

	witnessScriptCommitment := sha256.Sum256(pkScript)

	return witnessScriptCommitment, pkScript
}

func buildSpendingPsbt(s *testhelper.TestSuite, wif *btcutil.WIF) []byte {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(wif.SerializePubKey()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	pkScript, err := builder.Script()
	assert.Nil(s.T, err)

	return pkScript
}
