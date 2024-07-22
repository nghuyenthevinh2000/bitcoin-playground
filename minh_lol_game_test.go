package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/assert"
)

// bet T1 vs GenG: T1 win, GenG win, draw
// win to get 100000, draw: transfer to dealer 50000
// go test -v -run TestMinhLolGame
func TestMinhLolGame(t *testing.T) {
	suite := TestSuite{}
	suite.setupSimNetSuite(t)

	// Alice, Bob wallet
	alice := suite.openWallet(t, ALICE_WALLET_SEED, "alice")
	bob := suite.openWallet(t, BOB_WALLET_SEED, "bob")

	// dealer
	dealer := suite.openWallet(t, OLIVIA_WALLET_SEED, "olivia")
	// suite.fundWallet(dealer, btcutil.Amount(10000000))

	// check balance
	aliceBalance, _ := alice.CalculateBalance(1)
	bobBalance, _ := bob.CalculateBalance(1)
	dealerBalance, err := dealer.CalculateBalance(1)
	assert.Nil(t, err)

	t.Logf("aliceBalance: %d", aliceBalance)
	t.Logf("bobBalance: %d", bobBalance)
	t.Logf("dealerBalance: %d", dealerBalance)

	// priv key
	aliceWifPriv := suite.exportWIFPriv(alice)
	bobWifPriv := suite.exportWIFPriv(bob)
	dealerWifPriv := suite.exportWIFPriv(dealer)

	t.Logf("aliceWifPriv: %s", aliceWifPriv)
	t.Logf("bobWifPriv: %s", bobWifPriv)
	t.Logf("dealerWifPriv: %s", dealerWifPriv)

	// pubkey
	alicePk := aliceWifPriv.SerializePubKey()
	bobPk := bobWifPriv.SerializePubKey()
	dealerPk := dealerWifPriv.SerializePubKey()

	// build script
	lolGameScript := suite.buildWitnessScriptLolGame(alicePk, bobPk, dealerPk)
	t.Logf("lolGameScript: %x", lolGameScript)

	// create a P2WSH address
	lolGameScriptHash := sha256.Sum256(lolGameScript)
	address, err := btcutil.NewAddressWitnessScriptHash(lolGameScriptHash[:], suite.btcdChainConfig)
	assert.Nil(t, err)
	t.Logf("P2WSH contract address: %s", address.EncodeAddress())

	// witness script funding transaction
	commitHash, _ := suite.walletClient.SendToAddress(address, btcutil.Amount(546))
	time.Sleep(3 * time.Second)
	suite.generateBlocks(1)
	rawCommitTx, _ := suite.chainClient.GetRawTransaction(commitHash)
	t.Logf("Commitment tx: %+v", rawCommitTx.MsgTx())

	// dealer address wallet
	dealerAddr, _ := dealer.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	t.Logf("dealerAddr: %s", dealerAddr.EncodeAddress())

	// chose utxo
	dealerUtxos, _ := suite.chainClient.ListUnspentMinMaxAddresses(1, 9999999, []btcutil.Address{dealerAddr})
	t.Logf("dealerUtxos: %d", len(dealerUtxos))
	// Filter UTXOs with amount > 130000 sat, 100000 for bet, 30000 for fee
	var chosenUtxo btcjson.ListUnspentResult
	for _, utxo := range dealerUtxos {
		if utxo.Amount > 130000.0 {
			chosenUtxo = utxo
			fmt.Printf("TxID: %s, Vout: %d, Amount: %f BTC, Confirmations: %d\n",
				chosenUtxo.TxID, chosenUtxo.Vout, chosenUtxo.Amount, chosenUtxo.Confirmations)
			break
		}
	}

	// Create a new empty PSBT
	tx := wire.NewMsgTx(2)
	psbtLolGame, _ := psbt.NewFromUnsignedTx(tx)

	// Input
	psbtLolGame.UnsignedTx.AddTxIn(
		&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *rawCommitTx.Hash(),
				Index: 0,
			},
		},
	)
	hash, _ := chainhash.NewHashFromStr(chosenUtxo.TxID)
	psbtLolGame.UnsignedTx.AddTxIn(
		&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: chosenUtxo.Vout,
			},
		},
	)

	// Output
	psbtLolGame.UnsignedTx.AddTxOut(
		wire.NewTxOut(1e3, alicePk),
	)

	// constructing witness field
	prevTxOut := rawCommitTx.MsgTx().TxOut[0]
	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		prevTxOut.PkScript,
		prevTxOut.Value,
	)

	sigHashes := txscript.NewTxSigHashes(tx, inputFetcher)
	sig, err := txscript.RawTxInWitnessSignature(tx, sigHashes, 0, prevTxOut.Value, lolGameScript, txscript.SigHashSingle, aliceWifPriv.PrivKey)
	assert.Nil(t, err)

	// TODO: test with GenG win, draw
	witness := wire.TxWitness{
		sig, alicePk, []byte("T1 win"), lolGameScript,
	}
	tx.TxIn[0].Witness = witness

	// Sign the PSBT
	sigScript, err := txscript.SignatureScript(psbtLolGame.UnsignedTx, 1, psbtLolGame.UnsignedTx.TxIn[0].SignatureScript, txscript.SigHashAll, aliceWifPriv.PrivKey, true)
	if err != nil {
		t.Logf("error creating signature script: %v", err)
	}
	psbtLolGame.Inputs[1].FinalScriptSig = sigScript

	// Finalize the PSBT
	if err := psbt.MaybeFinalizeAll(psbtLolGame); err != nil {
		t.Logf("error finalizing PSBT: %v", err)
	}

	// Send Raw transaction
	finalTx := psbtLolGame.UnsignedTx
	txHash, err := suite.chainClient.SendRawTransaction(finalTx, false)
	if err != nil {
		log.Fatalf("error sending transaction: %v", err)
	}
	fmt.Printf("Transaction broadcasted successfully! TXID: %s\n", txHash.String())

	// generate a block to confirm the transaction
	time.Sleep(3 * time.Second)
	suite.generateBlocks(1)

	// check the balance of alice
	time.Sleep(3 * time.Second)
	aliceBalance, _ = alice.CalculateBalance(1)
	assert.Nil(t, err)
	t.Logf("Alice balance: %d", aliceBalance)
}

func (s *TestSuite) buildWitnessScriptLolGame(alicePk []byte, bobPk []byte, dealerPk []byte) []byte {
	betT1Hash := sha256.Sum256([]byte("T1 win"))
	fmt.Printf("betT1Hash: %x\n", betT1Hash)
	betGenGHash := sha256.Sum256([]byte("GenG win"))
	fmt.Printf("betGenGHash: %x\n", betGenGHash)
	drawHash := sha256.Sum256([]byte("draw"))
	fmt.Printf("drawHash: %x\n", drawHash)

	script := txscript.NewScriptBuilder()

	// check if T1 win
	script.AddOp(txscript.OP_SHA256)
	script.AddOp(txscript.OP_DUP) // duplicate bet hash
	script.AddData(betT1Hash[:])
	script.AddOp(txscript.OP_EQUAL)
	script.AddOp(txscript.OP_IF)
	script.AddOp(txscript.OP_DROP) // drop bet hash
	script.AddData(alicePk)
	script.AddOp(txscript.OP_SHA256)
	script.AddOp(txscript.OP_EQUALVERIFY)

	// check if GenG win
	script.AddOp(txscript.OP_ELSE)
	script.AddOp(txscript.OP_DUP)
	script.AddData(betGenGHash[:])
	script.AddOp(txscript.OP_EQUAL)
	script.AddOp(txscript.OP_IF)
	script.AddOp(txscript.OP_DROP)
	script.AddData(bobPk)
	script.AddOp(txscript.OP_SHA256)
	script.AddOp(txscript.OP_EQUALVERIFY)

	// check if draw
	script.AddOp(txscript.OP_ELSE)
	script.AddOp(txscript.OP_DUP)
	script.AddData(drawHash[:])
	script.AddOp(txscript.OP_EQUAL)
	script.AddOp(txscript.OP_DROP)
	script.AddData(dealerPk)
	script.AddOp(txscript.OP_SHA256)
	script.AddOp(txscript.OP_EQUALVERIFY)

	// check sig
	script.AddOp(txscript.OP_ENDIF)
	script.AddOp(txscript.OP_ENDIF)
	script.AddOp(txscript.OP_CHECKSIG)

	pkScript, err := script.Script()
	assert.Nil(s.t, err)

	return pkScript
}

// Create a Bech32 address from a P2WSH script for Simnet
func createP2WSHAddress(script []byte) (string, error) {
	// Hash the script using SHA-256
	sha256Hash := sha256.Sum256(script)
	witnessScriptHash := sha256Hash[:]

	// Create the SegWit program
	version := byte(0x00)
	segwitProgram := append([]byte{version, byte(len(witnessScriptHash))}, witnessScriptHash...)

	// Encode the SegWit program in Bech32 format
	hrp := "sb" // hrp for Simnet
	witnessProg, err := bech32.ConvertBits(segwitProgram, 8, 5, true)
	if err != nil {
		return "", err
	}
	address, err := bech32.Encode(hrp, witnessProg)
	if err != nil {
		return "", err
	}

	return address, nil
}
