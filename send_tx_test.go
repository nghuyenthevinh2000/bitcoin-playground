package main

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/assert"
)

// P2PKH:
// Script Pubkey: 76a91434bea36dc7fcccb2e5161ce0c7f557a69af0daad88ac
// Script Pubkey:
// 76: OP_DUP
// a9: OP_HASH160
// 14: OP_PUSHBYTES_20
// 34bea36dc7fcccb2e5161ce0c7f557a69af0daad
// 88: OP_EQUALVERIFY
// ac: OP_CHECKSIG

// ScriptSig:
// OP_PUSHBYTES_72
// <signature>
// OP_PUSHBYTES_33
// <pubkey>

// 48
// <signature>
// 21
// <pubkey>

// // current:
// 47
// 3044022059996c972fce5a5409a26d4f365344f026a5516902a908da9ecd322ee62a1270022015df8dd89dbbe9ce2ccfe363b939400cc2002fe6bc1a80de059faa6b1909e31401
// 21
// 031ee0b29099a6d093c204be231d5be0766f88b47bba071a9688c2e76dd644ea7c

// go test -v -run ^TestSendTx$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestSendTx(t *testing.T) {
	suite := TestSuite{}
	suite.setupSimNetSuite(t)

	// Alice, Bob wallet
	alice := suite.openWallet(t, ALICE_WALLET_SEED, "alice")
	bob := suite.openWallet(t, BOB_WALLET_SEED, "bob")

	// Ensure we derive the same address each time
	aliceCurrentAddress, err := alice.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(t, err)
	alicePrivKey, err := alice.PrivKeyForAddress(aliceCurrentAddress)
	assert.Nil(t, err)
	alicePubKey, err := alice.PubKeyForAddress(aliceCurrentAddress)
	assert.Nil(t, err)
	alicePubKeyCompressed := alicePubKey.SerializeCompressed()

	bodAddress, err := bob.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(t, err)

	utxo := getValidUtxo(t, &suite, alice, alicePubKeyCompressed, 0.7)
	assert.NotNil(t, utxo)

	t.Log("UTXO: ", utxo)

	// alice initial balance
	aliceAmount, err := alice.CalculateBalance(1)
	assert.Nil(t, err)
	t.Logf("Alice balance: %d", aliceAmount)

	// bob initial balance
	bobAmount, err := bob.CalculateBalance(1)
	assert.Nil(t, err)
	t.Logf("Bob balance: %d", bobAmount)

	tx := wire.NewMsgTx(wire.TxVersion)

	// Add an input
	utxoHash, err := chainhash.NewHashFromStr(utxo.TxID)
	assert.Nil(t, err)

	subscript, err := hex.DecodeString(utxo.ScriptPubKey)
	assert.Nil(t, err)

	// unlocking script
	sigScript, err := txscript.SignatureScript(tx, 0, subscript, txscript.SigHashAll, alicePrivKey, true)
	assert.Nil(t, err)

	outpoint := wire.NewOutPoint(utxoHash, utxo.Vout)
	txIn := wire.NewTxIn(outpoint, sigScript, nil)

	tx.AddTxIn(txIn)

	// Add an output
	scriptPubKey, err := txscript.PayToAddrScript(bodAddress)
	assert.Nil(t, err)

	txOut := wire.NewTxOut(1e3, scriptPubKey)
	tx.AddTxOut(txOut)

	t.Logf("ScriptSig: %s", hex.EncodeToString(sigScript))

	// // ScriptSig:

	// // 	OP_PUSHBYTES_72
	// 3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a772401
	// // OP_PUSHBYTES_33
	// // 03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31
	// // ScriptSig:
	// // 47: OP_DATA_0x47

	time.Sleep(5 * time.Second)

	// // send the raw transaction
	_, err = alice.ChainClient().SendRawTransaction(tx, false)
	assert.Nil(t, err)

	// // t.Logf("Transaction sent: %s", txHash.String())
}

func getValidUtxo(t *testing.T, suite *TestSuite, w *wallet.Wallet, compressedPublicKey []byte, threshold float64) *btcjson.ListUnspentResult {

	// FIXME: Dont know why all the utxos have the sciptPubKey not equal to the compressed public key,
	// So I try to fund the new utxo with the compressed public key
	suite.fundWallet(w, btcutil.Amount(1e8*threshold))

	accountName, err := w.AccountName(waddrmgr.KeyScopeBIP0044, 0)
	if err != nil {
		t.Fatal("Failed to get account name")
	}

	hash160PubKey := btcutil.Hash160(compressedPublicKey)
	t.Logf("hash160PubKey: %s", hex.EncodeToString(hash160PubKey))

	utxos, err := w.ListUnspent(1, 9999999, accountName)
	if err != nil {
		t.Fatal("Failed to list unspent")
	}

	for i, utxo := range utxos {
		pubKeyHash, err := ExtractPubKeyHash(utxo.ScriptPubKey)
		assert.Nil(t, err)

		if string(pubKeyHash) == string(hash160PubKey) {
			t.Logf("Match found in UTXO[%d]: %s", i, utxo.ScriptPubKey)
			return utxos[i]
		} else {
			t.Logf("No match in UTXO[%d]: %s", i, utxo.ScriptPubKey)
		}
	}

	return nil
}

func ExtractPubKeyHash(scriptPubKey string) ([]byte, error) {
	decoded, err := hex.DecodeString(scriptPubKey)
	if err != nil {
		return nil, err
	}
	// Typically scriptPubKey for P2PKH starts with 0x76 0xa9 0x14, and ends with 0x88 0xac
	if len(decoded) != 25 || decoded[0] != 0x76 || decoded[1] != 0xa9 || decoded[23] != 0x88 || decoded[24] != 0xac {
		return nil, fmt.Errorf("unexpected scriptPubKey format")
	}
	return decoded[2:22], nil
}
