package main

import (
	"encoding/hex"
	"log"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

const (
	DAVID_WALLET_SEED = "4298b991629070190fc541d046c6fd7cd290eab9630df52149b7ccc43da26007"
	DAVID_WALLET_NAME = "david"
)

/*
## P2PKH transaction

### Pubkey script:

76a91455ae51684c43435da751ac8d2173b2652eb6410588ac

OP_DUP (0x76)
OP_HASH160 (0xa9)
OP_PUSHBYTES_20 (0x14)
55ae51684c43435da751ac8d2173b2652eb64105 (hash160(pubkey))
OP_EQUALVERIFY (0x88)
OP_CHECKSIG (0xac)

### Signature script:

48 - 3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a772401 -
21 -
03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31

OP_PUSHBYTES_72 (0x48)
3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a772401 (signature)
OP_PUSHBYTES_33 (0x21)
03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31 (pubkey)
*/
func TestSendTxWithLegacyWallet(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupSimNetSuite(t, log.Default())

	// open from wallet
	fromWallet := suite.OpenWallet(t, DAVID_WALLET_SEED, DAVID_WALLET_NAME)
	fromAddress, err := fromWallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(t, err)
	fromPrivKey, err := fromWallet.PrivKeyForAddress(fromAddress)
	assert.Nil(t, err)
	fromPubKey, err := fromWallet.PubKeyForAddress(fromAddress)
	assert.Nil(t, err)
	fromName, err := fromWallet.AccountName(waddrmgr.KeyScopeBIP0044, 0)
	assert.Nil(t, err)
	compressedPubKey := fromPubKey.SerializeCompressed()

	_, err = suite.WalletClient.SendToAddress(fromAddress, btcutil.Amount(1e7))
	assert.Nil(t, err)

	// generate a block to confirm the transaction
	suite.GenerateBlocks(1)
	time.Sleep(5 * time.Second)

	utxos, err := fromWallet.ListUnspent(1, 9999999, fromName)
	assert.Nil(t, err)

	// FIXME: because the public key was changed every funding, so we need to re-fund and get the fist utxo
	choosenUtxo := utxos[0]
	assert.Equal(t, hex.EncodeToString(btcutil.Hash160(compressedPubKey)), choosenUtxo.ScriptPubKey[6:6+40])

	fromBalance, err := fromWallet.CalculateBalance(1)
	assert.Nil(t, err)

	t.Log("Before >> From balance: ", fromBalance)

	// open to wallet
	toWallet := suite.OpenWallet(t, BOB_WALLET_SEED, "bob2")
	toAddress, err := toWallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(t, err)
	toPubKey, err := toWallet.PubKeyForAddress(toAddress)
	assert.Nil(t, err)

	assert.Nil(t, err)
	toBalance, err := toWallet.CalculateBalance(1)
	assert.Nil(t, err)

	t.Log("Before >> To balance: ", toBalance)

	pubKeyScript, err := txscript.PayToAddrScript(toAddress)
	assert.Nil(t, err)

	hash160 := btcutil.Hash160(toPubKey.SerializeCompressed())
	t.Log(">> To script address: ", hex.EncodeToString(toAddress.ScriptAddress()))
	t.Log(">> To hash160: ", hex.EncodeToString(hash160))
	t.Log(">> To script: ", hex.EncodeToString(pubKeyScript))
	t.Log(">> To pubkey: ", hex.EncodeToString(toPubKey.SerializeCompressed()))

	// create transaction
	tx := wire.NewMsgTx(wire.TxVersion)

	utxoChainHash, err := chainhash.NewHashFromStr(choosenUtxo.TxID)
	assert.Nil(t, err)

	// add input
	txIn := wire.NewTxIn(&wire.OutPoint{
		Hash:  *utxoChainHash,
		Index: choosenUtxo.Vout,
	}, nil, nil)

	tx.AddTxIn(txIn)

	amount := int64(choosenUtxo.Amount*1e8 - 1e5)
	t.Log(">> Amount: ", amount)

	// add output
	txOut := wire.NewTxOut(amount, pubKeyScript)
	tx.AddTxOut(txOut)

	scriptPubKey, err := hex.DecodeString(choosenUtxo.ScriptPubKey)
	assert.Nil(t, err)

	// sign transaction
	sigScript, err := txscript.SignatureScript(tx, 0, scriptPubKey, txscript.SigHashAll, fromPrivKey, true)
	assert.Nil(t, err)

	tx.TxIn[0].SignatureScript = sigScript

	// broadcast transaction
	txHash, err := suite.WalletClient.SendRawTransaction(tx, false)
	assert.Nil(t, err)

	// generate a block to confirm the transaction
	time.Sleep(5 * time.Second)
	suite.GenerateBlocks(2)

	// check balance
	time.Sleep(5 * time.Second)

	fromBalanceAfter, err := fromWallet.CalculateBalance(1)
	assert.Nil(t, err)

	toBalanceAfter, err := toWallet.CalculateBalance(1)
	assert.Nil(t, err)

	t.Log("After >> From balance: ", fromBalanceAfter)
	t.Log("After >> To balance: ", toBalanceAfter)
	t.Log("Transaction hash: ", txHash)

	toBalanceBig := toBalance.ToUnit(btcutil.AmountSatoshi)
	toBalanceAfterBig := toBalanceAfter.ToUnit(btcutil.AmountSatoshi)
	diff := float64(amount)

	t.Logf("To balance: %f, To balance after: %f", toBalanceBig, toBalanceAfterBig)
	t.Logf("Diff: %f", diff)
	assert.Equal(t, toBalanceBig+diff, toBalanceAfterBig, "To balance should be increased by amount")
}
