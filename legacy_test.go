package main

import (
	"encoding/hex"
	"log"
	"reflect"
	"testing"
	"time"

	btcec "github.com/btcsuite/btcd/btcec/v2"
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

/*
## P2MS transaction (maximum of 3 public keys)

### Pubkey script:

524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae

OP_2 (0x52)
OP_PUSHBYTES_65 (0x41)
04d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a2 (pubkey)
OP_PUSHBYTES_65 (0x41)
04ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb1 (pubkey)
OP_PUSHBYTES_65 (0x41)
04b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e7 (pubkey)
OP_3 (0x53)
OP_CHECKMULTISIG (0xae)

### Signature script:

00483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801

OP_0 (0x00) -> Bug in the script
OP_PUSHBYTES_72 (0x48)
3045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601 (signature)
OP_PUSHBYTES_72 (0x48)
3045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801 (signature)

### Signature script:

48 - 3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a772401 -
21 -
03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31

OP_PUSHBYTES_72 (0x48)
3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a772401 (signature)
OP_PUSHBYTES_33 (0x21)
03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31 (pubkey)
*/
// go test -v -run TestSendTxWithP2MS -count 1
func TestSendTxWithP2MS(t *testing.T) {
	t.Skip("Skip this test because it's not implemented yet")
}

/*

## P2SH transaction

### Pubkey script:

a914748284390f9e263a4b766a75d0633c50426eb87587

OP_HASH160 (0xa9)
OP_PUSHBYTES_20 (0x14)
748284390f9e263a4b766a75d0633c50426eb875 (hash160(script))
OP_EQUAL (0x87)


### Signature script:

00473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae

OP_0 (0x00)
OP_PUSHBYTES_71 (0x47)
3044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401 (signature)
OP_PUSHBYTES_71 (0x47)
5121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae (script) ->

>>>  Script hash <<<<
>>>

51-21-022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c-052-ae

>>> OP_1: 0x51
>>> OP_PUSHBYTES_33: 0x21
>>> 022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e (pubkey)
>>> OP_PUSHBYTES_33: 0x21
>>> 03a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c0 (pubkey)
>>> OP_2: 0x52
>>> OP_CHECKMULTISIG: 0xae
*/
// go test -v -run TestSendTxWithP2SH -count 1
func TestSendTxWithP2SH(t *testing.T) {
	// Setup test suite
	suite := testhelper.TestSuite{}
	suite.SetupSimNetSuite(t, log.Default())

	// Open wallets
	davidWallet := suite.OpenWallet(t, DAVID_WALLET_SEED, "david")
	davidAddress, err := davidWallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(t, err)
	davidPrivKey, err := davidWallet.PrivKeyForAddress(davidAddress)
	assert.Nil(t, err)
	davidPubKey, err := davidWallet.PubKeyForAddress(davidAddress)
	assert.Nil(t, err)
	covertedDavidPubKey, err := btcutil.NewAddressPubKey(davidPubKey.SerializeCompressed(), suite.BtcdChainConfig)
	assert.Nil(t, err)
	davidBalance, err := davidWallet.CalculateBalance(1)
	assert.Nil(t, err)

	bobWallet := suite.OpenWallet(t, BOB_WALLET_SEED, "bob")
	bobAddress, err := bobWallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(t, err)
	bobPrivKey, err := bobWallet.PrivKeyForAddress(bobAddress)
	assert.Nil(t, err)
	bobPubKey, err := bobWallet.PubKeyForAddress(bobAddress)
	assert.Nil(t, err)
	covertedBobPubKey, err := btcutil.NewAddressPubKey(bobPubKey.SerializeCompressed(), suite.BtcdChainConfig)
	assert.Nil(t, err)
	bobBalance, err := bobWallet.CalculateBalance(1)
	assert.Nil(t, err)

	t.Log(">> David pubkey: ", hex.EncodeToString(davidPubKey.SerializeCompressed()))
	t.Log(">> Bob pubkey: ", hex.EncodeToString(bobPubKey.SerializeCompressed()))

	t.Log(">> Before >> David balance: ", davidBalance)
	t.Log(">> Before >> Bob balance: ", bobBalance)

	// // Create a 1-of-2 multisig script
	multisigScript, err := txscript.MultiSigScript([]*btcutil.AddressPubKey{
		covertedDavidPubKey,
		covertedBobPubKey,
	}, 1)

	assert.Nil(t, err)

	t.Log(">> Multisig script: ", hex.EncodeToString(multisigScript))

	_ = bobPrivKey
	_ = davidPrivKey

	p2shAddress, err := btcutil.NewAddressScriptHash(multisigScript, suite.BtcdChainConfig) // -> hash160(script)
	assert.Nil(t, err)

	// 37F3LW6dMrveNTixkqLmjm7H5tLQtmRvL2
	// ri2h7ocncQgmcFWeqSmao8W2KeehsMopBr

	amount := 4e6
	// Fund the P2SH address
	txHash, err := suite.WalletClient.SendToAddress(p2shAddress, btcutil.Amount(amount))
	assert.Nil(t, err)

	t.Log(">> P2SH address: ", p2shAddress.EncodeAddress())
	t.Log(">> Hash160: ", hex.EncodeToString(p2shAddress.ScriptAddress()))

	// Generate a block to confirm the transaction
	suite.GenerateBlocks(1)
	time.Sleep(5 * time.Second)

	rawTx, err := suite.WalletClient.GetRawTransaction(txHash)
	assert.Nil(t, err)

	t.Log(">> Funded transaction: ", rawTx.MsgTx().TxHash())

	// NOTES: *rawTx.Hash() and rawTx.MsgTx().TxHash() are the same but these are little endian format and big endian format

	// prevTxOut := rawTx.MsgTx().TxOut[0]

	var prevTxOut *wire.TxOut
	var index int

	for i, txOut := range rawTx.MsgTx().TxOut {
		if txOut.Value == int64(amount) {
			script := txOut.PkScript
			if len(script) == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 &&
				reflect.DeepEqual(script[2:2+20], p2shAddress.ScriptAddress()) {
				t.Logf(">> Found the P2SH output at index %d", i)
				prevTxOut = txOut
				index = i
				break
			}
		}
	}

	assert.NotNil(t, prevTxOut)

	tx := wire.NewMsgTx(wire.TxVersion)

	// Add input
	txIn := wire.NewTxIn(&wire.OutPoint{
		Hash:  *rawTx.Hash(),
		Index: uint32(index),
	}, nil, nil)

	tx.AddTxIn(txIn)

	davidPkScript, err := txscript.PayToAddrScript(davidAddress)
	assert.Nil(t, err)

	// // Add output
	txOut := wire.NewTxOut(prevTxOut.Value-1e5, davidPkScript) // -> output will be sent to David
	tx.AddTxOut(txOut)

	lookupKey := func(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
		return davidPrivKey, true, nil
		// t.Log(">> Address: ", addr.EncodeAddress())

		// // Return the private key for the P2SH address participants
		// if addr.EncodeAddress() == covertedDavidPubKey.EncodeAddress() {
		// 	fmt.Println(">> David private key")
		// } else if addr.EncodeAddress() == covertedBobPubKey.EncodeAddress() {
		// 	fmt.Println(">> Bob private key")
		// 	return bobPrivKey, true, nil
		// }
		// return nil, false, fmt.Errorf("unexpected address %s", addr.EncodeAddress())
	}

	lookupScript := func(addr btcutil.Address) ([]byte, error) {
		return multisigScript, nil
	}

	/// Sign transaction for unlocking the P2SH output
	sigScript, err := txscript.SignTxOutput(suite.BtcdChainConfig, tx, 0, prevTxOut.PkScript, txscript.SigHashAll, txscript.KeyClosure(lookupKey), txscript.ScriptClosure(lookupScript), multisigScript)
	assert.Nil(t, err)

	tx.TxIn[0].SignatureScript = sigScript

	t.Log(">> Signature script: ", hex.EncodeToString(sigScript))

	// Broadcast the transaction
	txHash, err = suite.WalletClient.SendRawTransaction(tx, true)
	assert.Nil(t, err)

	t.Logf(">> Transaction Broadcasted: %s", txHash.String())

	time.Sleep(5 * time.Second)
	// Verify the transaction
	suite.GenerateBlocks(2)
	time.Sleep(5 * time.Second)

	davidBalanceAfter, err := davidWallet.CalculateBalance(1)
	assert.Nil(t, err)

	t.Log(">> After >> David balance: ", davidBalanceAfter)
}
