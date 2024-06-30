package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
)

const (
	maxProtocolVersion = 70002
)

type ExecTx struct {
	aliceExecTx *wire.MsgTx
	bobExecTx   *wire.MsgTx
	aliceScript []byte
	bobScript   []byte
}

type Contract struct {
	txs []ExecTx
	R   KeyPair
}

// go test -v -run ^TestDLCChannel$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestDLC(t *testing.T) {
	suite := TestSuite{}
	suite.setupSimNetSuite(t)

	_, alicePair := suite.newKeyPair(ALICE_WALLET_SEED)   // alice key pair
	_, bobPair := suite.newKeyPair(BOB_WALLET_SEED)       // bob key pair
	_, oliviaPair := suite.newKeyPair(OLIVIA_WALLET_SEED) // olivia key pair

	// Situation:
	// On the occasion of Lunar New Year, boss Alice wants to congratulate hard-working employee Bob by giving him lucky money
	// But she wanted to increase the chance of the game, so she made up the rules, she calls random oracle to get a random number from 1, 2 and 3
	// - if random number is 1, Bob will get 0.1BTC
	// - if random number is 2, Bob will get 0,05BTC
	// - if random number is 3, Bob will get 0.0333BTC
	// To do that Alice created a DLC with the participation of 3 parties - Alice(boss), Bob(employee), Olivia(random oracle)
	amount := int64(10000000) // 0.1 BTC

	// First, Alice prepares a transaction depoist 0.1BTC to the MuSig address
	// Only require know about Bob pubkey, Alice will not broadcast this tx now but save it for later use
	fundTx, err := buildFundTx(alicePair, bobPair, amount)
	assert.Nil(suite.t, err)

	lockTime := uint32(10) // 10 Bitcoin's blocks
	// Alice prepares a refund transaction, which will allow her to spend BTC from her previous funding
	// into her wallet after delay time
	// This will avoid BTC being locked in the MuSig address when some problem occurs
	refundTx, err := buildRefundTx(fundTx, alicePair, bobPair, amount, lockTime)

	// validate refund BTC from fundTx to Alice wallet
	err = validateTransactions(fundTx, refundTx)
	assert.Nil(suite.t, err)

	deals := [][]byte{
		[]byte("1"), []byte("2"), []byte("3"),
	}
	// Cause, there are 3 possible cases with random numbers, Alice and Bob will build 3 pairs executionTx off-chain
	// and after the oracle reveals the random number, they will select valid transactions from those tx to broadcast to the blockchain
	contract, err := buildContract(suite, fundTx, deals, alicePair, bobPair, oliviaPair, amount)
	// validate all tx in contract
	for _, execTx := range contract.txs {
		// validate Alice tx
		err = validateTransactions(fundTx, execTx.aliceExecTx)
		assert.Nil(suite.t, err)

		// validate Bob tx
		err = validateTransactions(fundTx, execTx.bobExecTx)
		assert.Nil(suite.t, err)
	}

	// Suppose that random number is "2"
	randomIdx := 1
	sign := Sign(oliviaPair.priv, contract.R.priv, deals[randomIdx])

	// Either Alice or Bob can broadcast their executionTx and start building closeTx to withdraw BTC
	// Alice
	privAlice := genAddSigToPrivkey(alicePair.priv, sign)
	closeTx, err := buildCloseTx(contract.txs[randomIdx].aliceExecTx, contract.txs[randomIdx].aliceScript, alicePair.pub, privAlice)
	// validate Alice close tx
	err = validateTransactions(contract.txs[randomIdx].aliceExecTx, closeTx)
	assert.Nil(suite.t, err)

	// Bob
	privBob := genAddSigToPrivkey(bobPair.priv, sign)
	closeTx, err = buildCloseTx(contract.txs[randomIdx].bobExecTx, contract.txs[randomIdx].bobScript, bobPair.pub, privBob)
	// validate Bob close tx
	err = validateTransactions(contract.txs[randomIdx].bobExecTx, closeTx)
	assert.Nil(suite.t, err)
}

func buildCloseTx(execTx *wire.MsgTx, script []byte, pub *secp256k1.PublicKey, signPriv *secp256k1.PrivateKey) (*wire.MsgTx, error) {
	fout := execTx.TxOut[0]

	// create execution tx
	closeTx := wire.NewMsgTx(2)
	closeTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  execTx.TxHash(),
			Index: uint32(0),
		},
	})

	// pay to pubkey
	p2pkScript, err := P2PKScript(pub)
	if err != nil {
		return nil, err
	}
	txOut := &wire.TxOut{
		Value: execTx.TxOut[0].Value, PkScript: p2pkScript,
	}
	closeTx.AddTxOut(txOut)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		fout.PkScript,
		fout.Value,
	)
	sighash := txscript.NewTxSigHashes(closeTx, inputFetcher)
	sig, err := txscript.RawTxInWitnessSignature(closeTx, sighash, 0, fout.Value, script, txscript.SigHashAll, signPriv)
	closeTx.TxIn[0].Witness = wire.TxWitness{
		sig, []byte{1}, script,
	}

	return closeTx, err
}

func buildContract(suite TestSuite, fundTx *wire.MsgTx, deals [][]byte, alicePair, bobPair, olivia KeyPair, totalAmount int64) (*Contract, error) {
	var contract Contract

	secret := suite.generate32BSeed()
	Rpriv, _ := btcec.PrivKeyFromBytes(secret[:])

	contract.R.priv = Rpriv
	contract.R.pub = Rpriv.PubKey()

	for i, deal := range deals {
		pubm := Commit(olivia.pub, Rpriv.PubKey(), deal)

		amountToB := totalAmount / int64(i+1)
		amountToA := totalAmount - amountToB

		aliceExecTx, err := buildExecutionTx(fundTx, alicePair, bobPair, amountToA, amountToB, pubm)
		if err != nil {
			return nil, err
		}
		bobExecTx, err := buildExecutionTx(fundTx, bobPair, alicePair, amountToB, amountToA, pubm)
		if err != nil {
			return nil, err
		}

		// Alice and Bob sign txs together
		_ = signExecutionTx(fundTx, aliceExecTx, alicePair, bobPair)
		_ = signExecutionTx(fundTx, bobExecTx, alicePair, bobPair)

		aliceScript, _ := ContractExecutionScript(alicePair.pub, bobPair.pub, pubm)
		bobScript, _ := ContractExecutionScript(bobPair.pub, alicePair.pub, pubm)

		contract.txs = append(contract.txs, ExecTx{aliceExecTx, bobExecTx, aliceScript, bobScript})
	}

	return &contract, nil
}

func signExecutionTx(fundTx, executionTx *wire.MsgTx, alicePair, bobPair KeyPair) error {
	fundScript, err := FundScript(alicePair.pub, bobPair.pub)
	if err != nil {
		return err
	}

	aliceSig, err := witsigForFundScript(fundTx, executionTx, fundScript, alicePair)
	if err != nil {
		return err
	}
	bobSig, err := witsigForFundScript(fundTx, executionTx, fundScript, bobPair)
	if err != nil {
		return err
	}

	wt := wire.TxWitness{[]byte{}, aliceSig, bobSig, fundScript}
	executionTx.TxIn[0].Witness = wt

	return nil
}

func buildExecutionTx(fundTx *wire.MsgTx, pair_1, pair_2 KeyPair, amount_1, amount_2 int64, pubm *secp256k1.PublicKey) (*wire.MsgTx, error) {
	// create execution tx
	executionTx := wire.NewMsgTx(2)
	executionTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  fundTx.TxHash(),
			Index: uint32(0),
		},
	})

	// contract execution script
	executionScript, err := ContractExecutionScript(pair_1.pub, pair_2.pub, pubm)

	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(chainhash.HashB(executionScript))
	p2wshScript, err := builder.Script()

	// txOut1: pay to settlement script where A can withdraw by providing own sig and valid oracle's sign
	// or B can withdraw after the delay time
	txOut1 := &wire.TxOut{
		Value: amount_1, PkScript: p2wshScript,
	}
	executionTx.AddTxOut(txOut1)

	p2pkScript, _ := P2PKScript(pair_2.pub)

	// txOut2: pay to B address
	txOut2 := &wire.TxOut{
		Value: amount_2, PkScript: p2pkScript,
	}
	executionTx.AddTxOut(txOut2)

	return executionTx, err
}

func buildFundTx(alicePair, bobPair KeyPair, amount int64) (*wire.MsgTx, error) {

	// 2-of-2 multisig script
	fundScript, err := FundScript(alicePair.pub, bobPair.pub)
	if err != nil {
		return nil, err
	}

	// P2WSH script
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(chainhash.HashB(fundScript))
	p2wshScript, err := builder.Script()

	// Let's say this is a transaction where Alice can spent 0.1 BTC from
	txHash, err := chainhash.NewHashFromStr("aff48a9b83dc525d330ded64e1b6a9e127c99339f7246e2c89e06cd83493af9b")
	// create fund tx
	fundTx := wire.NewMsgTx(2)
	fundTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *txHash,
			Index: uint32(0),
		},
	})

	txOut := &wire.TxOut{
		Value: amount, PkScript: p2wshScript,
	}
	fundTx.AddTxOut(txOut)

	// Alice sign transaction
	sig, err := txscript.SignatureScript(fundTx, 0, []byte{}, txscript.SigHashSingle, alicePair.priv, true)
	fundTx.TxIn[0].SignatureScript = sig

	// log hex encoded tx
	// _ = logHexEncodedTx(fundTx, "Generated Fund Tx: ")

	return fundTx, nil
}

func buildRefundTx(fundTx *wire.MsgTx, alicePair, bobPair KeyPair, amount int64, lockTime uint32) (*wire.MsgTx, error) {

	// create refund tx
	refundTx := wire.NewMsgTx(2)
	refundTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  fundTx.TxHash(),
			Index: uint32(0),
		},
	})

	// pay to alice key
	p2pkScript, err := P2PKScript(alicePair.pub)
	if err != nil {
		return nil, err
	}

	txOut := &wire.TxOut{
		Value: amount, PkScript: p2pkScript,
	}
	refundTx.AddTxOut(txOut)
	refundTx.LockTime = lockTime

	fundScript, err := FundScript(alicePair.pub, bobPair.pub)
	if err != nil {
		return nil, err
	}

	aliceSig, err := witsigForFundScript(fundTx, refundTx, fundScript, alicePair)
	if err != nil {
		return nil, err
	}
	bobSig, err := witsigForFundScript(fundTx, refundTx, fundScript, bobPair)
	if err != nil {
		return nil, err
	}

	wt := wire.TxWitness{[]byte{}, aliceSig, bobSig, fundScript}
	refundTx.TxIn[0].Witness = wt

	// log hex encoded tx
	// _ = logHexEncodedTx(refundTx, "Generated Refund Tx: ")

	return refundTx, err
}

//////////////////////////////////////////////////////////
////                       HELPER                     ////
//////////////////////////////////////////////////////////

func witsigForFundScript(fundTx, refundTx *wire.MsgTx, fundScript []byte, pair KeyPair) ([]byte, error) {
	fout := fundTx.TxOut[0]

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		fout.PkScript,
		fout.Value,
	)
	sighash := txscript.NewTxSigHashes(refundTx, inputFetcher)
	return txscript.RawTxInWitnessSignature(
		refundTx, sighash, 0, fout.Value, fundScript, txscript.SigHashAll, pair.priv,
	)
}

func validateTransactions(txIn *wire.MsgTx, txOut *wire.MsgTx) error {
	blockUtxos := blockchain.NewUtxoViewpoint()
	sigCache := txscript.NewSigCache(50000)
	hashCache := txscript.NewHashCache(50000)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		txIn.TxOut[0].PkScript,
		txIn.TxOut[0].Value,
	)

	blockUtxos.AddTxOut(btcutil.NewTx(txIn), 0, 1)
	hashCache.AddSigHashes(txOut, inputFetcher)

	// validate
	return blockchain.ValidateTransactionScripts(
		btcutil.NewTx(txOut), blockUtxos, txscript.StandardVerifyFlags,
		sigCache, hashCache,
	)
}

func logHexEncodedTx(tx *wire.MsgTx, msg string) error {
	var buf bytes.Buffer
	if err := tx.BtcEncode(&buf, maxProtocolVersion, wire.WitnessEncoding); err != nil {
		return fmt.Errorf("failed to encode msg of type %T", tx)
	}
	fmt.Println(msg, hex.EncodeToString(buf.Bytes()))
	return nil
}

//////////////////////////////////////////////////////////
////                TRANSACTION SCRIPTS               ////
//////////////////////////////////////////////////////////

// FundScript is a 2-of-2 multisig script
//
// ScriptCode:
//
//	OP_2
//	  <public key first party>
//	  <public key second party>
//	OP_2
//	OP_CHECKMULTISIG
func FundScript(pub1, pub2 *btcec.PublicKey) (script []byte, err error) {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_2)
	builder.AddData(pub1.SerializeCompressed())
	builder.AddData(pub2.SerializeCompressed())
	builder.AddOp(txscript.OP_2)
	builder.AddOp(txscript.OP_CHECKMULTISIG)
	return builder.Script()
}

// Basic Pay-To-Public script
func P2PKScript(pub *btcec.PublicKey) (script []byte, err error) {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(btcutil.Hash160(pub.SerializeCompressed()))
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	return builder.Script()
}

// ContractExecutionScript returns a contract execution script.
//
// Script Code:
//
//	OP_IF
//	  <public key a + message public key>
//	OP_ELSE
//	  delay(fix 144)
//	  OP_CHECKSEQUENCEVERIFY
//	  OP_DROP
//	  <public key b>
//	OP_ENDIF
//	OP_CHECKSIG
//
// The if block can be passed when the contractor A has a valid oracle's sign to the message.
// But if the contractor sends this transaction without the oracle's valid sign,
// the else block will be used by the other party B after the delay time.
// Please check the original paper for more details.
//
// https://adiabat.github.io/dlc.pdf
func ContractExecutionScript(puba, pubb, pubm *btcec.PublicKey) ([]byte, error) {
	// pub key a + message pub key
	X, Y := btcec.S256().Add(puba.X(), puba.Y(), pubm.X(), pubm.Y())
	var x_val btcec.FieldVal
	x_val.SetBytes((*[32]byte)(X.Bytes()))
	var y_val btcec.FieldVal
	y_val.SetBytes((*[32]byte)(Y.Bytes()))
	pubam := btcec.NewPublicKey(&x_val, &y_val)
	// ContractExecutionDelay is a delay used in ContractExecutionScript
	const ContractExecutionDelay = 1 // 1 block ~ 10'

	delay := uint16(ContractExecutionDelay)
	csvflg := uint32(0x00000000)
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_IF)
	builder.AddData(pubam.SerializeCompressed())
	builder.AddOp(txscript.OP_ELSE)
	builder.AddInt64(int64(delay) + int64(csvflg))
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP)
	builder.AddData(pubb.SerializeCompressed())
	builder.AddOp(txscript.OP_ENDIF)
	builder.AddOp(txscript.OP_CHECKSIG)
	return builder.Script()
}

//////////////////////////////////////////////////////////
////                  SCHNORR SIGNATURE               ////
//////////////////////////////////////////////////////////

// Commit is calculatd by the following formula
//
//	sG = R - h(R, m) * V
//
// Where
//
//	s: sign for the message m
//	G: elliptic curve base
//	R: R-point
//	m: message
//	V: oracle's public key
func Commit(V, R *btcec.PublicKey, m []byte) *btcec.PublicKey {
	// - h(R, m)
	h := hash(R, m)
	h = new(big.Int).Neg(h)
	h = new(big.Int).Mod(h, btcec.S256().N)

	// - h(R, m) * V
	X, Y := btcec.S256().ScalarMult(V.X(), V.Y(), h.Bytes())
	var x_val btcec.FieldVal
	x_val.SetBytes((*[32]byte)(X.Bytes()))
	var y_val btcec.FieldVal
	y_val.SetBytes((*[32]byte)(Y.Bytes()))
	hV := btcec.NewPublicKey(&x_val, &y_val)

	// R - h(R, m) * V
	P := addPubkeys(R, hV)
	return P
}

func addPubkeys(A, B *btcec.PublicKey) *btcec.PublicKey {
	var C *btcec.PublicKey
	if A.X() == nil {
		var x_val btcec.FieldVal
		x_val.SetBytes((*[32]byte)(B.X().Bytes()))
		var y_val btcec.FieldVal
		y_val.SetBytes((*[32]byte)(B.Y().Bytes()))
		C = btcec.NewPublicKey(&x_val, &y_val)
	} else if B.X() == nil {
		var x_val btcec.FieldVal
		x_val.SetBytes((*[32]byte)(A.X().Bytes()))
		var y_val btcec.FieldVal
		y_val.SetBytes((*[32]byte)(A.Y().Bytes()))
		C = btcec.NewPublicKey(&x_val, &y_val)
	} else {
		X, Y := btcec.S256().Add(A.X(), A.Y(), B.X(), B.Y())
		var x_val btcec.FieldVal
		x_val.SetBytes((*[32]byte)(X.Bytes()))
		var y_val btcec.FieldVal
		y_val.SetBytes((*[32]byte)(Y.Bytes()))
		C = btcec.NewPublicKey(&x_val, &y_val)
	}
	return C
}

// Sign is calculated by the following formula
//
//	s = k - h(R, m) * v
//
// Where
//
//	s: sign
//	h: hash function
//	k: random nonce
//	R: R-point R = kG
//	m: message
//	G: elliptic curve base
//	v: oracle's private key
//
// Parameters:
//
//	rpriv: random point EC private key opriv: oracle's EC private key
//	m: message
func Sign(opriv, rpriv *btcec.PrivateKey, m []byte) []byte {
	R := rpriv.PubKey()
	b1 := rpriv.Key.Bytes()
	k := new(big.Int).SetBytes(b1[:])
	b2 := opriv.Key.Bytes()
	v := new(big.Int).SetBytes(b2[:])

	// h(R,m) * v
	hv := new(big.Int).Mul(hash(R, m), v)

	// k - h(R,m) * v
	s := new(big.Int).Sub(k, hv)

	// s mod N
	s = new(big.Int).Mod(s, btcec.S256().N)

	return s.Bytes()
}

func hash(R *btcec.PublicKey, m []byte) *big.Int {
	s := sha256.New()
	s.Write(R.SerializeUncompressed())
	s.Write(m)
	h := new(big.Int).SetBytes(s.Sum(nil))
	h = new(big.Int).Mod(h, btcec.S256().N)
	return h
}

func genAddSigToPrivkey(priv *secp256k1.PrivateKey, sig []byte) *secp256k1.PrivateKey {
	b := priv.Key.Bytes()
	n := new(big.Int).Add(new(big.Int).SetBytes(b[:]), new(big.Int).SetBytes(sig))
	n = new(big.Int).Mod(n, btcec.S256().N)
	p, _ := btcec.PrivKeyFromBytes(n.Bytes())
	return p
}
