package testhelper

import (
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
)

// validate script creates a funding transaction and a spending transaction
// the funding transaction will send funds to the test script
// the spending transaction will spend the funds from the funding transaction with test witness
func (s *TestSuite) ValidateScript(pkScript []byte, blockHeight int32, witnessFunc func(t *testing.T, prevOut *wire.TxOut, tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, idx int) wire.TxWitness) {
	// create a random key pair
	_, keypair := s.NewHDKeyPairFromSeed("")

	// create tx
	tx_1 := wire.NewMsgTx(2)
	tx_1.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: uint32(0),
		},
	})

	txOut := &wire.TxOut{
		Value: 1000000000, PkScript: pkScript,
	}
	tx_1.AddTxOut(txOut)

	sig, err := txscript.SignatureScript(tx_1, 0, []byte{}, txscript.SigHashDefault, keypair.priv, true)
	assert.Nil(s.T, err)
	tx_1.TxIn[0].SignatureScript = sig

	// create a second spending transaction where the signature is verified against the pubkey
	tx_2 := wire.NewMsgTx(2)
	tx_2.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  tx_1.TxHash(),
			Index: uint32(0),
		},
	})

	txOut = &wire.TxOut{
		Value: 1000000000, PkScript: nil,
	}
	tx_2.AddTxOut(txOut)
	tx_2.LockTime = uint32(blockHeight)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		tx_1.TxOut[0].PkScript,
		tx_1.TxOut[0].Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx_2, inputFetcher)

	witness := witnessFunc(s.T, tx_1.TxOut[0], tx_2, sigHashes, 0)
	tx_2.TxIn[0].Witness = witness

	// check that this tx in is valid before sending
	blockUtxos := blockchain.NewUtxoViewpoint()
	sigCache := txscript.NewSigCache(50000)
	hashCache := txscript.NewHashCache(50000)

	blockUtxos.AddTxOut(btcutil.NewTx(tx_1), 0, blockHeight)
	hashCache.AddSigHashes(tx_2, inputFetcher)

	err = blockchain.ValidateTransactionScripts(
		btcutil.NewTx(tx_2), blockUtxos, txscript.StandardVerifyFlags, sigCache, hashCache,
	)
	assert.Nil(s.T, err)
}

// first tx is used to create a challenge for the second tx
func (s *TestSuite) NewMockFirstTx(pkScript []byte, value int64) *wire.MsgTx {
	tx := wire.NewMsgTx(2)

	_, keypair := s.NewHDKeyPairFromSeed("")

	// first tx will always have their outpoint hash as empty
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: uint32(0),
		},
	})

	txOut := &wire.TxOut{
		Value: value, PkScript: pkScript,
	}
	tx.AddTxOut(txOut)

	sig, err := txscript.SignatureScript(tx, 0, []byte{}, txscript.SigHashDefault, keypair.priv, true)
	assert.Nil(s.T, err)
	tx.TxIn[0].SignatureScript = sig

	return tx
}
