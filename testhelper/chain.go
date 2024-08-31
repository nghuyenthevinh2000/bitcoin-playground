package testhelper

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
)

// this section is available if static suite is setup
// it will leverage UtxoViewpoint to store utxo

func (suite *TestSuite) CreateAccount(acc *btcec.PublicKey) {
	// create an account
	addr, err := btcutil.NewAddressWitnessPubKeyHash(acc.SerializeCompressed(), suite.BtcdChainConfig)
	assert.Nil(suite.T, err)
	prog_bytes, err := txscript.PayToAddrScript(addr)
	assert.Nil(suite.T, err)

	tx := wire.NewMsgTx(2)
	txOut := wire.NewTxOut(100000000, prog_bytes)
	tx.AddTxOut(txOut)

	suite.UtxoViewpoint.BestHash()

	suite.UtxoViewpoint.AddTxOut(btcutil.NewTx(tx), 0, 0)
}
