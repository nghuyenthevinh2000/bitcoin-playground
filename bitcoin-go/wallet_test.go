package main

import (
	"encoding/hex"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/nghuyenthevinh2000/bitcoin-playground/testhelper"
	"github.com/stretchr/testify/assert"
)

// go test -v -run ^TestExportPriv$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestExportPriv(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupSimNetSuite(t, log.Default())

	// open bob wallet
	bobWallet := suite.OpenWallet(t, BOB_WALLET_SEED, "bob")

	// export private key
	wif := suite.ExportWIFPriv(bobWallet)
	t.Logf("WIF private key: %s", wif.String())
}

// go test -v -run ^TestBtcdCreateWallet$ github.com/nghuyenthevinh2000/bitcoin-playground
// create bob wallet and fund bob wallet with 1000 sats sent from btcd registered mining wallet
func TestBtcdCreateWallet(t *testing.T) {
	suite := testhelper.TestSuite{}
	suite.SetupSimNetSuite(t, log.Default())

	// use a HD wallet seed
	seedStr := strings.TrimSpace(strings.ToLower(BOB_WALLET_SEED))
	seed, err := hex.DecodeString(seedStr)
	assert.Nil(t, err)
	pubPass := []byte("public")
	privPass := []byte("private")

	// setup wallet loader
	db, err := walletdb.Create("bdb", "boltdb/bob.db", true, 60*time.Second)
	assert.Nil(t, err)

	loader, err := wallet.NewLoaderWithDB(
		suite.BtcdChainConfig, 250, db,
		// TODO: need further investigation into this from wallet/example_test.go
		func() (bool, error) {
			return false, nil
		},
	)
	assert.Nil(t, err)

	// retrieve wallet
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	t.Logf("err: %v", err)
	if err != nil {
		w, err = loader.OpenExistingWallet(pubPass, false)
		assert.Nil(t, err)
	}
	w.SynchronizeRPC(suite.WalletChainClient)

	time.Sleep(5 * time.Second)

	bals, err := w.AccountBalances(waddrmgr.KeyScopeBIP0044, 1)
	assert.Nil(t, err)
	assert.Equal(t, bals[0].AccountBalance, btcutil.Amount(3000000))
	t.Logf("balances: %+v", bals)
}
