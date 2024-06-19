package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/assert"
)

// go test -v -run ^TestExportPriv$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestExportPriv(t *testing.T) {
	suite := TestSuite{}
	suite.setupSimNetSuite(t)

	// open bob wallet
	bobWallet := suite.openWallet(t, BOB_WALLET_SEED, "bob")

	// export private key
	wif := suite.exportWIFPriv(bobWallet)
	t.Logf("WIF private key: %s", wif.String())
}

// go test -v -run ^TestBtcdCreateWallet$ github.com/nghuyenthevinh2000/bitcoin-playground
// create bob wallet and fund bob wallet with 1000 sats sent from btcd registered mining wallet
func TestBtcdCreateWallet(t *testing.T) {
	suite := TestSuite{}
	suite.setupSimNetSuite(t)

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
		suite.btcdChainConfig, 250, db,
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
	w.SynchronizeRPC(suite.walletChainClient)

	time.Sleep(5 * time.Second)

	bals, err := w.AccountBalances(waddrmgr.KeyScopeBIP0044, 1)
	assert.Nil(t, err)
	assert.Equal(t, bals[0].AccountBalance, btcutil.Amount(3000000))
	t.Logf("balances: %+v", bals)
}

func (s *TestSuite) openWallet(t *testing.T, seed, wallet_name string) *wallet.Wallet {
	seedStr := strings.TrimSpace(strings.ToLower(seed))
	seedBytes, err := hex.DecodeString(seedStr)
	assert.Nil(t, err)
	pubPass := []byte("public")
	privPass := []byte("private")

	// setup wallet loader
	db, err := walletdb.Create("bdb", fmt.Sprintf("boltdb/%s.db", wallet_name), true, 60*time.Second)
	assert.Nil(t, err)

	loader, err := wallet.NewLoaderWithDB(
		s.btcdChainConfig, 250, db,
		// TODO: need further investigation into this from wallet/example_test.go
		func() (bool, error) {
			return false, nil
		},
	)
	assert.Nil(t, err)

	// retrieve wallet
	w, err := loader.CreateNewWallet(pubPass, privPass, seedBytes, time.Now())
	if err != nil {
		w, err = loader.OpenExistingWallet(pubPass, false)
		assert.Nil(t, err)
	}
	w.SynchronizeRPC(s.walletChainClient)

	time.Sleep(3 * time.Second)

	w.Unlock(privPass, time.After(60*time.Second))
	t.Logf("wallet %s opened", wallet_name)
	return w
}

// fund wallet with 0.1 BTC from mining wallet
func (s *TestSuite) fundWallet(wallet *wallet.Wallet, amount btcutil.Amount) {
	addr, err := wallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(s.t, err)

	s.t.Logf("address: %s", addr.EncodeAddress())

	// send 0.1 BTC to the address
	_, err = s.walletClient.SendToAddress(addr, amount)
	assert.Nil(s.t, err)

	// generate a block to confirm the transaction
	s.generateBlocks(1)
}

func (s *TestSuite) exportWIFPriv(wallet *wallet.Wallet) *btcutil.WIF {
	addr, err := wallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(s.t, err)

	privStr, err := wallet.DumpWIFPrivateKey(addr)
	assert.Nil(s.t, err)

	wif, err := btcutil.DecodeWIF(privStr)
	assert.Nil(s.t, err)

	return wif
}
