package testhelper

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

func (s *TestSuite) OpenWallet(t *testing.T, seed, wallet_name string) *wallet.Wallet {
	seedStr := strings.TrimSpace(strings.ToLower(seed))
	seedBytes, err := hex.DecodeString(seedStr)
	assert.Nil(t, err)
	pubPass := []byte("public")
	privPass := []byte("private")

	// setup wallet loader
	db, err := walletdb.Create("bdb", fmt.Sprintf("boltdb/%s.db", wallet_name), true, 60*time.Second)
	assert.Nil(t, err)

	loader, err := wallet.NewLoaderWithDB(
		s.BtcdChainConfig, 250, db,
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
	w.SynchronizeRPC(s.WalletChainClient)

	time.Sleep(3 * time.Second)

	w.Unlock(privPass, time.After(60*time.Second))
	t.Logf("wallet %s opened", wallet_name)
	return w
}

// fund wallet with 0.1 BTC from mining wallet
func (s *TestSuite) FundWallet(wallet *wallet.Wallet, amount btcutil.Amount) {
	addr, err := wallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(s.T, err)

	s.Logger.Printf("address: %s", addr.EncodeAddress())

	// send 0.1 BTC to the address
	_, err = s.WalletClient.SendToAddress(addr, amount)
	assert.Nil(s.T, err)

	// generate a block to confirm the transaction
	s.GenerateBlocks(1)
}

func (s *TestSuite) ExportWIFPriv(wallet *wallet.Wallet) *btcutil.WIF {
	addr, err := wallet.CurrentAddress(0, waddrmgr.KeyScopeBIP0044)
	assert.Nil(s.T, err)

	privStr, err := wallet.DumpWIFPrivateKey(addr)
	assert.Nil(s.T, err)

	wif, err := btcutil.DecodeWIF(privStr)
	assert.Nil(s.T, err)

	return wif
}
