package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type TestSuite struct {
	btcClient   *rpcclient.Client
	connConfig  *rpcclient.ConnConfig
	chainConfig *chaincfg.Params
}

var (
	reg RegBitcoinProcess
)

func TestMain(m *testing.M) {
	// start a bitcoin regtest network
	reg.RunBitcoinProcess()
	defer reg.Stop()

	// run all tests
	os.Exit(m.Run())
}

// go test -v -run ^TestBtcdCreateWallet$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestBtcdCreateWallet(t *testing.T) {
	suite := TestSuite{}
	suite.setupSuite()

	// create a HD wallet seed
	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	assert.Nil(t, err)
	pubPass := []byte("hello")
	privPass := []byte("world")

	// setup wallet loader
	db, err := walletdb.Open("bdb", "boltdb/wallet.db", true, 60*time.Second)
	assert.Nil(t, err)

	loader, err := wallet.NewLoaderWithDB(
		&chaincfg.RegressionNetParams, 250, db,
		// TODO: need further investigation into this from wallet/example_test.go
		func() (bool, error) {
			return false, nil
		},
	)
	assert.Nil(t, err)

	// retrieve wallet
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	if err != nil {
		w, err = loader.OpenExistingWallet(pubPass, false)
		assert.Nil(t, err)
	}
	rpc, err := chain.NewRPCClientWithConfig(&chain.RPCClientConfig{
		Conn:  suite.connConfig,
		Chain: suite.chainConfig,
	})
	w.SynchronizeRPC(rpc)
	assert.Nil(t, err)

	res, err := w.Accounts(waddrmgr.KeyScopeBIP0084)
	assert.Nil(t, err)
	t.Logf("accounts: %+v", res)

	// how to fund this new wallet?
}

// go test -v -run ^TestBallGameContract$ github.com/nghuyenthevinh2000/bitcoin-playground
func TestBallGameContract(t *testing.T) {
	suite := TestSuite{}
	suite.setupSuite()

	// Alice, Bob private key
	wallets := suite.generateWallets(t, 2)
	alice := wallets[0]
	bob := wallets[1]

	t.Logf("alice: %s", alice.String())

	wif, err := btcutil.DecodeWIF(alice.String())
	assert.Nil(t, err)

	t.Logf("wif: %s", wif.String())

	// fund the addresss
	// suite.fundWallets(t, wallets, cfg)

	os.Exit(0)

	// result hash of the game between VN and TL
	vn := sha256.Sum256([]byte("VN wins"))
	tl := sha256.Sum256([]byte("TL wins"))

	// Alice bets that VN wins
	// Bob bets that TL wins
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_IF)
	builder.AddOp(txscript.OP_SHA256).AddData(vn[:]).AddOp(txscript.OP_EQUALVERIFY)
	builder.AddData(alice.SerializePubKey()).AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_ELSE)
	builder.AddOp(txscript.OP_SHA256).AddData(tl[:]).AddOp(txscript.OP_EQUALVERIFY)
	builder.AddData(bob.SerializePubKey()).AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_ENDIF)
	pkScript, err := builder.Script()
	assert.Nil(t, err)

	// create a P2WSH address
	witnessScriptCommitment := sha256.Sum256(pkScript)
	address, err := btcutil.NewAddressWitnessScriptHash(witnessScriptCommitment[:], &chaincfg.RegressionNetParams)
	assert.Nil(t, err)
	t.Logf("P2SH address: %s", address.EncodeAddress())
}

func (s *TestSuite) setupSuite() {
	// connect to bitcoin regtest network
	connCfg := &rpcclient.ConnConfig{
		Host:         MockBtcHost,
		User:         MockBtcUser,
		Pass:         MockBtcPass,
		HTTPPostMode: true,
		DisableTLS:   true,
	}
	s.connConfig = connCfg

	s.chainConfig = &chaincfg.RegressionNetParams
	s.chainConfig.DefaultPort = "18443"

	// todo: determine what to do with bitcoin events for notification handlers
	btcClient, err := rpcclient.New(connCfg, nil)
	if err != nil {
		panic(fmt.Sprintf("error creating btcd RPC client: %v", err))
	}

	s.btcClient = btcClient
}

func (s *TestSuite) generateWallets(t *testing.T, num int) []*btcutil.WIF {
	wallets := make([]*btcutil.WIF, num)
	for i := 0; i < num; i++ {
		privKey, err := secp256k1.GeneratePrivateKey()
		assert.Nil(t, err)
		// WIF: Wallet Import Format
		wif, err := btcutil.NewWIF(privKey, s.chainConfig, true)
		assert.Nil(t, err)
		wallets[i] = wif
		wif.String()
	}

	return wallets
}

// this is for deriving witness pubkey hash from public key
func (s *TestSuite) deriveWitnessPubkeyHash(t *testing.T, wif *btcutil.WIF) string {
	pubKey := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKey)
	witness, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, s.chainConfig)
	assert.Nil(t, err)
	return witness.EncodeAddress()
}

// fund wallet with 1 BTC from main wallet in regtest
func (s *TestSuite) fundWallets(t *testing.T, wallets []*btcutil.WIF) {
	for _, wallet := range wallets {
		// generate 101 blocks to finalize coinbase rewards
		// addr := s.deriveWitnessPubkeyHash(t, wallet, cfg)
		// err := exec.Command("bitcoin-cli", "-regtest", "-rpcport=18443", "-rpcuser=regtest", "-rpcpassword=regtest", "sendtoaddress", addr, "1").Run()
		// assert.Nil(t, err)

		// check for balance
		err := s.btcClient.ImportPrivKey(wallet)
		assert.Nil(t, err)
		// err = exec.Command("bitcoin-cli", "-regtest", "-rpcport=18443", "-rpcuser=regtest", "-rpcpassword=regtest", "-generate", "100").Run()
		// assert.Nil(t, err)
		amt, err := s.btcClient.GetBalance("alice")
		assert.Nil(t, err)
		t.Logf("balance of %s: %f", "alice", amt.ToBTC())
	}
}
